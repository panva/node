#include "crypto/crypto_kmac.h"
#include "async_wrap-inl.h"
#include "node_internals.h"
#include "threadpoolwork-inl.h"

#if OPENSSL_WITH_EVP_MAC
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <array>
#include <utility>
#include "crypto/crypto_keys.h"
#include "crypto/crypto_sig.h"
#include "ncrypto.h"

namespace node::crypto {

using ncrypto::EVPMacCtxPointer;
using ncrypto::EVPMacPointer;
using node::Utf8Value;
using v8::Boolean;
using v8::FunctionCallbackInfo;
using v8::JustVoid;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Number;
using v8::Object;
using v8::Uint32;
using v8::Value;

KmacConfig::KmacConfig(KmacConfig&& other) noexcept
    : mode(other.mode),
      key(std::move(other.key)),
      data(std::move(other.data)),
      signature(std::move(other.signature)),
      customization(std::move(other.customization)),
      variant(other.variant),
      key_length(other.key_length),
      length(other.length) {}

KmacConfig& KmacConfig::operator=(KmacConfig&& other) noexcept {
  if (&other == this) return *this;
  this->~KmacConfig();
  return *new (this) KmacConfig(std::move(other));
}

void KmacConfig::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("key", key);
  tracker->TraitTrackInline(data, "data");
  tracker->TraitTrackInline(signature, "signature");
  tracker->TraitTrackInline(customization, "customization");
}

Maybe<void> KmacTraits::AdditionalConfig(
    CryptoJobMode mode,
    const FunctionCallbackInfo<Value>& args,
    unsigned int offset,
    KmacConfig* params) {
  Environment* env = Environment::GetCurrent(args);

  CHECK(args[offset]->IsUint32());  // SignConfiguration::Mode
  params->mode =
      static_cast<SignConfiguration::Mode>(args[offset].As<Uint32>()->Value());

  CHECK(args[offset + 1]->IsObject());  // Key
  KeyObjectHandle* key;
  ASSIGN_OR_RETURN_UNWRAP(&key, args[offset + 1], Nothing<void>());
  params->key = key->Data().addRef();

  CHECK(args[offset + 2]->IsNumber());  // Key length in bits
  params->key_length = args[offset + 2].As<Number>()->Value();

  CHECK(args[offset + 3]->IsString());  // Algorithm name
  Utf8Value algorithm_name(env->isolate(), args[offset + 3]);
  std::string_view algorithm_str = algorithm_name.ToStringView();

  // Convert string to enum and validate
  if (algorithm_str == OSSL_MAC_NAME_KMAC128) {
    params->variant = KmacVariant::KMAC128;
  } else if (algorithm_str == OSSL_MAC_NAME_KMAC256) {
    params->variant = KmacVariant::KMAC256;
  } else {
    UNREACHABLE();
  }

  // Customization string (may be empty or undefined).
  if (!args[offset + 4]->IsUndefined()) {
    ArrayBufferOrViewContents<char> customization(args[offset + 4]);
    if (!customization.CheckSizeInt32()) [[unlikely]] {
      THROW_ERR_OUT_OF_RANGE(env, "customization is too big");
      return Nothing<void>();
    }
    params->customization = IsCryptoJobAsync(mode)
                                ? customization.ToCopy()
                                : customization.ToByteSource();
  }
  // If undefined, params->customization remains uninitialized (size 0).

  CHECK(args[offset + 5]->IsUint32());  // Length
  params->length = args[offset + 5].As<Uint32>()->Value();

  ArrayBufferOrViewContents<char> data(args[offset + 6]);
  if (!data.CheckSizeInt32()) [[unlikely]] {
    THROW_ERR_OUT_OF_RANGE(env, "data is too big");
    return Nothing<void>();
  }
  params->data = IsCryptoJobAsync(mode) ? data.ToCopy() : data.ToByteSource();

  if (!args[offset + 7]->IsUndefined()) {
    ArrayBufferOrViewContents<char> signature(args[offset + 7]);
    if (!signature.CheckSizeInt32()) [[unlikely]] {
      THROW_ERR_OUT_OF_RANGE(env, "signature is too big");
      return Nothing<void>();
    }
    params->signature =
        IsCryptoJobAsync(mode) ? signature.ToCopy() : signature.ToByteSource();
  }

  return JustVoid();
}

namespace {

// SP 800-185, section 2.3.1. Inferred key bit lengths may exceed uint32_t.
size_t EncodeKmacInteger(uint64_t value,
                         bool right,
                         std::array<unsigned char, sizeof(uint64_t) + 1>* out) {
  size_t bytes = 1;
  for (uint64_t remaining = value; remaining > 0xff; remaining >>= CHAR_BIT) {
    bytes++;
  }
  for (size_t i = 0; i < bytes; i++) {
    (*out)[(right ? 0 : 1) + bytes - i - 1] = value & 0xff;
    value >>= CHAR_BIT;
  }
  (*out)[right ? bytes : 0] = static_cast<unsigned char>(bytes);
  return bytes + 1;
}

bool KmacWithCShake(const KmacConfig& params, ByteSource* out) {
  const bool is_128 = params.variant == KmacVariant::KMAC128;
  const auto digest =
      ncrypto::Digest::FromName(is_128 ? "cshake128" : "cshake256");
  auto ctx = ncrypto::EVPMDCtxPointer::New();
  CShakeOptions options;
  options.function_name = "KMAC";
  options.flags = CShakeOptions::kFunctionName | CShakeOptions::kCustomization;
  if (!params.customization.empty()) {
    options.customization.assign(params.customization.data<char>(),
                                 params.customization.size());
    // OpenSSL's cSHAKE customization parameter is a C string.
    if (options.customization.find('\0') != std::string::npos) return false;
  }
  if (!options.Initialize(&ctx, digest.get())) return false;

  // KMAC128/256(K, X, L, S) = cSHAKE128/256(
  //   bytepad(encode_string(K), rate) || X || right_encode(L), L, "KMAC", S).
  // Stream the bytepad prefix without making another copy of the key.
  // See SP 800-185, section 4.3.
  const uint32_t rate = is_128 ? 168 : 136;
  std::array<unsigned char, sizeof(uint64_t) + 1> encoded;
  size_t size = EncodeKmacInteger(rate, /* right */ false, &encoded);
  if (!ctx.digestUpdate({encoded.data(), size})) return false;
  size_t prefix_size = size;
  size = EncodeKmacInteger(params.key_length, /* right */ false, &encoded);
  if (!ctx.digestUpdate({encoded.data(), size})) return false;
  prefix_size += size;

  const auto* key =
      reinterpret_cast<const unsigned char*>(params.key.GetSymmetricKey());
  const size_t whole_bytes = params.key_length / CHAR_BIT;
  const unsigned int key_remainder = params.key_length % CHAR_BIT;
  if (!ctx.digestUpdate({key, whole_bytes})) return false;
  prefix_size += whole_bytes;
  if (key_remainder != 0) {
    // Raw/JWK keys keep a partial byte high-aligned. Move those bits to
    // Keccak's low-aligned representation before the bytepad zeroes.
    unsigned char last = key[whole_bytes] >> (CHAR_BIT - key_remainder);
    const bool updated = ctx.digestUpdate({&last, 1});
    OPENSSL_cleanse(&last, sizeof(last));
    if (!updated) return false;
    prefix_size++;
  }
  constexpr std::array<unsigned char, 168> zeroes{};
  const size_t padding = (rate - (prefix_size % rate)) % rate;
  if (!ctx.digestUpdate({zeroes.data(), padding}) ||
      !ctx.digestUpdate(params.data)) {
    return false;
  }

  // Encode the requested bit length, not the rounded byte length used to
  // squeeze the output. EVP_MAC cannot express this distinction.
  size = EncodeKmacInteger(params.length, /* right */ true, &encoded);
  if (!ctx.digestUpdate({encoded.data(), size})) return false;
  if (params.length == 0) return true;

  const size_t length_bytes =
      params.length / CHAR_BIT + (params.length % CHAR_BIT != 0);
  auto result = ctx.digestFinal(length_bytes);
  if (!result) return false;
  const unsigned int remainder = params.length % CHAR_BIT;
  if (remainder != 0) {
    // This prototype uses Keccak bit order for partial output bytes.
    result.get<unsigned char>()[length_bytes - 1] &= (1u << remainder) - 1;
  }
  *out = ByteSource::Allocated(result.release());
  return true;
}

}  // namespace

bool KmacTraits::DeriveBits(Environment* env,
                            const KmacConfig& params,
                            ByteSource* out,
                            CryptoJobMode mode,
                            CryptoErrorStore*) {
  const size_t key_bytes =
      params.key_length / CHAR_BIT + (params.key_length % CHAR_BIT != 0);
  if (key_bytes != params.key.GetSymmetricKeySize()) {
    return false;
  }
  if (params.length % CHAR_BIT != 0 || params.key_length % CHAR_BIT != 0) {
    return KmacWithCShake(params, out);
  }
  const size_t length_bytes = params.length / CHAR_BIT;

  // Get the key data.
  const void* key_data = params.key.GetSymmetricKey();
  size_t key_size = params.key.GetSymmetricKeySize();

  // Fetch the KMAC algorithm
  auto mac = EVPMacPointer::Fetch((params.variant == KmacVariant::KMAC128)
                                      ? OSSL_MAC_NAME_KMAC128
                                      : OSSL_MAC_NAME_KMAC256);
  if (!mac) {
    return false;
  }

  // Create MAC context
  auto mac_ctx = EVPMacCtxPointer::New(mac.get());
  if (!mac_ctx) {
    return false;
  }

  // Set up parameters.
  OSSL_PARAM params_array[3];  // Max 3: size + customization + end
  size_t params_count = 0;

  // Set output length (always required for KMAC).
  size_t outlen = length_bytes;
  params_array[params_count++] =
      OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outlen);

  // Set customization if provided.
  if (params.customization.size() > 0) {
    params_array[params_count++] = OSSL_PARAM_construct_octet_string(
        OSSL_MAC_PARAM_CUSTOM,
        const_cast<void*>(params.customization.data()),
        params.customization.size());
  }

  params_array[params_count] = OSSL_PARAM_construct_end();

  // Initialize the MAC context.
  if (!mac_ctx.init(ncrypto::Buffer<const void>(key_data, key_size),
                    params_array)) {
    return false;
  }

  // Update with data.
  if (!mac_ctx.update(ncrypto::Buffer<const void>(params.data.data(),
                                                  params.data.size()))) {
    return false;
  }

  // Finalize and get the result.
  auto result = mac_ctx.final(length_bytes);
  if (!result) {
    return false;
  }

  auto buffer = result.release();
  *out = ByteSource::Allocated(buffer.data, buffer.len);
  return true;
}

MaybeLocal<Value> KmacTraits::EncodeOutput(Environment* env,
                                           const KmacConfig& params,
                                           ByteSource* out) {
  switch (params.mode) {
    case SignConfiguration::Mode::Sign:
      return out->ToArrayBuffer(env);
    case SignConfiguration::Mode::Verify:
      return Boolean::New(
          env->isolate(),
          out->size() == params.signature.size() &&
              (out->size() == 0 ||
               CRYPTO_memcmp(
                   out->data(), params.signature.data(), out->size()) == 0));
  }
  UNREACHABLE();
}

void Kmac::Initialize(Environment* env, Local<Object> target) {
  KmacJob::Initialize(env, target);
}

void Kmac::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  KmacJob::RegisterExternalReferences(registry);
}

}  // namespace node::crypto

#endif  // OPENSSL_WITH_EVP_MAC
