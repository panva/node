#include "crypto/crypto_kmac.h"
#include "async_wrap-inl.h"
#include "node_internals.h"
#include "threadpoolwork-inl.h"

#if OPENSSL_WITH_KMAC
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include "crypto/crypto_keys.h"
#include "crypto/crypto_sig.h"
#include "ncrypto.h"

namespace node::crypto {

using ncrypto::EVPMacCtxPointer;
using ncrypto::EVPMacPointer;
using ncrypto::EVPMDCtxPointer;
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
    : job_mode(other.job_mode),
      mode(other.mode),
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
  // If the job is sync, then the KmacConfig does not own the data.
  if (IsCryptoJobAsync(job_mode)) {
    tracker->TrackFieldWithSize("data", data.size());
    tracker->TrackFieldWithSize("signature", signature.size());
    tracker->TrackFieldWithSize("customization", customization.size());
  }
}

Maybe<void> KmacTraits::AdditionalConfig(
    CryptoJobMode mode,
    const FunctionCallbackInfo<Value>& args,
    unsigned int offset,
    KmacConfig* params) {
  Environment* env = Environment::GetCurrent(args);

  params->job_mode = mode;

  CHECK(args[offset]->IsUint32());  // SignConfiguration::Mode
  params->mode =
      static_cast<SignConfiguration::Mode>(args[offset].As<Uint32>()->Value());

  CHECK(args[offset + 1]->IsObject());  // Key
  KeyObjectHandle* key;
  ASSIGN_OR_RETURN_UNWRAP(&key, args[offset + 1], Nothing<void>());
  params->key = key->Data().addRef();

  CHECK(args[offset + 2]->IsString());  // Algorithm name
  Utf8Value algorithm_name(env->isolate(), args[offset + 2]);
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
  if (!args[offset + 3]->IsUndefined()) {
    ArrayBufferOrViewContents<char> customization(args[offset + 3]);
    if (!customization.CheckSizeInt32()) [[unlikely]] {
      THROW_ERR_OUT_OF_RANGE(env, "customization is too big");
      return Nothing<void>();
    }
    params->customization = IsCryptoJobAsync(mode)
                                ? customization.ToCopy()
                                : customization.ToByteSource();
  }
  // If undefined, params->customization remains uninitialized (size 0).

  CHECK(args[offset + 4]->IsNumber());  // Key length
  double key_length = args[offset + 4].As<Number>()->Value();
  if (!(key_length >= 0) ||
      key_length > static_cast<double>(std::numeric_limits<size_t>::max())) {
    THROW_ERR_OUT_OF_RANGE(env, "key length is too big");
    return Nothing<void>();
  }
  params->key_length = static_cast<size_t>(key_length);

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

static constexpr std::array<unsigned char, 4> kKmacFunctionName = {
    'K', 'M', 'A', 'C'};
static constexpr std::array<unsigned char, 1> kEmptyString = {};
static constexpr size_t kKmacMinOpenSSLKeySize = 4;
// Keep the bit-aware path within OpenSSL's KMAC provider limits.
static constexpr size_t kKmacMaxOpenSSLKeySize = 512;
static constexpr size_t kKmacMaxOpenSSLCustomizationSize = 512;
static constexpr size_t kKmacMaxOpenSSLOutputSize = 0xffffff / CHAR_BIT;

struct EncodedLength {
  std::array<unsigned char, sizeof(size_t) + 1> data;
  size_t size;
};

size_t EncodedLengthSize(size_t value) {
  size_t size = 1;
  size_t remaining = value;
  while (remaining >>= CHAR_BIT) size++;
  return size + 1;
}

bool AddSize(size_t a, size_t b, size_t* out) {
  if (a > std::numeric_limits<size_t>::max() - b) return false;
  *out = a + b;
  return true;
}

bool ByteLengthToBitLength(size_t byte_length, size_t* bit_length) {
  if (byte_length > std::numeric_limits<size_t>::max() / CHAR_BIT) {
    return false;
  }
  *bit_length = byte_length * CHAR_BIT;
  return true;
}

bool KmacParamsWithinOpenSSLLimits(const KmacConfig& params,
                                   size_t key_size,
                                   size_t length_bytes) {
  return key_size <= kKmacMaxOpenSSLKeySize &&
         NumBitsToBytes(params.key_length) <= kKmacMaxOpenSSLKeySize &&
         params.customization.size() <= kKmacMaxOpenSSLCustomizationSize &&
         length_bytes <= kKmacMaxOpenSSLOutputSize;
}

EncodedLength EncodeLength(size_t value, bool left) {
  const size_t value_size = EncodedLengthSize(value) - 1;
  EncodedLength encoded = {{}, value_size + 1};

  if (left) encoded.data[0] = static_cast<unsigned char>(value_size);
  for (size_t n = 0; n < value_size; n++) {
    const size_t shift = CHAR_BIT * (value_size - n - 1);
    encoded.data[(left ? 1 : 0) + n] =
        static_cast<unsigned char>(value >> shift);
  }
  if (!left) encoded.data[value_size] = static_cast<unsigned char>(value_size);

  return encoded;
}

bool DigestUpdate(EVPMDCtxPointer* ctx, const void* data, size_t size) {
  if (size == 0) return true;
  return ctx->digestUpdate(ncrypto::Buffer<const void>{
      .data = data,
      .len = size,
  });
}

bool DigestUpdateEncodedLength(EVPMDCtxPointer* ctx, size_t value, bool left) {
  const EncodedLength encoded = EncodeLength(value, left);
  return DigestUpdate(ctx, encoded.data.data(), encoded.size);
}

bool DigestUpdateEncodedString(EVPMDCtxPointer* ctx,
                               const void* data,
                               size_t byte_length,
                               size_t bit_length) {
  return DigestUpdateEncodedLength(ctx, bit_length, true) &&
         DigestUpdate(ctx, data, byte_length);
}

bool DigestUpdateZeros(EVPMDCtxPointer* ctx, size_t size) {
  static constexpr std::array<unsigned char, 168> zeros = {};
  while (size > 0) {
    const size_t chunk = std::min(size, zeros.size());
    if (!DigestUpdate(ctx, zeros.data(), chunk)) return false;
    size -= chunk;
  }
  return true;
}

bool EncodedStringSize(size_t byte_length, size_t bit_length, size_t* size) {
  return AddSize(EncodedLengthSize(bit_length), byte_length, size);
}

bool DigestUpdateBytepad(EVPMDCtxPointer* ctx,
                         size_t width,
                         const void* data,
                         size_t byte_length,
                         size_t bit_length,
                         const void* data2 = nullptr,
                         size_t byte_length2 = 0,
                         size_t bit_length2 = 0) {
  if (width == 0) return false;

  size_t encoded_size;
  size_t written = EncodedLengthSize(width);
  if (!EncodedStringSize(byte_length, bit_length, &encoded_size) ||
      !AddSize(written, encoded_size, &written)) {
    return false;
  }
  if (data2 != nullptr) {
    if (!EncodedStringSize(byte_length2, bit_length2, &encoded_size) ||
        !AddSize(written, encoded_size, &written)) {
      return false;
    }
  }

  size_t padded_size;
  if (!AddSize(written, width - 1, &padded_size)) return false;
  padded_size = padded_size / width * width;
  DCHECK_GE(padded_size, written);
  const size_t padding = padded_size - written;

  return DigestUpdateEncodedLength(ctx, width, true) &&
         DigestUpdateEncodedString(ctx, data, byte_length, bit_length) &&
         (data2 == nullptr ||
          DigestUpdateEncodedString(ctx, data2, byte_length2, bit_length2)) &&
         DigestUpdateZeros(ctx, padding);
}

bool DeriveBitsWithBitLength(const KmacConfig& params,
                             const void* key_data,
                             size_t key_size,
                             ByteSource* out) {
  const size_t key_length_bytes = NumBitsToBytes(params.key_length);
  if (key_size < key_length_bytes) return false;

  const bool is_kmac128 = params.variant == KmacVariant::KMAC128;
  const size_t rate = is_kmac128 ? 168 : 136;
  const char* digest_name = is_kmac128 ? OSSL_DIGEST_NAME_KECCAK_KMAC128
                                       : OSSL_DIGEST_NAME_KECCAK_KMAC256;
  auto digest = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>{
      EVP_MD_fetch(nullptr, digest_name, nullptr), EVP_MD_free};
  if (!digest) return false;

  auto ctx = EVPMDCtxPointer::New();
  if (!ctx.digestInit(digest.get())) return false;

  size_t customization_bit_length;
  if (!ByteLengthToBitLength(params.customization.size(),
                             &customization_bit_length)) {
    return false;
  }

  const void* customization_data = params.customization.size() == 0
                                       ? kEmptyString.data()
                                       : params.customization.data();
  if (!DigestUpdateBytepad(&ctx,
                           rate,
                           kKmacFunctionName.data(),
                           kKmacFunctionName.size(),
                           kKmacFunctionName.size() * CHAR_BIT,
                           customization_data,
                           params.customization.size(),
                           customization_bit_length)) {
    return false;
  }

  if (!DigestUpdateBytepad(
          &ctx, rate, key_data, key_length_bytes, params.key_length)) {
    return false;
  }

  if (!DigestUpdate(&ctx, params.data.data(), params.data.size()) ||
      !DigestUpdateEncodedLength(&ctx, params.length, false)) {
    return false;
  }

  const size_t length_bytes = NumBitsToBytes(params.length);
  auto result = ctx.digestFinal(length_bytes);
  if (!result) return false;

  auto buffer = result.release();
  *out = ByteSource::Allocated(buffer.data, buffer.len);
  if (params.length % CHAR_BIT != 0) TruncateToBitLength(params.length, out);
  return true;
}

}  // namespace

bool KmacTraits::DeriveBits(Environment* env,
                            const KmacConfig& params,
                            ByteSource* out,
                            CryptoJobMode mode,
                            CryptoErrorStore*) {
  const bool truncate_to_bit_length = params.length % CHAR_BIT != 0;
  const size_t length_bytes =
      NumBitsToBytes(static_cast<size_t>(params.length));

  // Get the key data.
  const void* key_data = params.key.GetSymmetricKey();
  size_t key_size = params.key.GetSymmetricKeySize();

  if (!KmacParamsWithinOpenSSLLimits(params, key_size, length_bytes)) {
    return false;
  }

  if (params.length == 0) {
    *out = ByteSource();
    return true;
  }

  // OpenSSL's EVP_MAC provider rejects KMAC keys shorter than 4 bytes.
  if (params.length % CHAR_BIT != 0 || params.key_length % CHAR_BIT != 0 ||
      key_size < kKmacMinOpenSSLKeySize) {
    return DeriveBitsWithBitLength(params, key_data, key_size, out);
  }

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
  if (truncate_to_bit_length) TruncateToBitLength(params.length, out);
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
          out->size() > 0 && out->size() == params.signature.size() &&
              CRYPTO_memcmp(
                  out->data(), params.signature.data(), out->size()) == 0);
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

#endif  // OPENSSL_WITH_KMAC
