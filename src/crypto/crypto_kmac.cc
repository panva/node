#include "crypto/crypto_kmac.h"
#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_internals.h"
#include "string_bytes.h"
#include "threadpoolwork-inl.h"

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "crypto/crypto_keys.h"
#include "crypto/crypto_sig.h"
#include "ncrypto.h"

namespace node::crypto {

using ncrypto::EVPMacCtxPointer;
using ncrypto::EVPMacPointer;
using node::Utf8Value;
using v8::Boolean;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::HandleScope;
using v8::Isolate;
using v8::JustVoid;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Object;
using v8::Uint32;
using v8::Value;

Kmac::Kmac(Environment* env, Local<Object> wrap)
    : BaseObject(env, wrap) {
  MakeWeak();
}

void Kmac::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("context", ctx_ ? 1 : 0);
}

void Kmac::Initialize(Environment* env, Local<Object> target) {
  Isolate* isolate = env->isolate();
  Local<FunctionTemplate> t = NewFunctionTemplate(isolate, New);

  t->InstanceTemplate()->SetInternalFieldCount(Kmac::kInternalFieldCount);

  SetProtoMethod(isolate, t, "init", KmacInit);
  SetProtoMethod(isolate, t, "update", KmacUpdate);
  SetProtoMethod(isolate, t, "digest", KmacDigest);

  SetConstructorFunction(env->context(), target, "Kmac", t);

  KmacJob::Initialize(env, target);
}

void Kmac::RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  registry->Register(New);
  registry->Register(KmacInit);
  registry->Register(KmacUpdate);
  registry->Register(KmacDigest);
  KmacJob::RegisterExternalReferences(registry);
}

void Kmac::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  new Kmac(env, args.This());
}

void Kmac::KmacInit(const char* algorithm,
                    const char* key,
                    size_t key_len,
                    Local<Value> output_length,
                    Local<Value> custom) {
  HandleScope scope(env()->isolate());

  const char* openssl_algorithm;
  if (strcmp(algorithm, OSSL_MAC_NAME_KMAC128) == 0) {
    openssl_algorithm = OSSL_MAC_NAME_KMAC128;
  } else if (strcmp(algorithm, OSSL_MAC_NAME_KMAC256) == 0) {
    openssl_algorithm = OSSL_MAC_NAME_KMAC256;
  } else {
    return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env());
  }

  auto mac = EVPMacPointer::Fetch(openssl_algorithm);
  if (!mac) [[unlikely]] {
    return ThrowCryptoError(env(), ERR_get_error(), "KMAC not supported");
  }

  ctx_ = EVPMacCtxPointer::New(mac.get());
  if (!ctx_) [[unlikely]] {
    return ThrowCryptoError(env(), ERR_get_error(), "KMAC context error");
  }

  OSSL_PARAM params[3];
  size_t params_count = 0;
  size_t outlen = 0;
  if (!output_length->IsUndefined()) {
    CHECK(output_length->IsUint32());
    outlen = output_length.As<Uint32>()->Value();
    params[params_count++] =
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &outlen);
  }

  ArrayBufferOrViewContents<char> custom_buf(
      custom->IsUndefined() ? Local<Value>() : custom);
  if (!custom->IsUndefined()) {
    if (!custom_buf.CheckSizeInt32()) [[unlikely]] {
      ctx_.reset();
      return THROW_ERR_OUT_OF_RANGE(env(), "custom is too big");
    }
    params[params_count++] = OSSL_PARAM_construct_octet_string(
        OSSL_MAC_PARAM_CUSTOM,
        const_cast<char*>(custom_buf.data()),
        custom_buf.size());
  }

  params[params_count] = OSSL_PARAM_construct_end();

  if (!ctx_.init(ncrypto::Buffer<const void>(key, key_len), params)) {
    ctx_.reset();
    return ThrowCryptoError(
        env(), ERR_get_error(), "KMAC initialization error");
  }

  length_ = !output_length->IsUndefined()
      ? outlen
      : EVP_MAC_CTX_get_mac_size(ctx_.get());
}

void Kmac::KmacInit(const FunctionCallbackInfo<Value>& args) {
  Kmac* kmac;
  ASSIGN_OR_RETURN_UNWRAP(&kmac, args.This());
  Environment* env = kmac->env();

  const node::Utf8Value algorithm(env->isolate(), args[0]);
  ByteSource key = ByteSource::FromSecretKeyBytes(env, args[1]);
  kmac->KmacInit(*algorithm, key.data<char>(), key.size(), args[2], args[3]);
}

bool Kmac::KmacUpdate(const char* data, size_t len) {
  ncrypto::Buffer<const void> buf{
      .data = data,
      .len = len,
  };
  return ctx_.update(buf);
}

void Kmac::KmacUpdate(const FunctionCallbackInfo<Value>& args) {
  Decode<Kmac>(args, [](Kmac* kmac, const FunctionCallbackInfo<Value>& args,
                        const char* data, size_t size) {
    Environment* env = Environment::GetCurrent(args);
    if (size > INT_MAX) [[unlikely]]
      return THROW_ERR_OUT_OF_RANGE(env, "data is too long");
    bool r = kmac->KmacUpdate(data, size);
    args.GetReturnValue().Set(r);
  });
}

void Kmac::KmacDigest(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  Kmac* kmac;
  ASSIGN_OR_RETURN_UNWRAP(&kmac, args.This());

  enum encoding encoding = BUFFER;
  if (args.Length() >= 1) {
    encoding = ParseEncoding(env->isolate(), args[0], BUFFER);
  }

  ByteSource out;
  if (kmac->ctx_ && kmac->length_ > 0) {
    auto result = kmac->ctx_.final(kmac->length_);
    if (!result) [[unlikely]] {
      kmac->ctx_.reset();
      return ThrowCryptoError(env, ERR_get_error(), "Failed to finalize KMAC");
    }
    DCHECK(!result.isSecure());
    out = ByteSource::Allocated(result.release());
  }
  kmac->ctx_.reset();

  const char* data = out.size() == 0 ? "" : out.data<char>();
  Local<Value> ret;
  if (StringBytes::Encode(env->isolate(), data, out.size(), encoding)
          .ToLocal(&ret)) {
    args.GetReturnValue().Set(ret);
  }
}

KmacConfig::KmacConfig(KmacConfig&& other) noexcept
    : job_mode(other.job_mode),
      mode(other.mode),
      key(std::move(other.key)),
      data(std::move(other.data)),
      signature(std::move(other.signature)),
      customization(std::move(other.customization)),
      variant(other.variant),
      length(other.length) {}

KmacConfig& KmacConfig::operator=(KmacConfig&& other) noexcept {
  if (&other == this) return *this;
  this->~KmacConfig();
  return *new (this) KmacConfig(std::move(other));
}

void KmacConfig::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("key", key);
  // If the job is sync, then the KmacConfig does not own the data.
  if (job_mode == kCryptoJobAsync) {
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
    params->customization = mode == kCryptoJobAsync
                                ? customization.ToCopy()
                                : customization.ToByteSource();
  }
  // If undefined, params->customization remains uninitialized (size 0).

  CHECK(args[offset + 4]->IsUint32());  // Length
  params->length = args[offset + 4].As<Uint32>()->Value();

  ArrayBufferOrViewContents<char> data(args[offset + 5]);
  if (!data.CheckSizeInt32()) [[unlikely]] {
    THROW_ERR_OUT_OF_RANGE(env, "data is too big");
    return Nothing<void>();
  }
  params->data = mode == kCryptoJobAsync ? data.ToCopy() : data.ToByteSource();

  if (!args[offset + 6]->IsUndefined()) {
    ArrayBufferOrViewContents<char> signature(args[offset + 6]);
    if (!signature.CheckSizeInt32()) [[unlikely]] {
      THROW_ERR_OUT_OF_RANGE(env, "signature is too big");
      return Nothing<void>();
    }
    params->signature =
        mode == kCryptoJobAsync ? signature.ToCopy() : signature.ToByteSource();
  }

  return JustVoid();
}

bool KmacTraits::DeriveBits(Environment* env,
                            const KmacConfig& params,
                            ByteSource* out,
                            CryptoJobMode mode,
                            CryptoErrorStore* errors) {
  if (params.length == 0) {
    *out = ByteSource();
    return true;
  }

  // Get the key data.
  const void* key_data = params.key.GetSymmetricKey();
  size_t key_size = params.key.GetSymmetricKeySize();

  if (key_size == 0) {
    errors->Insert(NodeCryptoError::KMAC_FAILED);
    return false;
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
  size_t outlen = params.length;
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
  auto result = mac_ctx.final(params.length);
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
          out->size() > 0 && out->size() == params.signature.size() &&
              CRYPTO_memcmp(
                  out->data(), params.signature.data(), out->size()) == 0);
  }
  UNREACHABLE();
}

}  // namespace node::crypto

#endif
