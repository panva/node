#include "crypto/crypto_kem.h"

#if OPENSSL_VERSION_MAJOR >= 3

#include "async_wrap-inl.h"
#include "base_object-inl.h"
#include "crypto/crypto_keys.h"
#include "crypto/crypto_util.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_buffer.h"
#include "threadpoolwork-inl.h"
#include "v8.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

namespace node {

using ncrypto::ClearErrorOnReturn;
using ncrypto::EVPKeyPointer;
using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Maybe;
using v8::MaybeLocal;
using v8::Nothing;
using v8::Object;
using v8::Value;

namespace crypto {

KEMConfiguration::KEMConfiguration(KEMConfiguration&& other) noexcept
    : job_mode(other.job_mode),
      mode(other.mode),
      key(std::move(other.key)),
      ciphertext(std::move(other.ciphertext)) {}

KEMConfiguration& KEMConfiguration::operator=(
    KEMConfiguration&& other) noexcept {
  if (&other == this) return *this;
  this->~KEMConfiguration();
  return *new (this) KEMConfiguration(std::move(other));
}

void KEMConfiguration::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackField("key", key);
  if (job_mode == kCryptoJobAsync) {
    tracker->TrackFieldWithSize("ciphertext", ciphertext.size());
  }
}

namespace {

// Helper function to set KEM operation parameter for OpenSSL < 3.5.0
bool SetKEMOperationParameter(EVP_PKEY_CTX* ctx, const EVPKeyPointer& key) {
#if OPENSSL_VERSION_PREREQ(3, 5)
  // OpenSSL 3.5.0+ doesn't need manual parameter setting
  return true;
#else
  int key_type = EVP_PKEY_id(key.get());
  const char* operation = nullptr;

  switch (key_type) {
    case EVP_PKEY_RSA:
      operation = OSSL_KEM_PARAM_OPERATION_RSASVE;
      break;
#if OPENSSL_VERSION_PREREQ(3, 2)
    case EVP_PKEY_EC:
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
      operation = OSSL_KEM_PARAM_OPERATION_DHKEM;
      break;
#endif
    default:
      // For other key types, don't set the parameter
      return true;
  }

  if (operation != nullptr) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(
            OSSL_KEM_PARAM_OPERATION, const_cast<char*>(operation), 0),
        OSSL_PARAM_END};

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
      return false;
    }
  }

  return true;
#endif
}

bool DoKEMEncapsulate(Environment* env,
                      const EVPKeyPointer& public_key,
                      ByteSource* out,
                      CryptoJobMode mode) {
  ClearErrorOnReturn clear_error_on_return;

  // Create EVP_PKEY_CTX for encapsulation
  auto ctx = public_key.newCtx();
  if (!ctx) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env, "Failed to create context");
    }
    return false;
  }

  // Initialize for encapsulation
  if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to initialize encapsulation");
    }
    return false;
  }

  // Set KEM operation parameter for OpenSSL < 3.5.0
  if (!SetKEMOperationParameter(ctx.get(), public_key)) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(
          env, "Failed to set KEM operation parameter");
    }
    return false;
  }

  // Get the sizes needed for the output
  size_t ciphertext_len = 0;
  size_t shared_key_len = 0;

  if (EVP_PKEY_encapsulate(
          ctx.get(), nullptr, &ciphertext_len, nullptr, &shared_key_len) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to determine output sizes");
    }
    return false;
  }

  // Allocate output buffer:
  // [ciphertext_len][shared_key_len][ciphertext][shared_key]
  size_t total_len =
      sizeof(uint32_t) + sizeof(uint32_t) + ciphertext_len + shared_key_len;
  auto data = ncrypto::DataPointer::Alloc(total_len);
  if (!data) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to allocate output buffer");
    }
    return false;
  }

  unsigned char* ptr = static_cast<unsigned char*>(data.get());

  // Store sizes at the beginning
  *reinterpret_cast<uint32_t*>(ptr) = static_cast<uint32_t>(ciphertext_len);
  *reinterpret_cast<uint32_t*>(ptr + sizeof(uint32_t)) =
      static_cast<uint32_t>(shared_key_len);

  unsigned char* ciphertext_ptr = ptr + 2 * sizeof(uint32_t);
  unsigned char* shared_key_ptr = ciphertext_ptr + ciphertext_len;

  // Perform encapsulation
  if (EVP_PKEY_encapsulate(ctx.get(),
                           ciphertext_ptr,
                           &ciphertext_len,
                           shared_key_ptr,
                           &shared_key_len) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env, "Failed to perform encapsulation");
    }
    return false;
  }

  *out = ByteSource::Allocated(data.release());
  return true;
}

bool DoKEMDecapsulate(Environment* env,
                      const EVPKeyPointer& private_key,
                      const ByteSource& ciphertext,
                      ByteSource* out,
                      CryptoJobMode mode) {
  ClearErrorOnReturn clear_error_on_return;

  // Create EVP_PKEY_CTX for decapsulation
  auto ctx = private_key.newCtx();
  if (!ctx) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env, "Failed to create context");
    }
    return false;
  }

  // Initialize for decapsulation
  if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to initialize decapsulation");
    }
    return false;
  }

  // Set KEM operation parameter for OpenSSL < 3.5.0
  if (!SetKEMOperationParameter(ctx.get(), private_key)) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(
          env, "Failed to set KEM operation parameter");
    }
    return false;
  }

  // Get the size needed for the shared key
  size_t shared_key_len = 0;
  if (EVP_PKEY_decapsulate(ctx.get(),
                           nullptr,
                           &shared_key_len,
                           ciphertext.data<unsigned char>(),
                           ciphertext.size()) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to determine shared key size");
    }
    return false;
  }

  // Allocate output buffer for shared key
  auto data = ncrypto::DataPointer::Alloc(shared_key_len);
  if (!data) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env,
                                        "Failed to allocate output buffer");
    }
    return false;
  }

  // Perform decapsulation
  if (EVP_PKEY_decapsulate(ctx.get(),
                           static_cast<unsigned char*>(data.get()),
                           &shared_key_len,
                           ciphertext.data<unsigned char>(),
                           ciphertext.size()) <= 0) {
    if (mode == kCryptoJobSync) {
      THROW_ERR_CRYPTO_OPERATION_FAILED(env, "Failed to perform decapsulation");
    }
    return false;
  }

  *out = ByteSource::Allocated(data.release());
  return true;
}

}  // anonymous namespace

// KEMEncapsulateTraits implementation
Maybe<void> KEMEncapsulateTraits::AdditionalConfig(
    CryptoJobMode mode,
    const FunctionCallbackInfo<Value>& args,
    unsigned int offset,
    KEMConfiguration* params) {
  params->job_mode = mode;
  params->mode = KEMMode::Encapsulate;

  // Get public key from arguments
  unsigned int key_offset = offset;
  auto public_key_data =
      KeyObjectData::GetPublicOrPrivateKeyFromJs(args, &key_offset);
  if (!public_key_data) {
    return Nothing<void>();
  }
  params->key = std::move(public_key_data);

  return v8::JustVoid();
}

bool KEMEncapsulateTraits::DeriveBits(Environment* env,
                                      const KEMConfiguration& params,
                                      ByteSource* out,
                                      CryptoJobMode mode) {
  Mutex::ScopedLock lock(params.key.mutex());
  const auto& public_key = params.key.GetAsymmetricKey();

  return DoKEMEncapsulate(env, public_key, out, mode);
}

MaybeLocal<Value> KEMEncapsulateTraits::EncodeOutput(
    Environment* env, const KEMConfiguration& params, ByteSource* out) {
  // The output contains:
  // [ciphertext_len][shared_key_len][ciphertext][shared_key]
  const unsigned char* data = out->data<unsigned char>();

  uint32_t ciphertext_len = *reinterpret_cast<const uint32_t*>(data);
  uint32_t shared_key_len =
      *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));

  const unsigned char* ciphertext_ptr = data + 2 * sizeof(uint32_t);
  const unsigned char* shared_key_ptr = ciphertext_ptr + ciphertext_len;

  // Create result object with ciphertext and sharedKey
  Local<Object> result = Object::New(env->isolate());

  // Create ciphertext Buffer
  MaybeLocal<Object> ciphertext_buf =
      node::Buffer::Copy(env->isolate(),
                         reinterpret_cast<const char*>(ciphertext_ptr),
                         ciphertext_len);

  // Create sharedKey Buffer
  MaybeLocal<Object> shared_key_buf =
      node::Buffer::Copy(env->isolate(),
                         reinterpret_cast<const char*>(shared_key_ptr),
                         shared_key_len);

  Local<Object> ciphertext_obj;
  Local<Object> shared_key_obj;
  if (!ciphertext_buf.ToLocal(&ciphertext_obj) ||
      !shared_key_buf.ToLocal(&shared_key_obj)) {
    return MaybeLocal<Value>();
  }

  if (result->Set(env->context(), env->ciphertext_string(), ciphertext_obj)
          .IsNothing() ||
      result->Set(env->context(), env->sharedkey_string(), shared_key_obj)
          .IsNothing()) {
    return MaybeLocal<Value>();
  }

  return result;
}

// KEMDecapsulateTraits implementation
Maybe<void> KEMDecapsulateTraits::AdditionalConfig(
    CryptoJobMode mode,
    const FunctionCallbackInfo<Value>& args,
    unsigned int offset,
    KEMConfiguration* params) {
  Environment* env = Environment::GetCurrent(args);

  params->job_mode = mode;
  params->mode = KEMMode::Decapsulate;

  // Get private key from arguments
  unsigned int key_offset = offset;
  auto private_key_data =
      KeyObjectData::GetPrivateKeyFromJs(args, &key_offset, true);
  if (!private_key_data) {
    return Nothing<void>();
  }
  params->key = std::move(private_key_data);

  // Get ciphertext from arguments
  ArrayBufferOrViewContents<unsigned char> ciphertext(args[key_offset]);
  if (!ciphertext.CheckSizeInt32()) {
    THROW_ERR_OUT_OF_RANGE(env, "ciphertext is too big");
    return Nothing<void>();
  }

  // Store ciphertext in params
  params->ciphertext =
      mode == kCryptoJobAsync ? ciphertext.ToCopy() : ciphertext.ToByteSource();

  return v8::JustVoid();
}

bool KEMDecapsulateTraits::DeriveBits(Environment* env,
                                      const KEMConfiguration& params,
                                      ByteSource* out,
                                      CryptoJobMode mode) {
  Mutex::ScopedLock lock(params.key.mutex());
  const auto& private_key = params.key.GetAsymmetricKey();

  return DoKEMDecapsulate(env, private_key, params.ciphertext, out, mode);
}

MaybeLocal<Value> KEMDecapsulateTraits::EncodeOutput(
    Environment* env, const KEMConfiguration& params, ByteSource* out) {
  // Return the shared key as a Buffer
  return out->ToBuffer(env);
}

void InitializeKEM(Environment* env, Local<Object> target) {
  KEMEncapsulateJob::Initialize(env, target);
  KEMDecapsulateJob::Initialize(env, target);

  constexpr int kKEMEncapsulate = static_cast<int>(KEMMode::Encapsulate);
  constexpr int kKEMDecapsulate = static_cast<int>(KEMMode::Decapsulate);

  NODE_DEFINE_CONSTANT(target, kKEMEncapsulate);
  NODE_DEFINE_CONSTANT(target, kKEMDecapsulate);
}

void RegisterKEMExternalReferences(ExternalReferenceRegistry* registry) {
  KEMEncapsulateJob::RegisterExternalReferences(registry);
  KEMDecapsulateJob::RegisterExternalReferences(registry);
}

namespace KEM {
void Initialize(Environment* env, Local<Object> target) {
  InitializeKEM(env, target);
}

void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  RegisterKEMExternalReferences(registry);
}
}  // namespace KEM

}  // namespace crypto
}  // namespace node

#endif
