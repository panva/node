#include "crypto/crypto_hpke.h"

#if OPENSSL_WITH_HPKE

#include "base_object-inl.h"
#include "env-inl.h"
#include "memory_tracker-inl.h"
#include "node_buffer.h"
#include "v8.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace node {

using ncrypto::ClearErrorOnReturn;
using ncrypto::DataPointer;
using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Int32;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Number;
using v8::Object;
using v8::String;
using v8::Uint32;
using v8::Undefined;
using v8::Value;

namespace crypto {
namespace {

constexpr uint32_t kMaxHPKESuiteId = std::numeric_limits<uint16_t>::max();

int GetInt32Arg(const FunctionCallbackInfo<Value>& args, int offset) {
  CHECK(args[offset]->IsInt32());
  return args[offset].As<Int32>()->Value();
}

uint16_t GetHPKESuiteIdArg(const FunctionCallbackInfo<Value>& args,
                           int offset) {
  CHECK(args[offset]->IsUint32());
  const uint32_t value = args[offset].As<Uint32>()->Value();
  CHECK_LE(value, kMaxHPKESuiteId);
  return static_cast<uint16_t>(value);
}

OSSL_HPKE_SUITE GetSuite(const FunctionCallbackInfo<Value>& args,
                         int offset = 0) {
  return OSSL_HPKE_SUITE{
      GetHPKESuiteIdArg(args, offset),
      GetHPKESuiteIdArg(args, offset + 1),
      GetHPKESuiteIdArg(args, offset + 2),
  };
}

size_t GetSizeArg(const FunctionCallbackInfo<Value>& args, int offset) {
  CHECK(args[offset]->IsNumber());
  const double value = args[offset].As<Number>()->Value();
  CHECK_GE(value, 0);
  CHECK_LE(value, static_cast<double>(Buffer::kMaxLength));
  return static_cast<size_t>(value);
}

Local<Value> OptionalBufferSource(const FunctionCallbackInfo<Value>& args,
                                  int offset) {
  if (args[offset]->IsUndefined()) return Local<Value>();
  return args[offset];
}

void ThrowHPKEOperationFailed(Environment* env, const char* message) {
  unsigned long err = ERR_get_error();  // NOLINT(runtime/int)
  if (err != 0) {
    return ThrowCryptoError(env, err, message);
  }
  return THROW_ERR_CRYPTO_OPERATION_FAILED(env, message);
}

bool CheckBufferLength(Environment* env, size_t length) {
  if (length <= Buffer::kMaxLength) return true;

  THROW_ERR_BUFFER_TOO_LARGE(env, "Buffer is too large");
  return false;
}

bool GetEncodedPublicKey(Environment* env,
                         const KeyObjectData& key_data,
                         const OSSL_HPKE_SUITE& suite,
                         ByteSource* out) {
  Mutex::ScopedLock lock(key_data.mutex());
  const auto& key = key_data.GetAsymmetricKey();

  size_t public_key_len = OSSL_HPKE_get_public_encap_size(suite);
  if (public_key_len == 0) {
    ThrowHPKEOperationFailed(env, "Invalid HPKE suite");
    return false;
  }

  unsigned char* public_key_data = nullptr;
  size_t actual_len =
      EVP_PKEY_get1_encoded_public_key(key.get(), &public_key_data);
  if (actual_len != public_key_len) {
    OPENSSL_clear_free(public_key_data, actual_len);
    ThrowHPKEOperationFailed(env, "Failed to get HPKE public key");
    return false;
  }

  *out = ByteSource::Allocated(public_key_data, actual_len);
  return true;
}

bool IsSupportedSuite(const OSSL_HPKE_SUITE& suite) {
  ClearErrorOnReturn clear_error_on_return;
  return OSSL_HPKE_suite_check(suite) == 1;
}

void DefineConstant(Local<Object> target, const char* name, double value) {
  Isolate* isolate = Isolate::GetCurrent();
  Local<Context> context = isolate->GetCurrentContext();
  Local<String> constant_name =
      String::NewFromUtf8(isolate, name, v8::NewStringType::kInternalized)
          .ToLocalChecked();
  Local<Number> constant_value = Number::New(isolate, value);
  auto attributes =
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontDelete);
  target->DefineOwnProperty(context, constant_name, constant_value, attributes)
      .Check();
}

void DefineConstants(Local<Object> target) {
  DefineConstant(target, "KEM_DHKEM_P256_HKDF_SHA256", OSSL_HPKE_KEM_ID_P256);
  DefineConstant(target, "KEM_DHKEM_P384_HKDF_SHA384", OSSL_HPKE_KEM_ID_P384);
  DefineConstant(target, "KEM_DHKEM_P521_HKDF_SHA512", OSSL_HPKE_KEM_ID_P521);
  DefineConstant(
      target, "KEM_DHKEM_X25519_HKDF_SHA256", OSSL_HPKE_KEM_ID_X25519);
  DefineConstant(target, "KEM_DHKEM_X448_HKDF_SHA512", OSSL_HPKE_KEM_ID_X448);
  DefineConstant(target, "KDF_HKDF_SHA256", OSSL_HPKE_KDF_ID_HKDF_SHA256);
  DefineConstant(target, "KDF_HKDF_SHA384", OSSL_HPKE_KDF_ID_HKDF_SHA384);
  DefineConstant(target, "KDF_HKDF_SHA512", OSSL_HPKE_KDF_ID_HKDF_SHA512);
  DefineConstant(target, "AEAD_AES_128_GCM", OSSL_HPKE_AEAD_ID_AES_GCM_128);
  DefineConstant(target, "AEAD_AES_256_GCM", OSSL_HPKE_AEAD_ID_AES_GCM_256);
  DefineConstant(
      target, "AEAD_ChaCha20Poly1305", OSSL_HPKE_AEAD_ID_CHACHA_POLY1305);
  DefineConstant(target, "AEAD_EXPORT_ONLY", OSSL_HPKE_AEAD_ID_EXPORTONLY);
  DefineConstant(target, "MAX_PARAMETER_LENGTH", OSSL_HPKE_MAX_PARMLEN);
  DefineConstant(target, "MIN_PSK_LENGTH", OSSL_HPKE_MIN_PSKLEN);
  DefineConstant(target, "MAX_INFO_LENGTH", OSSL_HPKE_MAX_INFOLEN);
}

}  // namespace

HPKEContext::HPKEContext(Environment* env,
                         Local<Object> wrap,
                         OSSL_HPKE_CTX* ctx,
                         OSSL_HPKE_SUITE suite)
    : BaseObject(env, wrap), ctx_(ctx), suite_(suite) {
  MakeWeak();
}

void HPKEContext::MemoryInfo(MemoryTracker* tracker) const {
  tracker->TrackFieldWithSize("ctx", ctx_ ? 1 : 0);
}

void HPKEContext::New(const FunctionCallbackInfo<Value>& args) {
  CHECK(args.IsConstructCall());
  Environment* env = Environment::GetCurrent(args);

  const int role = GetInt32Arg(args, 0);
  const int mode = GetInt32Arg(args, 1);
  const OSSL_HPKE_SUITE suite = GetSuite(args, 2);

  if (!IsSupportedSuite(suite)) {
    return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env,
                                                  "Unsupported HPKE suite");
  }

  ClearErrorOnReturn clear_error_on_return;
  OSSL_HPKE_CTX* ctx = OSSL_HPKE_CTX_new(mode, suite, role, nullptr, nullptr);
  if (ctx == nullptr) {
    return ThrowHPKEOperationFailed(env, "Failed to create HPKE context");
  }

  auto ctx_ptr = ncrypto::DeleteFnPtr<OSSL_HPKE_CTX, OSSL_HPKE_CTX_free>(ctx);

  if (!args[5]->IsUndefined()) {
    ArrayBufferOrViewContents<unsigned char> psk(args[5]);
    ArrayBufferOrViewContents<char> psk_id(args[6]);

    std::string psk_id_string(psk_id.data(), psk_id.size());
    if (OSSL_HPKE_CTX_set1_psk(
            ctx_ptr.get(), psk_id_string.c_str(), psk.data(), psk.size()) !=
        1) {
      return ThrowHPKEOperationFailed(env, "Failed to set HPKE PSK");
    }
  }

  new HPKEContext(env, args.This(), ctx_ptr.release(), suite);
}

void HPKEContext::Encap(const FunctionCallbackInfo<Value>& args) {
  HPKEContext* hpke;
  ASSIGN_OR_RETURN_UNWRAP(&hpke, args.This());
  Environment* env = Environment::GetCurrent(args);

  unsigned int offset = 0;
  auto public_key_data =
      KeyObjectData::GetPublicOrPrivateKeyFromJs(args, &offset);
  if (!public_key_data) return;

  ByteSource public_key;
  if (!GetEncodedPublicKey(env, public_key_data, hpke->suite_, &public_key))
    return;

  ArrayBufferOrViewContents<unsigned char> info(
      OptionalBufferSource(args, offset));
  size_t enc_len = OSSL_HPKE_get_public_encap_size(hpke->suite_);
  auto enc = DataPointer::Alloc(enc_len);
  if (!enc) {
    return ThrowHPKEOperationFailed(env,
                                    "Failed to allocate HPKE encapsulated key");
  }

  ClearErrorOnReturn clear_error_on_return;
  if (OSSL_HPKE_encap(hpke->ctx_.get(),
                      enc.get<unsigned char>(),
                      &enc_len,
                      public_key.data<unsigned char>(),
                      public_key.size(),
                      info.data(),
                      info.size()) != 1) {
    return ThrowHPKEOperationFailed(env, "HPKE encapsulation failed");
  }

  Local<Object> ret;
  if (Buffer::Copy(env->isolate(), enc.get<char>(), enc_len).ToLocal(&ret)) {
    args.GetReturnValue().Set(ret);
  }
}

void HPKEContext::Decap(const FunctionCallbackInfo<Value>& args) {
  HPKEContext* hpke;
  ASSIGN_OR_RETURN_UNWRAP(&hpke, args.This());
  Environment* env = Environment::GetCurrent(args);

  unsigned int offset = 0;
  auto private_key_data =
      KeyObjectData::GetPrivateKeyFromJs(args, &offset, true);
  if (!private_key_data) return;

  ArrayBufferOrViewContents<unsigned char> enc(args[offset++]);
  ArrayBufferOrViewContents<unsigned char> info(
      OptionalBufferSource(args, offset));

  ClearErrorOnReturn clear_error_on_return;
  {
    Mutex::ScopedLock lock(private_key_data.mutex());
    const auto& private_key = private_key_data.GetAsymmetricKey();
    if (OSSL_HPKE_decap(hpke->ctx_.get(),
                        enc.data(),
                        enc.size(),
                        private_key.get(),
                        info.data(),
                        info.size()) != 1) {
      return ThrowHPKEOperationFailed(env, "HPKE decapsulation failed");
    }
  }

  args.GetReturnValue().Set(Undefined(env->isolate()));
}

void HPKEContext::Seal(const FunctionCallbackInfo<Value>& args) {
  HPKEContext* hpke;
  ASSIGN_OR_RETURN_UNWRAP(&hpke, args.This());
  Environment* env = Environment::GetCurrent(args);

  ArrayBufferOrViewContents<unsigned char> plaintext(args[0]);
  ArrayBufferOrViewContents<unsigned char> aad(OptionalBufferSource(args, 1));

  size_t ciphertext_len =
      OSSL_HPKE_get_ciphertext_size(hpke->suite_, plaintext.size());
  if (ciphertext_len == 0) {
    return ThrowHPKEOperationFailed(env, "Invalid HPKE suite");
  }
  if (!CheckBufferLength(env, ciphertext_len)) return;

  auto ciphertext = DataPointer::Alloc(ciphertext_len);
  if (!ciphertext) {
    return ThrowHPKEOperationFailed(env, "Failed to allocate HPKE ciphertext");
  }

  ClearErrorOnReturn clear_error_on_return;
  if (OSSL_HPKE_seal(hpke->ctx_.get(),
                     ciphertext.get<unsigned char>(),
                     &ciphertext_len,
                     aad.data(),
                     aad.size(),
                     plaintext.data(),
                     plaintext.size()) != 1) {
    return ThrowHPKEOperationFailed(env, "HPKE seal failed");
  }

  Local<Object> ret;
  if (Buffer::Copy(env->isolate(), ciphertext.get<char>(), ciphertext_len)
          .ToLocal(&ret)) {
    args.GetReturnValue().Set(ret);
  }
}

void HPKEContext::Open(const FunctionCallbackInfo<Value>& args) {
  HPKEContext* hpke;
  ASSIGN_OR_RETURN_UNWRAP(&hpke, args.This());
  Environment* env = Environment::GetCurrent(args);

  ArrayBufferOrViewContents<unsigned char> ciphertext(args[0]);
  ArrayBufferOrViewContents<unsigned char> aad(OptionalBufferSource(args, 1));

  auto plaintext = ciphertext.size() == 0
                       ? DataPointer()
                       : DataPointer::Alloc(ciphertext.size());
  if (ciphertext.size() != 0 && !plaintext) {
    return ThrowHPKEOperationFailed(env, "Failed to allocate HPKE plaintext");
  }

  size_t plaintext_len = ciphertext.size();
  unsigned char empty_plaintext = 0;
  unsigned char* plaintext_data = ciphertext.size() == 0
                                      ? &empty_plaintext
                                      : plaintext.get<unsigned char>();
  ClearErrorOnReturn clear_error_on_return;
  if (OSSL_HPKE_open(hpke->ctx_.get(),
                     plaintext_data,
                     &plaintext_len,
                     aad.data(),
                     aad.size(),
                     ciphertext.data(),
                     ciphertext.size()) != 1) {
    return ThrowHPKEOperationFailed(env, "HPKE open failed");
  }

  Local<Object> ret;
  const char* plaintext_buffer =
      ciphertext.size() == 0 ? "" : plaintext.get<char>();
  if (Buffer::Copy(env->isolate(), plaintext_buffer, plaintext_len)
          .ToLocal(&ret)) {
    args.GetReturnValue().Set(ret);
  }
}

void HPKEContext::Export(const FunctionCallbackInfo<Value>& args) {
  HPKEContext* hpke;
  ASSIGN_OR_RETURN_UNWRAP(&hpke, args.This());
  Environment* env = Environment::GetCurrent(args);

  ArrayBufferOrViewContents<unsigned char> label(args[0]);
  const size_t secret_len = GetSizeArg(args, 1);

  auto secret =
      secret_len == 0 ? DataPointer() : DataPointer::Alloc(secret_len);
  if (secret_len != 0 && !secret) {
    return ThrowHPKEOperationFailed(env,
                                    "Failed to allocate HPKE exported secret");
  }

  unsigned char empty_secret = 0;
  unsigned char* secret_data =
      secret_len == 0 ? &empty_secret : secret.get<unsigned char>();

  ClearErrorOnReturn clear_error_on_return;
  if (OSSL_HPKE_export(hpke->ctx_.get(),
                       secret_data,
                       secret_len,
                       label.data(),
                       label.size()) != 1) {
    return ThrowHPKEOperationFailed(env, "HPKE export failed");
  }

  auto bytes = secret_len == 0 ? ByteSource::Allocated(nullptr, 0)
                               : ByteSource::Allocated(secret.release());
  auto data = KeyObjectData::CreateSecret(std::move(bytes));
  MaybeLocal<Object> maybe_handle = KeyObjectHandle::Create(env, data);
  Local<Object> handle;
  if (maybe_handle.ToLocal(&handle)) {
    args.GetReturnValue().Set(handle);
  }
}

void HPKEContext::IsSuiteSupported(const FunctionCallbackInfo<Value>& args) {
  args.GetReturnValue().Set(IsSupportedSuite(GetSuite(args)));
}

void HPKEContext::GetPublicEncapSize(const FunctionCallbackInfo<Value>& args) {
  const OSSL_HPKE_SUITE suite = GetSuite(args);
  ClearErrorOnReturn clear_error_on_return;
  const size_t size = OSSL_HPKE_get_public_encap_size(suite);
  args.GetReturnValue().Set(v8::Number::New(args.GetIsolate(), size));
}

void HPKEContext::GetCiphertextSize(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  const OSSL_HPKE_SUITE suite = GetSuite(args);
  const size_t plaintext_len = GetSizeArg(args, 3);

  ClearErrorOnReturn clear_error_on_return;
  const size_t size = OSSL_HPKE_get_ciphertext_size(suite, plaintext_len);
  if (!CheckBufferLength(env, size)) return;
  args.GetReturnValue().Set(v8::Number::New(args.GetIsolate(), size));
}

void HPKEContext::Initialize(Environment* env, Local<Object> target) {
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();
  Local<FunctionTemplate> t = NewFunctionTemplate(isolate, New);
  Local<Object> constants = Object::New(isolate);

  t->InstanceTemplate()->SetInternalFieldCount(
      HPKEContext::kInternalFieldCount);

  SetProtoMethod(isolate, t, "encap", Encap);
  SetProtoMethod(isolate, t, "decap", Decap);
  SetProtoMethod(isolate, t, "seal", Seal);
  SetProtoMethod(isolate, t, "open", Open);
  SetProtoMethod(isolate, t, "export", Export);

  SetConstructorFunction(context, target, "HPKEContext", t);
  DefineConstants(constants);
  target->Set(context, env->constants_string(), constants).Check();

  SetMethodNoSideEffect(context, target, "isSuiteSupported", IsSuiteSupported);
  SetMethodNoSideEffect(
      context, target, "getPublicEncapSize", GetPublicEncapSize);
  SetMethodNoSideEffect(
      context, target, "getCiphertextSize", GetCiphertextSize);
}

void HPKEContext::RegisterExternalReferences(
    ExternalReferenceRegistry* registry) {
  registry->Register(New);
  registry->Register(Encap);
  registry->Register(Decap);
  registry->Register(Seal);
  registry->Register(Open);
  registry->Register(Export);
  registry->Register(IsSuiteSupported);
  registry->Register(GetPublicEncapSize);
  registry->Register(GetCiphertextSize);
}

namespace HPKE {
void Initialize(Environment* env, Local<Object> target) {
  HPKEContext::Initialize(env, target);
}

void RegisterExternalReferences(ExternalReferenceRegistry* registry) {
  HPKEContext::RegisterExternalReferences(registry);
}
}  // namespace HPKE

}  // namespace crypto
}  // namespace node

#endif  // OPENSSL_WITH_HPKE
