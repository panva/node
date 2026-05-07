#ifndef SRC_CRYPTO_CRYPTO_HPKE_H_
#define SRC_CRYPTO_CRYPTO_HPKE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "base_object.h"
#include "crypto/crypto_keys.h"
#include "crypto/crypto_util.h"
#include "env.h"
#include "memory_tracker.h"
#include "node_external_reference.h"
#include "v8.h"

#if OPENSSL_WITH_HPKE
#include <openssl/hpke.h>

namespace node::crypto {

class HPKEContext final : public BaseObject {
 public:
  static void Initialize(Environment* env, v8::Local<v8::Object> target);
  static void RegisterExternalReferences(ExternalReferenceRegistry* registry);

  void MemoryInfo(MemoryTracker* tracker) const override;
  SET_MEMORY_INFO_NAME(HPKEContext)
  SET_SELF_SIZE(HPKEContext)

 protected:
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Encap(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Decap(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Seal(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Open(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Export(const v8::FunctionCallbackInfo<v8::Value>& args);

  static void IsSuiteSupported(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GetPublicEncapSize(
      const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GetCiphertextSize(
      const v8::FunctionCallbackInfo<v8::Value>& args);

  HPKEContext(Environment* env,
              v8::Local<v8::Object> wrap,
              OSSL_HPKE_CTX* ctx,
              OSSL_HPKE_SUITE suite);

 private:
  ncrypto::DeleteFnPtr<OSSL_HPKE_CTX, OSSL_HPKE_CTX_free> ctx_;
  OSSL_HPKE_SUITE suite_;
};

namespace HPKE {
void Initialize(Environment* env, v8::Local<v8::Object> target);
void RegisterExternalReferences(ExternalReferenceRegistry* registry);
}  // namespace HPKE

}  // namespace node::crypto

#else

namespace node::crypto::HPKE {
inline void Initialize(Environment* env, v8::Local<v8::Object> target) {}
inline void RegisterExternalReferences(ExternalReferenceRegistry* registry) {}
}  // namespace node::crypto::HPKE

#endif  // OPENSSL_WITH_HPKE

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_CRYPTO_CRYPTO_HPKE_H_
