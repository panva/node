#include "crypto/crypto_slh_dsa.h"
#include "crypto/crypto_util.h"
#include "env-inl.h"
#include "string_bytes.h"
#include "v8.h"

namespace node {

using ncrypto::DataPointer;
using ncrypto::EVPKeyPointer;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

namespace crypto {

#if OPENSSL_WITH_PQC
constexpr const char* GetSlhDsaAlgorithmName(int id) {
  switch (id) {
    case EVP_PKEY_SLH_DSA_SHA2_128F:
      return "SLH-DSA-SHA2-128f";
    case EVP_PKEY_SLH_DSA_SHA2_128S:
      return "SLH-DSA-SHA2-128s";
    case EVP_PKEY_SLH_DSA_SHA2_192F:
      return "SLH-DSA-SHA2-192f";
    case EVP_PKEY_SLH_DSA_SHA2_192S:
      return "SLH-DSA-SHA2-192s";
    case EVP_PKEY_SLH_DSA_SHA2_256F:
      return "SLH-DSA-SHA2-256f";
    case EVP_PKEY_SLH_DSA_SHA2_256S:
      return "SLH-DSA-SHA2-256s";
    case EVP_PKEY_SLH_DSA_SHAKE_128F:
      return "SLH-DSA-SHAKE-128f";
    case EVP_PKEY_SLH_DSA_SHAKE_128S:
      return "SLH-DSA-SHAKE-128s";
    case EVP_PKEY_SLH_DSA_SHAKE_192F:
      return "SLH-DSA-SHAKE-192f";
    case EVP_PKEY_SLH_DSA_SHAKE_192S:
      return "SLH-DSA-SHAKE-192s";
    case EVP_PKEY_SLH_DSA_SHAKE_256F:
      return "SLH-DSA-SHAKE-256f";
    case EVP_PKEY_SLH_DSA_SHAKE_256S:
      return "SLH-DSA-SHAKE-256s";
    default:
      return nullptr;
  }
}

/**
 * Exports an SLH-DSA key to JWK format.
 *
 * The resulting JWK object contains:
 * - "kty": "AKP" (Asymmetric Key Pair - required)
 * - "alg": "SLH-DSA-*" (Algorithm identifier - required for "AKP")
 * - "pub": "<Base64URL-encoded raw public key>" (required)
 * - "priv": "<Base64URL-encoded raw private key>" (required for private keys)
 */
bool ExportJwkSlhDsaKey(Environment* env,
                        const KeyObjectData& key,
                        Local<Object> target) {
  Mutex::ScopedLock lock(key.mutex());
  const auto& pkey = key.GetAsymmetricKey();

  const char* alg = GetSlhDsaAlgorithmName(pkey.id());
  CHECK(alg);

  static constexpr auto trySetKey = [](Environment* env,
                                       DataPointer data,
                                       Local<Object> target,
                                       Local<String> key) {
    Local<Value> encoded;
    if (!data) return false;
    const ncrypto::Buffer<const char> out = data;
    return StringBytes::Encode(env->isolate(), out.data, out.len, BASE64URL)
               .ToLocal(&encoded) &&
           target->Set(env->context(), key, encoded).IsJust();
  };

  if (key.GetKeyType() == kKeyTypePrivate) {
    if (!trySetKey(env, pkey.rawPrivateKey(), target, env->jwk_priv_string())) {
      return false;
    }
  }

  return !(
      target->Set(env->context(), env->jwk_kty_string(), env->jwk_akp_string())
          .IsNothing() ||
      target
          ->Set(env->context(),
                env->jwk_alg_string(),
                OneByteString(env->isolate(), alg))
          .IsNothing() ||
      !trySetKey(env, pkey.rawPublicKey(), target, env->jwk_pub_string()));
}

KeyObjectData ImportJWKSlhDsaKey(Environment* env, Local<Object> jwk) {
  Local<Value> alg_value;
  Local<Value> pub_value;
  Local<Value> priv_value;

  if (!jwk->Get(env->context(), env->jwk_alg_string()).ToLocal(&alg_value) ||
      !jwk->Get(env->context(), env->jwk_pub_string()).ToLocal(&pub_value) ||
      !jwk->Get(env->context(), env->jwk_priv_string()).ToLocal(&priv_value)) {
    return {};
  }

  static constexpr int kSlhDsaIds[] = {
      EVP_PKEY_SLH_DSA_SHA2_128F,
      EVP_PKEY_SLH_DSA_SHA2_128S,
      EVP_PKEY_SLH_DSA_SHA2_192F,
      EVP_PKEY_SLH_DSA_SHA2_192S,
      EVP_PKEY_SLH_DSA_SHA2_256F,
      EVP_PKEY_SLH_DSA_SHA2_256S,
      EVP_PKEY_SLH_DSA_SHAKE_128F,
      EVP_PKEY_SLH_DSA_SHAKE_128S,
      EVP_PKEY_SLH_DSA_SHAKE_192F,
      EVP_PKEY_SLH_DSA_SHAKE_192S,
      EVP_PKEY_SLH_DSA_SHAKE_256F,
      EVP_PKEY_SLH_DSA_SHAKE_256S,
  };

  Utf8Value alg(env->isolate(),
                alg_value->IsString() ? alg_value.As<String>()
                                      : String::Empty(env->isolate()));

  int id = NID_undef;
  for (int candidate : kSlhDsaIds) {
    if (strcmp(*alg, GetSlhDsaAlgorithmName(candidate)) == 0) {
      id = candidate;
      break;
    }
  }

  if (id == NID_undef) {
    // Return empty without throwing to signal that this is not an SLH-DSA
    // algorithm, allowing the caller to try other AKP handlers.
    return {};
  }

  if (!pub_value->IsString() ||
      (!priv_value->IsUndefined() && !priv_value->IsString())) {
    THROW_ERR_CRYPTO_INVALID_JWK(env, "Invalid JWK AKP key");
    return {};
  }

  KeyType type = priv_value->IsString() ? kKeyTypePrivate : kKeyTypePublic;

  EVPKeyPointer pkey;
  if (type == kKeyTypePrivate) {
    // SLH-DSA uses raw private key (not seed)
    ByteSource priv =
        ByteSource::FromEncodedString(env, priv_value.As<String>());
    pkey = EVPKeyPointer::NewRawPrivate(
        id,
        ncrypto::Buffer<const unsigned char>{
            .data = priv.data<const unsigned char>(),
            .len = priv.size(),
        });
  } else {
    ByteSource pub = ByteSource::FromEncodedString(env, pub_value.As<String>());
    pkey =
        EVPKeyPointer::NewRawPublic(id,
                                    ncrypto::Buffer<const unsigned char>{
                                        .data = pub.data<const unsigned char>(),
                                        .len = pub.size(),
                                    });
  }

  if (!pkey) {
    THROW_ERR_CRYPTO_INVALID_JWK(env, "Invalid JWK AKP key");
    return {};
  }

  // When importing a private key, verify that the JWK's pub field matches
  // the public key derived from the private key.
  if (type == kKeyTypePrivate && pub_value->IsString()) {
    ByteSource pub = ByteSource::FromEncodedString(env, pub_value.As<String>());
    auto derived_pub = pkey.rawPublicKey();
    if (!derived_pub || derived_pub.size() != pub.size() ||
        CRYPTO_memcmp(derived_pub.get(), pub.data(), pub.size()) != 0) {
      THROW_ERR_CRYPTO_INVALID_JWK(env, "Invalid JWK AKP key");
      return {};
    }
  }

  return KeyObjectData::CreateAsymmetric(type, std::move(pkey));
}
#endif
}  // namespace crypto
}  // namespace node
