#include <openssl/opensslv.h>

#ifdef _WIN32
#define DEFAULT_VISIBILITY __declspec(dllexport)
#else
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#endif

#if OPENSSL_VERSION_MAJOR >= 3 && !defined(OPENSSL_IS_BORINGSSL)
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#include <stdlib.h>
#include <string.h>

#include <string>

namespace {

struct KeyDefinition {
  const char* name;
  const char* algorithm;
  const char* fixture;
};

struct StoreCtx {
  const KeyDefinition* key = nullptr;
  bool loaded = false;
};

struct TestKey {
  const KeyDefinition* definition = nullptr;
  EVP_PKEY* key = nullptr;
};

const KeyDefinition kKeys[] = {
  { "rsa", "RSA", "keys/rsa_private_2048.pem" },
  { "rsa-pss", "RSA-PSS",
    "keys/rsa_pss_private_2048_sha256_sha256_16.pem" },
  { "dsa", "DSA", "keys/dsa_private.pem" },
  { "dh", "DH", "keys/dh_private.pem" },
  { "ec-p256", "EC", "keys/ec_p256_private.pem" },
  { "ed25519", "ED25519", "keys/ed25519_private.pem" },
  { "ed448", "ED448", "keys/ed448_private.pem" },
  { "x25519", "X25519", "keys/x25519_private.pem" },
  { "x448", "X448", "keys/x448_private.pem" },
  { "ml-kem-768", "ML-KEM-768",
    "keys/ml_kem_768_private_seed_only.pem" },
  { "ml-dsa-44", "ML-DSA-44",
    "keys/ml_dsa_44_private_seed_only.pem" },
  { "slh-dsa-sha2-128f", "SLH-DSA-SHA2-128f",
    "keys/slh_dsa_sha2_128f_private.pem" },
};

const KeyDefinition* FindKeyByName(const char* name) {
  for (const KeyDefinition& key : kKeys) {
    if (strcmp(name, key.name) == 0)
      return &key;
  }
  return nullptr;
}

EVP_PKEY* LoadFixtureKey(const KeyDefinition* definition) {
  const char* fixture_root =
      getenv("NODE_TEST_STORE_PROVIDER_FIXTURE_ROOT");
  if (fixture_root == nullptr)
    return nullptr;

  std::string path = fixture_root;
  if (!path.empty() && path.back() != '/' && path.back() != '\\')
    path += '/';
  path += definition->fixture;

  BIO* bio = BIO_new_file(path.c_str(), "r");
  if (bio == nullptr)
    return nullptr;

  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return key;
}

TestKey* NewTestKey(const KeyDefinition* definition, EVP_PKEY* pkey) {
  TestKey* key = static_cast<TestKey*>(OPENSSL_zalloc(sizeof(TestKey)));
  if (key == nullptr) {
    EVP_PKEY_free(pkey);
    return nullptr;
  }

  key->definition = definition;
  key->key = pkey;
  return key;
}

void* StoreOpen(void* /* provctx */, const char* uri) {
  const char prefix[] = "nodejs-test-store:";
  if (strncmp(uri, prefix, sizeof(prefix) - 1) != 0)
    return nullptr;

  const KeyDefinition* key = FindKeyByName(uri + sizeof(prefix) - 1);
  if (key == nullptr)
    return nullptr;

  StoreCtx* ctx = static_cast<StoreCtx*>(OPENSSL_zalloc(sizeof(StoreCtx)));
  if (ctx == nullptr)
    return nullptr;

  ctx->key = key;
  return ctx;
}

void* StoreOpenEx(void* provctx,
                  const char* uri,
                  const OSSL_PARAM* /* params */,
                  OSSL_PASSPHRASE_CALLBACK* /* pw_cb */,
                  void* /* pw_cbarg */) {
  return StoreOpen(provctx, uri);
}

int StoreLoad(void* loaderctx,
              OSSL_CALLBACK* object_cb,
              void* object_cbarg,
              OSSL_PASSPHRASE_CALLBACK* /* pw_cb */,
              void* /* pw_cbarg */) {
  StoreCtx* ctx = static_cast<StoreCtx*>(loaderctx);
  if (ctx->loaded)
    return 0;
  ctx->loaded = true;

  int object_type = OSSL_OBJECT_PKEY;
  const KeyDefinition* key = ctx->key;
  OSSL_PARAM object[] = {
    OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type),
    OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_TYPE,
        const_cast<char*>(key->algorithm),
        0),
    OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_REFERENCE,
        &key,
        sizeof(key)),
    OSSL_PARAM_END,
  };

  return object_cb(object, object_cbarg);
}

int StoreEof(void* loaderctx) {
  StoreCtx* ctx = static_cast<StoreCtx*>(loaderctx);
  return ctx->loaded;
}

int StoreClose(void* loaderctx) {
  OPENSSL_free(loaderctx);
  return 1;
}

void* KeyLoad(const void* reference, size_t reference_size) {
  const KeyDefinition* definition = nullptr;
  if (reference_size != sizeof(definition))
    return nullptr;

  memcpy(&definition, reference, sizeof(definition));
  if (definition == nullptr)
    return nullptr;

  EVP_PKEY* pkey = LoadFixtureKey(definition);
  if (pkey == nullptr)
    return nullptr;

  return NewTestKey(definition, pkey);
}

void KeyFree(void* keydata) {
  TestKey* key = static_cast<TestKey*>(keydata);
  if (key != nullptr) {
    EVP_PKEY_free(key->key);
    OPENSSL_free(key);
  }
}

int KeyHas(const void* keydata, int /* selection */) {
  const TestKey* key = static_cast<const TestKey*>(keydata);
  if (key == nullptr || key->key == nullptr)
    return 0;

  return 1;
}

int KeyGetParams(void* keydata, OSSL_PARAM params[]) {
  TestKey* key = static_cast<TestKey*>(keydata);
  if (key == nullptr || key->key == nullptr)
    return 0;
  return EVP_PKEY_get_params(key->key, params);
}

const OSSL_PARAM* KeyGettableParams(void* /* provctx */) {
  static const OSSL_PARAM params[] = {
    OSSL_PARAM_END,
  };
  return params;
}

int KeyExport(void* keydata,
              int selection,
              OSSL_CALLBACK* param_cb,
              void* cbarg) {
  TestKey* key = static_cast<TestKey*>(keydata);
  if (key == nullptr || key->key == nullptr)
    return 0;

  OSSL_PARAM* params = nullptr;
  int ok = EVP_PKEY_todata(key->key, selection, &params);
  if (ok == 1)
    ok = param_cb(params, cbarg);
  OSSL_PARAM_free(params);
  return ok;
}

const OSSL_PARAM* KeyExportTypes(int /* selection */) {
  static const OSSL_PARAM params[] = {
    OSSL_PARAM_END,
  };
  return params;
}

void* KeyDup(const void* keydata, int /* selection */) {
  const TestKey* key = static_cast<const TestKey*>(keydata);
  if (key == nullptr || key->key == nullptr)
    return nullptr;

  if (EVP_PKEY_up_ref(key->key) != 1)
    return nullptr;

  return NewTestKey(key->definition, key->key);
}

const char* ECQueryOperationName(int operation_id) {
  switch (operation_id) {
    case OSSL_OP_KEYEXCH:
      return "ECDH";
    case OSSL_OP_SIGNATURE:
      return "ECDSA";
  }
  return nullptr;
}

const char* RSAQueryOperationName(int /* operation_id */) {
  return "RSA";
}

const OSSL_DISPATCH store_functions[] = {
  { OSSL_FUNC_STORE_OPEN, reinterpret_cast<void (*)(void)>(StoreOpen) },
  { OSSL_FUNC_STORE_OPEN_EX, reinterpret_cast<void (*)(void)>(StoreOpenEx) },
  { OSSL_FUNC_STORE_LOAD, reinterpret_cast<void (*)(void)>(StoreLoad) },
  { OSSL_FUNC_STORE_EOF, reinterpret_cast<void (*)(void)>(StoreEof) },
  { OSSL_FUNC_STORE_CLOSE, reinterpret_cast<void (*)(void)>(StoreClose) },
  OSSL_DISPATCH_END,
};

const OSSL_DISPATCH keymgmt_functions[] = {
  { OSSL_FUNC_KEYMGMT_LOAD, reinterpret_cast<void (*)(void)>(KeyLoad) },
  { OSSL_FUNC_KEYMGMT_FREE, reinterpret_cast<void (*)(void)>(KeyFree) },
  { OSSL_FUNC_KEYMGMT_HAS, reinterpret_cast<void (*)(void)>(KeyHas) },
  { OSSL_FUNC_KEYMGMT_GET_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGetParams) },
  { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGettableParams) },
  { OSSL_FUNC_KEYMGMT_EXPORT, reinterpret_cast<void (*)(void)>(KeyExport) },
  { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    reinterpret_cast<void (*)(void)>(KeyExportTypes) },
  { OSSL_FUNC_KEYMGMT_DUP, reinterpret_cast<void (*)(void)>(KeyDup) },
  OSSL_DISPATCH_END,
};

const OSSL_DISPATCH ec_keymgmt_functions[] = {
  { OSSL_FUNC_KEYMGMT_LOAD, reinterpret_cast<void (*)(void)>(KeyLoad) },
  { OSSL_FUNC_KEYMGMT_FREE, reinterpret_cast<void (*)(void)>(KeyFree) },
  { OSSL_FUNC_KEYMGMT_HAS, reinterpret_cast<void (*)(void)>(KeyHas) },
  { OSSL_FUNC_KEYMGMT_GET_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGetParams) },
  { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGettableParams) },
  { OSSL_FUNC_KEYMGMT_EXPORT, reinterpret_cast<void (*)(void)>(KeyExport) },
  { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    reinterpret_cast<void (*)(void)>(KeyExportTypes) },
  { OSSL_FUNC_KEYMGMT_DUP, reinterpret_cast<void (*)(void)>(KeyDup) },
  { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    reinterpret_cast<void (*)(void)>(ECQueryOperationName) },
  OSSL_DISPATCH_END,
};

const OSSL_DISPATCH rsa_keymgmt_functions[] = {
  { OSSL_FUNC_KEYMGMT_LOAD, reinterpret_cast<void (*)(void)>(KeyLoad) },
  { OSSL_FUNC_KEYMGMT_FREE, reinterpret_cast<void (*)(void)>(KeyFree) },
  { OSSL_FUNC_KEYMGMT_HAS, reinterpret_cast<void (*)(void)>(KeyHas) },
  { OSSL_FUNC_KEYMGMT_GET_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGetParams) },
  { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
    reinterpret_cast<void (*)(void)>(KeyGettableParams) },
  { OSSL_FUNC_KEYMGMT_EXPORT, reinterpret_cast<void (*)(void)>(KeyExport) },
  { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    reinterpret_cast<void (*)(void)>(KeyExportTypes) },
  { OSSL_FUNC_KEYMGMT_DUP, reinterpret_cast<void (*)(void)>(KeyDup) },
  { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    reinterpret_cast<void (*)(void)>(RSAQueryOperationName) },
  OSSL_DISPATCH_END,
};

const OSSL_ALGORITHM store_algs[] = {
  { "nodejs-test-store", "provider=nodejs-test-store", store_functions },
  { nullptr, nullptr, nullptr },
};

const OSSL_ALGORITHM keymgmt_algs[] = {
  { "RSA", "provider=nodejs-test-store", rsa_keymgmt_functions },
  { "RSA-PSS", "provider=nodejs-test-store", rsa_keymgmt_functions },
  { "DSA", "provider=nodejs-test-store", keymgmt_functions },
  { "DH", "provider=nodejs-test-store", keymgmt_functions },
  { "EC", "provider=nodejs-test-store", ec_keymgmt_functions },
  { "ED25519", "provider=nodejs-test-store", keymgmt_functions },
  { "ED448", "provider=nodejs-test-store", keymgmt_functions },
  { "X25519", "provider=nodejs-test-store", keymgmt_functions },
  { "X448", "provider=nodejs-test-store", keymgmt_functions },
  { "ML-KEM-768", "provider=nodejs-test-store", keymgmt_functions },
  { "ML-DSA-44", "provider=nodejs-test-store", keymgmt_functions },
  { "SLH-DSA-SHA2-128f", "provider=nodejs-test-store", keymgmt_functions },
  { nullptr, nullptr, nullptr },
};

const OSSL_ALGORITHM* QueryOperation(void* /* provctx */,
                                     int operation_id,
                                     int* no_store) {
  *no_store = 0;
  switch (operation_id) {
    case OSSL_OP_STORE:
      return store_algs;
    case OSSL_OP_KEYMGMT:
      return keymgmt_algs;
  }
  return nullptr;
}

const OSSL_DISPATCH provider_functions[] = {
  {
    OSSL_FUNC_PROVIDER_QUERY_OPERATION,
    reinterpret_cast<void (*)(void)>(QueryOperation),
  },
  OSSL_DISPATCH_END,
};

}  // namespace

extern "C" DEFAULT_VISIBILITY int OSSL_provider_init(
    const OSSL_CORE_HANDLE* /* handle */,
    const OSSL_DISPATCH* /* in */,
    const OSSL_DISPATCH** out,
    void** provctx) {
  *provctx = nullptr;
  *out = provider_functions;
  return 1;
}
#else
extern "C" DEFAULT_VISIBILITY void nodejs_test_store_provider_noop() {}
#endif
