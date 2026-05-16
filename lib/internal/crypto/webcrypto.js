'use strict';

const {
  ArrayPrototypeSlice,
  FunctionPrototypeCall,
  JSONParse,
  JSONStringify,
  ObjectDefineProperties,
  PromisePrototypeThen,
  PromiseReject,
  PromiseResolve,
  ReflectApply,
  ReflectConstruct,
  StringPrototypeRepeat,
  StringPrototypeSlice,
  StringPrototypeStartsWith,
  SymbolToStringTag,
  TypedArrayPrototypeGetBuffer,
} = primordials;

const {
  kWebCryptoKeyFormatRaw,
  kWebCryptoKeyFormatPKCS8,
  kWebCryptoKeyFormatSPKI,
  kWebCryptoCipherEncrypt,
  kWebCryptoCipherDecrypt,
} = internalBinding('crypto');

const { TextDecoder, TextEncoder } = require('internal/encoding');

const {
  codes: {
    ERR_ILLEGAL_CONSTRUCTOR,
    ERR_INVALID_THIS,
  },
} = require('internal/errors');

const {
  createPublicKey,
  CryptoKey,
  getCryptoKeyAlgorithm,
  getCryptoKeyExtractable,
  getCryptoKeyHandle,
  getCryptoKeyType,
  getCryptoKeyUsages,
  getCryptoKeyUsagesMask,
  hasCryptoKeyUsage,
  importGenericSecretKey,
  PrivateKeyObject,
} = require('internal/crypto/keys');

const {
  asyncDigest,
} = require('internal/crypto/hash');

const {
  getBlockSize,
  normalizeAlgorithm,
  normalizeHashName,
  validateMaxBufferLength,
} = require('internal/crypto/util');

const {
  emitExperimentalWarning,
  kEnumerableProperty,
  lazyDOMException,
} = require('internal/util');

const {
  getRandomValues: _getRandomValues,
  randomUUID: _randomUUID,
} = require('internal/crypto/random');

let webidl;

function digest(algorithm, data) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'digest' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    data = webidl.converters.BufferSource(data, {
      prefix,
      context: '2nd argument',
    });

    algorithm = normalizeAlgorithm(algorithm, 'digest');

    return FunctionPrototypeCall(asyncDigest, this, algorithm, data);
  } catch (err) {
    return PromiseReject(err);
  }
}

function randomUUID() {
  if (this !== crypto) throw new ERR_INVALID_THIS('Crypto');
  return _randomUUID();
}

function generateKey(
  algorithm,
  extractable,
  keyUsages) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'generateKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 3, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '2nd argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '3rd argument',
    });

    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'generateKey');
    switch (normalizedAlgorithm.name) {
      case 'RSASSA-PKCS1-v1_5':
        // Fall through
      case 'RSA-PSS':
        // Fall through
      case 'RSA-OAEP':
        return require('internal/crypto/rsa')
          .rsaKeyGenerate(normalizedAlgorithm, extractable, usages);
      case 'Ed25519':
        // Fall through
      case 'Ed448':
        // Fall through
      case 'X25519':
        // Fall through
      case 'X448':
        return require('internal/crypto/cfrg')
          .cfrgGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'ECDSA':
        // Fall through
      case 'ECDH':
        return require('internal/crypto/ec')
          .ecGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'HMAC':
        return require('internal/crypto/mac')
          .hmacGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'AES-CTR':
        // Fall through
      case 'AES-CBC':
        // Fall through
      case 'AES-GCM':
        // Fall through
      case 'AES-OCB':
        // Fall through
      case 'AES-KW':
        return require('internal/crypto/aes')
          .aesGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'ChaCha20-Poly1305':
        return require('internal/crypto/chacha20_poly1305')
          .c20pGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'ML-DSA-44':
        // Fall through
      case 'ML-DSA-65':
        // Fall through
      case 'ML-DSA-87':
        return require('internal/crypto/ml_dsa')
          .mlDsaGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'ML-KEM-512':
        // Fall through
      case 'ML-KEM-768':
        // Fall through
      case 'ML-KEM-1024':
        return require('internal/crypto/ml_kem')
          .mlKemGenerateKey(normalizedAlgorithm, extractable, usages);
      case 'KMAC128':
        // Fall through
      case 'KMAC256':
        return require('internal/crypto/mac')
          .kmacGenerateKey(normalizedAlgorithm, extractable, usages);
      default:
        throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
    }
  } catch (err) {
    return PromiseReject(err);
  }
}

function deriveBits(algorithm, baseKey, length = null) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'deriveBits' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    baseKey = webidl.converters.CryptoKey(baseKey, {
      prefix,
      context: '2nd argument',
    });
    if (length !== null) {
      length = webidl.converters['unsigned long'](length, {
        prefix,
        context: '3rd argument',
      });
    }

    algorithm = normalizeAlgorithm(algorithm, 'deriveBits');
    if (!hasCryptoKeyUsage(baseKey, 'deriveBits')) {
      throw lazyDOMException(
        'baseKey does not have deriveBits usage',
        'InvalidAccessError');
    }
    if (getCryptoKeyAlgorithm(baseKey).name !== algorithm.name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');
    switch (algorithm.name) {
      case 'X25519':
        // Fall through
      case 'X448':
        // Fall through
      case 'ECDH':
        return require('internal/crypto/diffiehellman')
          .ecdhDeriveBits(algorithm, baseKey, length);
      case 'HKDF':
        return require('internal/crypto/hkdf')
          .hkdfDeriveBits(algorithm, baseKey, length);
      case 'PBKDF2':
        return require('internal/crypto/pbkdf2')
          .pbkdf2DeriveBits(algorithm, baseKey, length);
      case 'Argon2d':
        // Fall through
      case 'Argon2i':
        // Fall through
      case 'Argon2id':
        return require('internal/crypto/argon2')
          .argon2DeriveBits(algorithm, baseKey, length);
    }
    throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
  } catch (err) {
    return PromiseReject(err);
  }
}

function getKeyLength({ name, length, hash }) {
  switch (name) {
    case 'AES-CTR':
    case 'AES-CBC':
    case 'AES-GCM':
    case 'AES-OCB':
    case 'AES-KW':
      if (length !== 128 && length !== 192 && length !== 256)
        throw lazyDOMException('Invalid key length', 'OperationError');

      return length;
    case 'HMAC':
      if (length === undefined) {
        return getBlockSize(hash?.name);
      }

      if (typeof length === 'number' && length !== 0) {
        return length;
      }

      throw lazyDOMException('Invalid key length', 'OperationError');
    case 'KMAC128':
    case 'KMAC256':
      if (typeof length === 'number') {
        return length;
      }

      return name === 'KMAC128' ? 128 : 256;
    case 'HKDF':
    case 'PBKDF2':
    case 'Argon2d':
    case 'Argon2i':
    case 'Argon2id':
      return null;
    case 'ChaCha20-Poly1305':
      return 256;
  }
}

function deriveKey(
  algorithm,
  baseKey,
  derivedKeyType,
  extractable,
  keyUsages) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'deriveKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 5, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    baseKey = webidl.converters.CryptoKey(baseKey, {
      prefix,
      context: '2nd argument',
    });
    derivedKeyType = webidl.converters.AlgorithmIdentifier(derivedKeyType, {
      prefix,
      context: '3rd argument',
    });
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '4th argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '5th argument',
    });

    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'deriveBits');
    const normalizedDerivedKeyAlgorithmImport = normalizeAlgorithm(derivedKeyType, 'importKey');
    const normalizedDerivedKeyAlgorithmLength = normalizeAlgorithm(derivedKeyType, 'get key length');
    if (!hasCryptoKeyUsage(baseKey, 'deriveKey')) {
      throw lazyDOMException(
        'baseKey does not have deriveKey usage',
        'InvalidAccessError');
    }
    if (getCryptoKeyAlgorithm(baseKey).name !== normalizedAlgorithm.name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

    const length = getKeyLength(normalizedDerivedKeyAlgorithmLength);
    let secret;
    switch (normalizedAlgorithm.name) {
      case 'X25519':
        // Fall through
      case 'X448':
        // Fall through
      case 'ECDH':
        secret = require('internal/crypto/diffiehellman')
          .ecdhDeriveBits(normalizedAlgorithm, baseKey, length);
        break;
      case 'HKDF':
        secret = require('internal/crypto/hkdf')
          .hkdfDeriveBits(normalizedAlgorithm, baseKey, length);
        break;
      case 'PBKDF2':
        secret = require('internal/crypto/pbkdf2')
          .pbkdf2DeriveBits(normalizedAlgorithm, baseKey, length);
        break;
      case 'Argon2d':
        // Fall through
      case 'Argon2i':
        // Fall through
      case 'Argon2id':
        secret = require('internal/crypto/argon2')
          .argon2DeriveBits(normalizedAlgorithm, baseKey, length);
        break;
      default:
        throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
    }

    return PromisePrototypeThen(secret, (secret) => FunctionPrototypeCall(
      importKeySync,
      this,
      'raw-secret', secret, normalizedDerivedKeyAlgorithmImport, extractable, usages,
    ));
  } catch (err) {
    return PromiseReject(err);
  }
}

function exportKeySpki(key) {
  switch (getCryptoKeyAlgorithm(key).name) {
    case 'RSASSA-PKCS1-v1_5':
      // Fall through
    case 'RSA-PSS':
      // Fall through
    case 'RSA-OAEP':
      return require('internal/crypto/rsa')
        .rsaExportKey(key, kWebCryptoKeyFormatSPKI);
    case 'ECDSA':
      // Fall through
    case 'ECDH':
      return require('internal/crypto/ec')
        .ecExportKey(key, kWebCryptoKeyFormatSPKI);
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      // Fall through
    case 'X25519':
      // Fall through
    case 'X448':
      return require('internal/crypto/cfrg')
        .cfrgExportKey(key, kWebCryptoKeyFormatSPKI);
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      return require('internal/crypto/ml_dsa')
        .mlDsaExportKey(key, kWebCryptoKeyFormatSPKI);
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024':
      return require('internal/crypto/ml_kem')
        .mlKemExportKey(key, kWebCryptoKeyFormatSPKI);
    default:
      return undefined;
  }
}

function exportKeyPkcs8(key) {
  switch (getCryptoKeyAlgorithm(key).name) {
    case 'RSASSA-PKCS1-v1_5':
      // Fall through
    case 'RSA-PSS':
      // Fall through
    case 'RSA-OAEP':
      return require('internal/crypto/rsa')
        .rsaExportKey(key, kWebCryptoKeyFormatPKCS8);
    case 'ECDSA':
      // Fall through
    case 'ECDH':
      return require('internal/crypto/ec')
        .ecExportKey(key, kWebCryptoKeyFormatPKCS8);
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      // Fall through
    case 'X25519':
      // Fall through
    case 'X448':
      return require('internal/crypto/cfrg')
        .cfrgExportKey(key, kWebCryptoKeyFormatPKCS8);
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      return require('internal/crypto/ml_dsa')
        .mlDsaExportKey(key, kWebCryptoKeyFormatPKCS8);
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024':
      return require('internal/crypto/ml_kem')
        .mlKemExportKey(key, kWebCryptoKeyFormatPKCS8);
    default:
      return undefined;
  }
}

function exportKeyRawPublic(key, format) {
  switch (getCryptoKeyAlgorithm(key).name) {
    case 'ECDSA':
      // Fall through
    case 'ECDH':
      return require('internal/crypto/ec')
        .ecExportKey(key, kWebCryptoKeyFormatRaw);
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      // Fall through
    case 'X25519':
      // Fall through
    case 'X448':
      return require('internal/crypto/cfrg')
        .cfrgExportKey(key, kWebCryptoKeyFormatRaw);
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87': {
      // ML-DSA keys don't recognize "raw"
      if (format !== 'raw-public') {
        return undefined;
      }
      return require('internal/crypto/ml_dsa')
        .mlDsaExportKey(key, kWebCryptoKeyFormatRaw);
    }
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024': {
      // ML-KEM keys don't recognize "raw"
      if (format !== 'raw-public') {
        return undefined;
      }
      return require('internal/crypto/ml_kem')
        .mlKemExportKey(key, kWebCryptoKeyFormatRaw);
    }
    default:
      return undefined;
  }
}

function exportKeyRawSeed(key) {
  switch (getCryptoKeyAlgorithm(key).name) {
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      return require('internal/crypto/ml_dsa')
        .mlDsaExportKey(key, kWebCryptoKeyFormatRaw);
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024':
      return require('internal/crypto/ml_kem')
        .mlKemExportKey(key, kWebCryptoKeyFormatRaw);
    default:
      return undefined;
  }
}

function exportKeyRawSecret(key, format) {
  switch (getCryptoKeyAlgorithm(key).name) {
    case 'AES-CTR':
      // Fall through
    case 'AES-CBC':
      // Fall through
    case 'AES-GCM':
      // Fall through
    case 'AES-KW':
      // Fall through
    case 'HMAC':
      return TypedArrayPrototypeGetBuffer(getCryptoKeyHandle(key).export());
    case 'AES-OCB':
      // Fall through
    case 'KMAC128':
      // Fall through
    case 'KMAC256':
      // Fall through
    case 'ChaCha20-Poly1305':
      if (format === 'raw-secret') {
        return TypedArrayPrototypeGetBuffer(getCryptoKeyHandle(key).export());
      }
      return undefined;
    default:
      return undefined;
  }
}

function exportKeyJWK(key) {
  const algorithm = getCryptoKeyAlgorithm(key);
  const parameters = {
    key_ops: ArrayPrototypeSlice(getCryptoKeyUsages(key), 0),
    ext: getCryptoKeyExtractable(key),
  };
  switch (algorithm.name) {
    case 'RSASSA-PKCS1-v1_5': {
      const alg = normalizeHashName(
        algorithm.hash.name,
        normalizeHashName.kContextJwkRsa);
      if (alg) parameters.alg = alg;
      break;
    }
    case 'RSA-PSS': {
      const alg = normalizeHashName(
        algorithm.hash.name,
        normalizeHashName.kContextJwkRsaPss);
      if (alg) parameters.alg = alg;
      break;
    }
    case 'RSA-OAEP': {
      const alg = normalizeHashName(
        algorithm.hash.name,
        normalizeHashName.kContextJwkRsaOaep);
      if (alg) parameters.alg = alg;
      break;
    }
    case 'ECDSA':
      // Fall through
    case 'ECDH':
      // Fall through
    case 'X25519':
      // Fall through
    case 'X448':
      // Fall through
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      // Fall through
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024':
      break;
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      parameters.alg = algorithm.name;
      break;
    case 'AES-CTR':
      // Fall through
    case 'AES-CBC':
      // Fall through
    case 'AES-GCM':
      // Fall through
    case 'AES-OCB':
      // Fall through
    case 'AES-KW':
      parameters.alg = require('internal/crypto/aes')
        .getAlgorithmName(algorithm.name, algorithm.length);
      break;
    case 'ChaCha20-Poly1305':
      parameters.alg = 'C20P';
      break;
    case 'HMAC': {
      const alg = normalizeHashName(
        algorithm.hash.name,
        normalizeHashName.kContextJwkHmac);
      if (alg) parameters.alg = alg;
      break;
    }
    case 'KMAC128':
      parameters.alg = 'K128';
      break;
    case 'KMAC256': {
      parameters.alg = 'K256';
      break;
    }
    default:
      return undefined;
  }

  return getCryptoKeyHandle(key).exportJwk(parameters, true);
}

function exportKeySync(format, key) {
  const algorithm = getCryptoKeyAlgorithm(key);
  try {
    normalizeAlgorithm(algorithm, 'exportKey');
  } catch {
    throw lazyDOMException(
      `${algorithm.name} key export is not supported`, 'NotSupportedError');
  }

  if (!getCryptoKeyExtractable(key))
    throw lazyDOMException('key is not extractable', 'InvalidAccessError');

  const type = getCryptoKeyType(key);
  let result;
  switch (format) {
    case 'spki': {
      if (type === 'public') {
        result = exportKeySpki(key);
      }
      break;
    }
    case 'pkcs8': {
      if (type === 'private') {
        result = exportKeyPkcs8(key);
      }
      break;
    }
    case 'jwk': {
      result = exportKeyJWK(key);
      break;
    }
    case 'raw-secret': {
      if (type === 'secret') {
        result = exportKeyRawSecret(key, format);
      }
      break;
    }
    case 'raw-public': {
      if (type === 'public') {
        result = exportKeyRawPublic(key, format);
      }
      break;
    }
    case 'raw-seed': {
      if (type === 'private') {
        result = exportKeyRawSeed(key);
      }
      break;
    }
    case 'raw': {
      if (type === 'secret') {
        result = exportKeyRawSecret(key, format);
      } else if (type === 'public') {
        result = exportKeyRawPublic(key, format);
      }
      break;
    }
  }

  if (!result) {
    throw lazyDOMException(
      `Unable to export ${algorithm.name} ${type} key using ${format} format`,
      'NotSupportedError');
  }

  return result;
}

function exportKey(format, key) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'exportKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });
    format = webidl.converters.KeyFormat(format, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });

    return PromiseResolve(exportKeySync(format, key));
  } catch (err) {
    return PromiseReject(err);
  }
}

function aliasKeyFormat(format) {
  switch (format) {
    case 'raw-public':
    case 'raw-secret':
      return 'raw';
    default:
      return format;
  }
}

function importKeySync(format, keyData, algorithm, extractable, keyUsages) {
  let result;
  switch (algorithm.name) {
    case 'RSASSA-PKCS1-v1_5':
      // Fall through
    case 'RSA-PSS':
      // Fall through
    case 'RSA-OAEP':
      format = aliasKeyFormat(format);
      result = require('internal/crypto/rsa')
        .rsaImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
    case 'ECDSA':
      // Fall through
    case 'ECDH':
      format = aliasKeyFormat(format);
      result = require('internal/crypto/ec')
        .ecImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      // Fall through
    case 'X25519':
      // Fall through
    case 'X448':
      format = aliasKeyFormat(format);
      result = require('internal/crypto/cfrg')
        .cfrgImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
    case 'HMAC':
      // Fall through
    case 'KMAC128':
      // Fall through
    case 'KMAC256':
      result = require('internal/crypto/mac')
        .macImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
    case 'AES-CTR':
      // Fall through
    case 'AES-CBC':
      // Fall through
    case 'AES-GCM':
      // Fall through
    case 'AES-KW':
      // Fall through
    case 'AES-OCB':
      result = require('internal/crypto/aes')
        .aesImportKey(algorithm, format, keyData, extractable, keyUsages);
      break;
    case 'ChaCha20-Poly1305':
      result = require('internal/crypto/chacha20_poly1305')
        .c20pImportKey(algorithm, format, keyData, extractable, keyUsages);
      break;
    case 'HKDF':
      // Fall through
    case 'PBKDF2':
      format = aliasKeyFormat(format);
      result = importGenericSecretKey(
        algorithm,
        format,
        keyData,
        extractable,
        keyUsages);
      break;
    case 'Argon2d':
      // Fall through
    case 'Argon2i':
      // Fall through
    case 'Argon2id':
      if (format === 'raw-secret') {
        result = importGenericSecretKey(
          algorithm,
          format,
          keyData,
          extractable,
          keyUsages);
      }
      break;
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      result = require('internal/crypto/ml_dsa')
        .mlDsaImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
    case 'ML-KEM-512':
      // Fall through
    case 'ML-KEM-768':
      // Fall through
    case 'ML-KEM-1024':
      result = require('internal/crypto/ml_kem')
        .mlKemImportKey(format, keyData, algorithm, extractable, keyUsages);
      break;
  }

  if (!result) {
    throw lazyDOMException(
      `Unable to import ${algorithm.name} using ${format} format`,
      'NotSupportedError');
  }

  const type = getCryptoKeyType(result);
  if ((type === 'secret' || type === 'private') && getCryptoKeyUsagesMask(result) === 0) {
    throw lazyDOMException(
      `Usages cannot be empty when importing a ${type} key.`,
      'SyntaxError');
  }

  return result;
}

function importKey(
  format,
  keyData,
  algorithm,
  extractable,
  keyUsages) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'importKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 5, { prefix });
    format = webidl.converters.KeyFormat(format, {
      prefix,
      context: '1st argument',
    });
    const type = format === 'jwk' ? 'JsonWebKey' : 'BufferSource';
    keyData = webidl.converters[type](keyData, {
      prefix,
      context: '2nd argument',
    });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '3rd argument',
    });
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '4th argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '5th argument',
    });

    const normalizedAlgorithm = normalizeAlgorithm(algorithm, 'importKey');

    return PromiseResolve(FunctionPrototypeCall(
      importKeySync,
      this,
      format, keyData, normalizedAlgorithm, extractable, usages,
    ));
  } catch (err) {
    return PromiseReject(err);
  }
}

// subtle.wrapKey() is essentially a subtle.exportKey() followed
// by a subtle.encrypt().
function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'wrapKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 4, { prefix });
    format = webidl.converters.KeyFormat(format, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });
    wrappingKey = webidl.converters.CryptoKey(wrappingKey, {
      prefix,
      context: '3rd argument',
    });
    let algorithm = webidl.converters.AlgorithmIdentifier(wrapAlgorithm, {
      prefix,
      context: '4th argument',
    });

    try {
      algorithm = normalizeAlgorithm(algorithm, 'wrapKey');
    } catch {
      algorithm = normalizeAlgorithm(algorithm, 'encrypt');
    }

    if (algorithm.name !== getCryptoKeyAlgorithm(wrappingKey).name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

    if (!hasCryptoKeyUsage(wrappingKey, 'wrapKey'))
      throw lazyDOMException(
        'Unable to use this key to wrapKey', 'InvalidAccessError');

    let keyData = exportKeySync(format, key);

    if (format === 'jwk') {
      const ec = new TextEncoder();
      const raw = JSONStringify(keyData);
      // As per the NOTE in step 13 https://w3c.github.io/webcrypto/#SubtleCrypto-method-wrapKey
      // we're padding AES-KW wrapped JWK to make sure it is always a multiple of 8 bytes
      // in length
      if (algorithm.name === 'AES-KW' && raw.length % 8 !== 0) {
        keyData = ec.encode(raw + StringPrototypeRepeat(' ', 8 - (raw.length % 8)));
      } else {
        keyData = ec.encode(raw);
      }
    }

    return cipherOrWrap(
      kWebCryptoCipherEncrypt,
      algorithm,
      wrappingKey,
      keyData,
      'wrapKey');
  } catch (err) {
    return PromiseReject(err);
  }
}

// subtle.unwrapKey() is essentially a subtle.decrypt() followed
// by a subtle.importKey().
function unwrapKey(
  format,
  wrappedKey,
  unwrappingKey,
  unwrapAlgorithm,
  unwrappedKeyAlgorithm,
  extractable,
  keyUsages) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'unwrapKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 7, { prefix });
    format = webidl.converters.KeyFormat(format, {
      prefix,
      context: '1st argument',
    });
    wrappedKey = webidl.converters.BufferSource(wrappedKey, {
      prefix,
      context: '2nd argument',
    });
    unwrappingKey = webidl.converters.CryptoKey(unwrappingKey, {
      prefix,
      context: '3rd argument',
    });
    let algorithm = webidl.converters.AlgorithmIdentifier(unwrapAlgorithm, {
      prefix,
      context: '4th argument',
    });
    unwrappedKeyAlgorithm = webidl.converters.AlgorithmIdentifier(
      unwrappedKeyAlgorithm,
      {
        prefix,
        context: '5th argument',
      },
    );
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '6th argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '7th argument',
    });

    try {
      algorithm = normalizeAlgorithm(algorithm, 'unwrapKey');
    } catch {
      algorithm = normalizeAlgorithm(algorithm, 'decrypt');
    }

    const normalizedKeyAlgorithm = normalizeAlgorithm(unwrappedKeyAlgorithm, 'importKey');

    if (algorithm.name !== getCryptoKeyAlgorithm(unwrappingKey).name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

    if (!hasCryptoKeyUsage(unwrappingKey, 'unwrapKey'))
      throw lazyDOMException(
        'Unable to use this key to unwrapKey', 'InvalidAccessError');

    const keyData = cipherOrWrap(
      kWebCryptoCipherDecrypt,
      algorithm,
      unwrappingKey,
      wrappedKey,
      'unwrapKey');

    return PromisePrototypeThen(keyData, (keyData) => {
      if (format === 'jwk') {
        // The fatal: true option is only supported in builds that have ICU.
        const options = process.versions.icu !== undefined ?
          { fatal: true } : undefined;
        const dec = new TextDecoder('utf-8', options);
        try {
          keyData = JSONParse(dec.decode(keyData));
        } catch {
          throw lazyDOMException('Invalid wrapped JWK key', 'DataError');
        }
      }

      return FunctionPrototypeCall(
        importKeySync,
        this,
        format, keyData, normalizedKeyAlgorithm, extractable, usages,
      );
    });
  } catch (err) {
    return PromiseReject(err);
  }
}

function signVerify(algorithm, key, data, signature) {
  const op = signature !== undefined ? 'verify' : 'sign'; // This is also usage
  algorithm = normalizeAlgorithm(algorithm, op);

  if (algorithm.name !== getCryptoKeyAlgorithm(key).name)
    throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

  if (!hasCryptoKeyUsage(key, op))
    throw lazyDOMException(
      `Unable to use this key to ${op}`, 'InvalidAccessError');

  switch (algorithm.name) {
    case 'RSA-PSS':
      // Fall through
    case 'RSASSA-PKCS1-v1_5':
      return require('internal/crypto/rsa')
        .rsaSignVerify(key, data, algorithm, signature);
    case 'ECDSA':
      return require('internal/crypto/ec')
        .ecdsaSignVerify(key, data, algorithm, signature);
    case 'Ed25519':
      // Fall through
    case 'Ed448':
      // Fall through
      return require('internal/crypto/cfrg')
        .eddsaSignVerify(key, data, algorithm, signature);
    case 'HMAC':
      return require('internal/crypto/mac')
        .hmacSignVerify(key, data, algorithm, signature);
    case 'ML-DSA-44':
      // Fall through
    case 'ML-DSA-65':
      // Fall through
    case 'ML-DSA-87':
      return require('internal/crypto/ml_dsa')
        .mlDsaSignVerify(key, data, algorithm, signature);
    case 'KMAC128':
      // Fall through
    case 'KMAC256':
      return require('internal/crypto/mac')
        .kmacSignVerify(key, data, algorithm, signature);
  }
  throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
}

function sign(algorithm, key, data) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'sign' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 3, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });
    data = webidl.converters.BufferSource(data, {
      prefix,
      context: '3rd argument',
    });

    return signVerify(algorithm, key, data);
  } catch (err) {
    return PromiseReject(err);
  }
}

function verify(algorithm, key, signature, data) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'verify' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 4, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });
    signature = webidl.converters.BufferSource(signature, {
      prefix,
      context: '3rd argument',
    });
    data = webidl.converters.BufferSource(data, {
      prefix,
      context: '4th argument',
    });

    return signVerify(algorithm, key, data, signature);
  } catch (err) {
    return PromiseReject(err);
  }
}

function cipherOrWrap(mode, algorithm, key, data, op) {
  // While WebCrypto allows for larger input buffer sizes, we limit
  // those to sizes that can fit within uint32_t because of limitations
  // in the OpenSSL API.
  validateMaxBufferLength(data, 'data');

  switch (algorithm.name) {
    case 'RSA-OAEP':
      return require('internal/crypto/rsa')
        .rsaCipher(mode, key, data, algorithm);
    case 'AES-CTR':
      // Fall through
    case 'AES-CBC':
      // Fall through
    case 'AES-GCM':
      // Fall through
    case 'AES-OCB':
      return require('internal/crypto/aes')
        .aesCipher(mode, key, data, algorithm);
    case 'ChaCha20-Poly1305':
      return require('internal/crypto/chacha20_poly1305')
        .c20pCipher(mode, key, data, algorithm);
    case 'AES-KW':
      if (op === 'wrapKey' || op === 'unwrapKey') {
        return require('internal/crypto/aes')
          .aesCipher(mode, key, data, algorithm);
      }
  }
  throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
}

function encrypt(algorithm, key, data) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'encrypt' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 3, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });
    data = webidl.converters.BufferSource(data, {
      prefix,
      context: '3rd argument',
    });

    algorithm = normalizeAlgorithm(algorithm, 'encrypt');

    if (algorithm.name !== getCryptoKeyAlgorithm(key).name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

    if (!hasCryptoKeyUsage(key, 'encrypt'))
      throw lazyDOMException(
        'Unable to use this key to encrypt', 'InvalidAccessError');

    return cipherOrWrap(
      kWebCryptoCipherEncrypt,
      algorithm,
      key,
      data,
      'encrypt',
    );
  } catch (err) {
    return PromiseReject(err);
  }
}

function decrypt(algorithm, key, data) {
  try {
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'decrypt' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 3, { prefix });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '1st argument',
    });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '2nd argument',
    });
    data = webidl.converters.BufferSource(data, {
      prefix,
      context: '3rd argument',
    });

    algorithm = normalizeAlgorithm(algorithm, 'decrypt');

    if (algorithm.name !== getCryptoKeyAlgorithm(key).name)
      throw lazyDOMException('Key algorithm mismatch', 'InvalidAccessError');

    if (!hasCryptoKeyUsage(key, 'decrypt'))
      throw lazyDOMException(
        'Unable to use this key to decrypt', 'InvalidAccessError');

    return cipherOrWrap(
      kWebCryptoCipherDecrypt,
      algorithm,
      key,
      data,
      'decrypt',
    );
  } catch (err) {
    return PromiseReject(err);
  }
}

// Implements https://wicg.github.io/webcrypto-modern-algos/#SubtleCrypto-method-getPublicKey
function getPublicKey(key, keyUsages) {
  try {
    emitExperimentalWarning('The getPublicKey Web Crypto API method');
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'getPublicKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });
    key = webidl.converters.CryptoKey(key, {
      prefix,
      context: '1st argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '2nd argument',
    });

    const type = getCryptoKeyType(key);
    if (type !== 'private')
      throw lazyDOMException('key must be a private key',
                             type === 'secret' ? 'NotSupportedError' : 'InvalidAccessError');


    // TODO(panva): this is by no means a hot path, but let's still follow up to get
    //              rid of this awkwardness
    const keyObject = createPublicKey(new PrivateKeyObject(getCryptoKeyHandle(key)));
    return PromiseResolve(keyObject.toCryptoKey(getCryptoKeyAlgorithm(key), true, usages));
  } catch (err) {
    return PromiseReject(err);
  }
}

function encapsulateBits(encapsulationAlgorithm, encapsulationKey) {
  try {
    emitExperimentalWarning('The encapsulateBits Web Crypto API method');
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'encapsulateBits' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });
    encapsulationAlgorithm = webidl.converters.AlgorithmIdentifier(encapsulationAlgorithm, {
      prefix,
      context: '1st argument',
    });
    encapsulationKey = webidl.converters.CryptoKey(encapsulationKey, {
      prefix,
      context: '2nd argument',
    });

    const normalizedEncapsulationAlgorithm = normalizeAlgorithm(encapsulationAlgorithm, 'encapsulate');
    const keyAlgorithm = getCryptoKeyAlgorithm(encapsulationKey);

    if (normalizedEncapsulationAlgorithm.name !== keyAlgorithm.name) {
      throw lazyDOMException(
        'key algorithm mismatch',
        'InvalidAccessError');
    }

    if (!hasCryptoKeyUsage(encapsulationKey, 'encapsulateBits')) {
      throw lazyDOMException(
        'encapsulationKey does not have encapsulateBits usage',
        'InvalidAccessError');
    }

    switch (keyAlgorithm.name) {
      case 'ML-KEM-512':
      case 'ML-KEM-768':
      case 'ML-KEM-1024':
        return require('internal/crypto/ml_kem')
          .mlKemEncapsulate(encapsulationKey);
    }

    throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
  } catch (err) {
    return PromiseReject(err);
  }
}

function encapsulateKey(encapsulationAlgorithm, encapsulationKey, sharedKeyAlgorithm, extractable, keyUsages) {
  try {
    emitExperimentalWarning('The encapsulateKey Web Crypto API method');
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'encapsulateKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 5, { prefix });
    encapsulationAlgorithm = webidl.converters.AlgorithmIdentifier(encapsulationAlgorithm, {
      prefix,
      context: '1st argument',
    });
    encapsulationKey = webidl.converters.CryptoKey(encapsulationKey, {
      prefix,
      context: '2nd argument',
    });
    sharedKeyAlgorithm = webidl.converters.AlgorithmIdentifier(sharedKeyAlgorithm, {
      prefix,
      context: '3rd argument',
    });
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '4th argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '5th argument',
    });

    const normalizedEncapsulationAlgorithm = normalizeAlgorithm(encapsulationAlgorithm, 'encapsulate');
    const normalizedSharedKeyAlgorithm = normalizeAlgorithm(sharedKeyAlgorithm, 'importKey');
    const keyAlgorithm = getCryptoKeyAlgorithm(encapsulationKey);

    if (normalizedEncapsulationAlgorithm.name !== keyAlgorithm.name) {
      throw lazyDOMException(
        'key algorithm mismatch',
        'InvalidAccessError');
    }

    if (!hasCryptoKeyUsage(encapsulationKey, 'encapsulateKey')) {
      throw lazyDOMException(
        'encapsulationKey does not have encapsulateKey usage',
        'InvalidAccessError');
    }

    let encapsulatedBits;
    switch (keyAlgorithm.name) {
      case 'ML-KEM-512':
      case 'ML-KEM-768':
      case 'ML-KEM-1024':
        encapsulatedBits = require('internal/crypto/ml_kem')
          .mlKemEncapsulate(encapsulationKey);
        break;
      default:
        throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
    }

    return PromisePrototypeThen(encapsulatedBits, (encapsulatedBits) => {
      const sharedKey = FunctionPrototypeCall(
        importKeySync,
        this,
        'raw-secret', encapsulatedBits.sharedKey, normalizedSharedKeyAlgorithm, extractable, usages,
      );

      return {
        ciphertext: encapsulatedBits.ciphertext,
        sharedKey,
      };
    });
  } catch (err) {
    return PromiseReject(err);
  }
}

function decapsulateBits(decapsulationAlgorithm, decapsulationKey, ciphertext) {
  try {
    emitExperimentalWarning('The decapsulateBits Web Crypto API method');
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'decapsulateBits' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 3, { prefix });
    decapsulationAlgorithm = webidl.converters.AlgorithmIdentifier(decapsulationAlgorithm, {
      prefix,
      context: '1st argument',
    });
    decapsulationKey = webidl.converters.CryptoKey(decapsulationKey, {
      prefix,
      context: '2nd argument',
    });
    ciphertext = webidl.converters.BufferSource(ciphertext, {
      prefix,
      context: '3rd argument',
    });

    const normalizedDecapsulationAlgorithm = normalizeAlgorithm(decapsulationAlgorithm, 'decapsulate');
    const keyAlgorithm = getCryptoKeyAlgorithm(decapsulationKey);

    if (normalizedDecapsulationAlgorithm.name !== keyAlgorithm.name) {
      throw lazyDOMException(
        'key algorithm mismatch',
        'InvalidAccessError');
    }

    if (!hasCryptoKeyUsage(decapsulationKey, 'decapsulateBits')) {
      throw lazyDOMException(
        'decapsulationKey does not have decapsulateBits usage',
        'InvalidAccessError');
    }

    switch (keyAlgorithm.name) {
      case 'ML-KEM-512':
      case 'ML-KEM-768':
      case 'ML-KEM-1024':
        return require('internal/crypto/ml_kem')
          .mlKemDecapsulate(decapsulationKey, ciphertext);
    }

    throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
  } catch (err) {
    return PromiseReject(err);
  }
}

function decapsulateKey(
  decapsulationAlgorithm, decapsulationKey, ciphertext, sharedKeyAlgorithm, extractable, keyUsages,
) {
  try {
    emitExperimentalWarning('The decapsulateKey Web Crypto API method');
    if (this !== subtle) throw new ERR_INVALID_THIS('SubtleCrypto');

    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'decapsulateKey' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 6, { prefix });
    decapsulationAlgorithm = webidl.converters.AlgorithmIdentifier(decapsulationAlgorithm, {
      prefix,
      context: '1st argument',
    });
    decapsulationKey = webidl.converters.CryptoKey(decapsulationKey, {
      prefix,
      context: '2nd argument',
    });
    ciphertext = webidl.converters.BufferSource(ciphertext, {
      prefix,
      context: '3rd argument',
    });
    sharedKeyAlgorithm = webidl.converters.AlgorithmIdentifier(sharedKeyAlgorithm, {
      prefix,
      context: '4th argument',
    });
    extractable = webidl.converters.boolean(extractable, {
      prefix,
      context: '5th argument',
    });
    const usages = webidl.converters['sequence<KeyUsage>'](keyUsages, {
      prefix,
      context: '6th argument',
    });

    const normalizedDecapsulationAlgorithm = normalizeAlgorithm(decapsulationAlgorithm, 'decapsulate');
    const normalizedSharedKeyAlgorithm = normalizeAlgorithm(sharedKeyAlgorithm, 'importKey');
    const keyAlgorithm = getCryptoKeyAlgorithm(decapsulationKey);

    if (normalizedDecapsulationAlgorithm.name !== keyAlgorithm.name) {
      throw lazyDOMException(
        'key algorithm mismatch',
        'InvalidAccessError');
    }

    if (!hasCryptoKeyUsage(decapsulationKey, 'decapsulateKey')) {
      throw lazyDOMException(
        'decapsulationKey does not have decapsulateKey usage',
        'InvalidAccessError');
    }

    let decapsulatedBits;
    switch (keyAlgorithm.name) {
      case 'ML-KEM-512':
      case 'ML-KEM-768':
      case 'ML-KEM-1024':
        decapsulatedBits = require('internal/crypto/ml_kem')
          .mlKemDecapsulate(decapsulationKey, ciphertext);
        break;
      default:
        throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
    }

    return PromisePrototypeThen(decapsulatedBits, (decapsulatedBits) => FunctionPrototypeCall(
      importKeySync,
      this,
      'raw-secret', decapsulatedBits, normalizedSharedKeyAlgorithm, extractable, usages,
    ));
  } catch (err) {
    return PromiseReject(err);
  }
}

// The SubtleCrypto and Crypto classes are defined as part of the
// Web Crypto API standard: https://www.w3.org/TR/WebCryptoAPI/

class SubtleCrypto {
  constructor() {
    throw new ERR_ILLEGAL_CONSTRUCTOR();
  }

  // Implements https://wicg.github.io/webcrypto-modern-algos/#SubtleCrypto-method-supports
  static supports(operation, algorithm, lengthOrAdditionalAlgorithm = null) {
    emitExperimentalWarning('The supports Web Crypto API method');
    if (this !== SubtleCrypto) throw new ERR_INVALID_THIS('SubtleCrypto constructor');
    webidl ??= require('internal/crypto/webidl');
    const prefix = "Failed to execute 'supports' on 'SubtleCrypto'";
    webidl.requiredArguments(arguments.length, 2, { prefix });

    operation = webidl.converters.DOMString(operation, {
      prefix,
      context: '1st argument',
    });
    algorithm = webidl.converters.AlgorithmIdentifier(algorithm, {
      prefix,
      context: '2nd argument',
    });

    switch (operation) {
      case 'decapsulateBits':
      case 'decapsulateKey':
      case 'decrypt':
      case 'deriveBits':
      case 'deriveKey':
      case 'digest':
      case 'encapsulateBits':
      case 'encapsulateKey':
      case 'encrypt':
      case 'exportKey':
      case 'generateKey':
      case 'getPublicKey':
      case 'importKey':
      case 'sign':
      case 'unwrapKey':
      case 'verify':
      case 'wrapKey':
        break;
      default:
        return false;
    }

    let length;
    let additionalAlgorithm;
    if (operation === 'deriveKey') {
      additionalAlgorithm = webidl.converters.AlgorithmIdentifier(lengthOrAdditionalAlgorithm, {
        prefix,
        context: '3rd argument',
      });

      if (!check('importKey', additionalAlgorithm)) {
        return false;
      }

      try {
        length = getKeyLength(normalizeAlgorithm(additionalAlgorithm, 'get key length'));
      } catch {
        return false;
      }

      operation = 'deriveBits';
    } else if (operation === 'wrapKey') {
      additionalAlgorithm = webidl.converters.AlgorithmIdentifier(lengthOrAdditionalAlgorithm, {
        prefix,
        context: '3rd argument',
      });

      if (!check('exportKey', additionalAlgorithm)) {
        return false;
      }
    } else if (operation === 'unwrapKey') {
      additionalAlgorithm = webidl.converters.AlgorithmIdentifier(lengthOrAdditionalAlgorithm, {
        prefix,
        context: '3rd argument',
      });

      if (!check('importKey', additionalAlgorithm)) {
        return false;
      }
    } else if (operation === 'deriveBits') {
      length = lengthOrAdditionalAlgorithm;
      if (length !== null) {
        length = webidl.converters['unsigned long'](length, {
          prefix,
          context: '3rd argument',
        });
      }
    } else if (operation === 'getPublicKey') {
      let normalizedAlgorithm;
      try {
        normalizedAlgorithm = normalizeAlgorithm(algorithm, 'exportKey');
      } catch {
        return false;
      }

      switch (StringPrototypeSlice(normalizedAlgorithm.name, 0, 2)) {
        case 'ML': // ML-DSA-*, ML-KEM-*
        case 'SL': // SLH-DSA-*
        case 'RS': // RSA-OAEP, RSA-PSS, RSASSA-PKCS1-v1_5
        case 'EC': // ECDSA, ECDH
        case 'Ed': // Ed*
        case 'X2': // X25519
        case 'X4': // X448
          return true;
        default:
          return false;
      }
    } else if (operation === 'encapsulateKey' || operation === 'decapsulateKey') {
      additionalAlgorithm = webidl.converters.AlgorithmIdentifier(lengthOrAdditionalAlgorithm, {
        prefix,
        context: '3rd argument',
      });

      let normalizedAdditionalAlgorithm;
      try {
        normalizedAdditionalAlgorithm = normalizeAlgorithm(additionalAlgorithm, 'importKey');
      } catch {
        return false;
      }

      switch (normalizedAdditionalAlgorithm.name) {
        case 'AES-OCB':
        case 'AES-KW':
        case 'AES-GCM':
        case 'AES-CTR':
        case 'AES-CBC':
        case 'ChaCha20-Poly1305':
        case 'HKDF':
        case 'PBKDF2':
        case 'Argon2i':
        case 'Argon2d':
        case 'Argon2id':
          break;
        case 'HMAC':
        case 'KMAC128':
        case 'KMAC256':
          if (normalizedAdditionalAlgorithm.length === undefined || normalizedAdditionalAlgorithm.length === 256) {
            break;
          }
          return false;
        default:
          return false;
      }
    }

    try {
      return check(operation, algorithm, length);
    } catch {
      return false;
    }
  }
}

function check(op, alg, length) {
  if (op === 'encapsulateBits' || op === 'encapsulateKey') {
    op = 'encapsulate';
  }

  if (op === 'decapsulateBits' || op === 'decapsulateKey') {
    op = 'decapsulate';
  }

  let normalizedAlgorithm;
  try {
    normalizedAlgorithm = normalizeAlgorithm(alg, op);
  } catch {
    if (op === 'wrapKey') {
      return check('encrypt', alg);
    }

    if (op === 'unwrapKey') {
      return check('decrypt', alg);
    }

    return false;
  }

  switch (op) {
    case 'decapsulate':
    case 'decrypt':
    case 'digest':
    case 'encapsulate':
    case 'encrypt':
    case 'exportKey':
    case 'importKey':
    case 'sign':
    case 'unwrapKey':
    case 'verify':
    case 'wrapKey':
      return true;
    case 'deriveBits': {
      if (normalizedAlgorithm.name === 'HKDF') {
        require('internal/crypto/hkdf').validateHkdfDeriveBitsLength(length);
      }

      if (normalizedAlgorithm.name === 'PBKDF2') {
        require('internal/crypto/pbkdf2').validatePbkdf2DeriveBitsLength(length);
      }

      if (StringPrototypeStartsWith(normalizedAlgorithm.name, 'Argon2')) {
        require('internal/crypto/argon2').validateArgon2DeriveBitsLength(length);
      }

      if (normalizedAlgorithm.name === 'X25519' && length > 256) {
        return false;
      }

      if (normalizedAlgorithm.name === 'X448' && length > 448) {
        return false;
      }

      if (normalizedAlgorithm.name === 'ECDH') {
        const namedCurve = getCryptoKeyAlgorithm(normalizedAlgorithm.public).namedCurve;
        const maxLength = {
          '__proto__': null,
          'P-256': 256,
          'P-384': 384,
          'P-521': 528,
        }[namedCurve];

        if (length > maxLength) {
          return false;
        }
      }

      return true;
    }
    case 'generateKey': {
      if (
        normalizedAlgorithm.name === 'HMAC' &&
        normalizedAlgorithm.length === undefined &&
        StringPrototypeStartsWith(normalizedAlgorithm.hash.name, 'SHA3-')
      ) {
        return false;
      }

      return true;
    }
    default: {
      const assert = require('internal/assert');
      assert.fail('Unreachable code');
    }
  }
}

const subtle = ReflectConstruct(function() {}, [], SubtleCrypto);

class Crypto {
  constructor() {
    throw new ERR_ILLEGAL_CONSTRUCTOR();
  }

  get subtle() {
    if (this !== crypto) throw new ERR_INVALID_THIS('Crypto');
    return subtle;
  }
}
const crypto = ReflectConstruct(function() {}, [], Crypto);

function getRandomValues(array) {
  if (this !== crypto) throw new ERR_INVALID_THIS('Crypto');

  webidl ??= require('internal/crypto/webidl');
  const prefix = "Failed to execute 'getRandomValues' on 'Crypto'";
  webidl.requiredArguments(arguments.length, 1, { prefix });

  return ReflectApply(_getRandomValues, this, arguments);
}

ObjectDefineProperties(
  Crypto.prototype, {
    [SymbolToStringTag]: {
      __proto__: null,
      enumerable: false,
      configurable: true,
      writable: false,
      value: 'Crypto',
    },
    subtle: kEnumerableProperty,
    getRandomValues: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: getRandomValues,
    },
    randomUUID: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: randomUUID,
    },
  });

ObjectDefineProperties(
  SubtleCrypto.prototype, {
    [SymbolToStringTag]: {
      __proto__: null,
      enumerable: false,
      configurable: true,
      writable: false,
      value: 'SubtleCrypto',
    },
    encrypt: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: encrypt,
    },
    decrypt: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: decrypt,
    },
    sign: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: sign,
    },
    verify: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: verify,
    },
    digest: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: digest,
    },
    generateKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: generateKey,
    },
    deriveKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: deriveKey,
    },
    deriveBits: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: deriveBits,
    },
    importKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: importKey,
    },
    exportKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: exportKey,
    },
    wrapKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: wrapKey,
    },
    unwrapKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: unwrapKey,
    },
    getPublicKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: getPublicKey,
    },
    encapsulateBits: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: encapsulateBits,
    },
    encapsulateKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: encapsulateKey,
    },
    decapsulateBits: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: decapsulateBits,
    },
    decapsulateKey: {
      __proto__: null,
      enumerable: true,
      configurable: true,
      writable: true,
      value: decapsulateKey,
    },
  });

ObjectDefineProperties(SubtleCrypto, {
  supports: kEnumerableProperty,
});

module.exports = {
  Crypto,
  CryptoKey,
  SubtleCrypto,
  crypto,
};
