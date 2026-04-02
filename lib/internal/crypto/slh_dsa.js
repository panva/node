'use strict';

const {
  SafeSet,
  StringPrototypeToLowerCase,
  TypedArrayPrototypeGetBuffer,
} = primordials;

const {
  SignJob,
  kCryptoJobAsync,
  kKeyFormatDER,
  kKeyFormatRawPrivate,
  kKeyFormatRawPublic,
  kSignJobModeSign,
  kSignJobModeVerify,
  kWebCryptoKeyFormatRaw,
  kWebCryptoKeyFormatPKCS8,
  kWebCryptoKeyFormatSPKI,
} = internalBinding('crypto');

const {
  getUsagesUnion,
  hasAnyNotIn,
  jobPromise,
  kHandle,
  kKeyObject,
} = require('internal/crypto/util');

const {
  lazyDOMException,
  promisify,
} = require('internal/util');

const {
  generateKeyPair: _generateKeyPair,
} = require('internal/crypto/keygen');

const {
  InternalCryptoKey,
  kKeyType,
} = require('internal/crypto/keys');

const {
  importDerKey,
  importJwkKey,
  importRawKey,
  validateJwk,
} = require('internal/crypto/webcrypto_util');

const generateKeyPair = promisify(_generateKeyPair);

function verifyAcceptableSlhDsaKeyUse(name, isPublic, usages) {
  const checkSet = isPublic ? ['verify'] : ['sign'];
  if (hasAnyNotIn(usages, checkSet)) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError');
  }
}

async function slhDsaGenerateKey(algorithm, extractable, keyUsages) {
  const { name } = algorithm;

  const usageSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(usageSet, ['sign', 'verify'])) {
    throw lazyDOMException(
      `Unsupported key usage for an ${name} key`,
      'SyntaxError');
  }

  let keyPair;
  try {
    keyPair = await generateKeyPair(name.toLowerCase());
  } catch (err) {
    throw lazyDOMException(
      'The operation failed for an operation-specific reason',
      { name: 'OperationError', cause: err });
  }

  const publicUsages = getUsagesUnion(usageSet, 'verify');
  const privateUsages = getUsagesUnion(usageSet, 'sign');

  const keyAlgorithm = { name };

  const publicKey =
    new InternalCryptoKey(
      keyPair.publicKey,
      keyAlgorithm,
      publicUsages,
      true);

  const privateKey =
    new InternalCryptoKey(
      keyPair.privateKey,
      keyAlgorithm,
      privateUsages,
      extractable);

  return { __proto__: null, privateKey, publicKey };
}

function slhDsaExportKey(key, format) {
  try {
    switch (format) {
      case kWebCryptoKeyFormatRaw: {
        const handle = key[kKeyObject][kHandle];
        return TypedArrayPrototypeGetBuffer(
          key[kKeyType] === 'private' ? handle.rawPrivateKey() : handle.rawPublicKey());
      }
      case kWebCryptoKeyFormatSPKI: {
        return TypedArrayPrototypeGetBuffer(key[kKeyObject][kHandle].export(kKeyFormatDER, kWebCryptoKeyFormatSPKI));
      }
      case kWebCryptoKeyFormatPKCS8: {
        return TypedArrayPrototypeGetBuffer(
          key[kKeyObject][kHandle].export(kKeyFormatDER, kWebCryptoKeyFormatPKCS8, null, null));
      }
      default:
        return undefined;
    }
  } catch (err) {
    throw lazyDOMException(
      'The operation failed for an operation-specific reason',
      { name: 'OperationError', cause: err });
  }
}

function slhDsaImportKey(
  format,
  keyData,
  algorithm,
  extractable,
  keyUsages) {

  const { name } = algorithm;
  let keyObject;
  const usagesSet = new SafeSet(keyUsages);
  switch (format) {
    case 'KeyObject': {
      verifyAcceptableSlhDsaKeyUse(name, keyData.type === 'public', usagesSet);
      keyObject = keyData;
      break;
    }
    case 'spki': {
      verifyAcceptableSlhDsaKeyUse(name, true, usagesSet);
      keyObject = importDerKey(keyData, true);
      break;
    }
    case 'pkcs8': {
      verifyAcceptableSlhDsaKeyUse(name, false, usagesSet);
      keyObject = importDerKey(keyData, false);
      break;
    }
    case 'jwk': {
      validateJwk(keyData, 'AKP', extractable, usagesSet, 'sig');

      if (keyData.alg !== name)
        throw lazyDOMException(
          'JWK "alg" Parameter and algorithm name mismatch', 'DataError');

      const isPublic = keyData.priv === undefined;
      verifyAcceptableSlhDsaKeyUse(name, isPublic, usagesSet);
      keyObject = importJwkKey(isPublic, keyData);
      break;
    }
    case 'raw-public':
    case 'raw-private': {
      const isPublic = format === 'raw-public';
      verifyAcceptableSlhDsaKeyUse(name, isPublic, usagesSet);
      keyObject = importRawKey(isPublic, keyData, isPublic ? kKeyFormatRawPublic : kKeyFormatRawPrivate, name);
      break;
    }
    default:
      return undefined;
  }

  if (keyObject.asymmetricKeyType !== StringPrototypeToLowerCase(name)) {
    throw lazyDOMException('Invalid key type', 'DataError');
  }

  return new InternalCryptoKey(
    keyObject,
    { name },
    keyUsages,
    extractable);
}

async function slhDsaSignVerify(key, data, algorithm, signature) {
  const mode = signature === undefined ? kSignJobModeSign : kSignJobModeVerify;
  const type = mode === kSignJobModeSign ? 'private' : 'public';

  if (key[kKeyType] !== type)
    throw lazyDOMException(`Key must be a ${type} key`, 'InvalidAccessError');

  return await jobPromise(() => new SignJob(
    kCryptoJobAsync,
    mode,
    key[kKeyObject][kHandle],
    undefined,
    undefined,
    undefined,
    undefined,
    data,
    undefined,
    undefined,
    undefined,
    undefined,
    algorithm.context,
    signature));
}

module.exports = {
  slhDsaExportKey,
  slhDsaGenerateKey,
  slhDsaImportKey,
  slhDsaSignVerify,
};
