'use strict';

const {
  ArrayFrom,
  MathCeil,
  SafeSet,
  Uint8Array,
} = primordials;

const {
  HmacJob,
  KeyObjectHandle,
  kCryptoJobAsync,
  kSignJobModeSign,
  kSignJobModeVerify,
} = internalBinding('crypto');

const {
  getBlockSize,
  hasAnyNotIn,
  jobPromise,
  normalizeHashName,
  validateKeyOps,
  kHandle,
  kKeyObject,
  truncateToBitLength,
} = require('internal/crypto/util');

const {
  randomFill: _randomFill,
} = require('internal/crypto/random');

const {
  lazyDOMException,
  promisify,
} = require('internal/util');

const {
  InternalCryptoKey,
  createSecretKey,
} = require('internal/crypto/keys');

const randomFill = promisify(_randomFill);

function validateHmacGenerateKeyAlgorithm(algorithm) {
  if (algorithm.length !== undefined) {
    if (algorithm.length === 0)
      throw lazyDOMException(
        'Zero-length key is not supported',
        'OperationError');
  }
}

async function hmacGenerateKey(algorithm, extractable, keyUsages) {
  validateHmacGenerateKeyAlgorithm(algorithm);
  const { hash, name } = algorithm;
  let { length } = algorithm;

  if (length === undefined)
    length = getBlockSize(hash.name);

  const usageSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(usageSet, ['sign', 'verify'])) {
    throw lazyDOMException(
      'Unsupported key usage for an HMAC key',
      'SyntaxError');
  }

  const keyData = await randomFill(new Uint8Array(MathCeil(length / 8))).catch((err) => {
    throw lazyDOMException(
      'The operation failed for an operation-specific reason',
      { name: 'OperationError', cause: err });
  });

  const keyObject = createSecretKey(truncateToBitLength(length, keyData));

  return new InternalCryptoKey(
    keyObject,
    { name, length, hash: { name: hash.name } },
    ArrayFrom(usageSet),
    extractable);
}

function getAlgorithmName(hash) {
  switch (hash) {
    case 'SHA-1': // Fall through
    case 'SHA-256': // Fall through
    case 'SHA-384': // Fall through
    case 'SHA-512': // Fall through
      return `HS${hash.slice(4)}`;
    default:
      throw lazyDOMException('Unsupported digest algorithm', 'DataError');
  }
}

function validateHmacImportKeyAlgorithm(algorithm) {
  if (algorithm.length !== undefined) {
    if (algorithm.length === 0) {
      throw lazyDOMException('Zero-length key is not supported', 'DataError');
    }

    // The Web Crypto spec allows for key lengths that are not multiples of 8. We don't.
    if (algorithm.length % 8) {
      throw lazyDOMException('Unsupported algorithm.length', 'NotSupportedError');
    }
  }
}

function hmacImportKey(
  format,
  keyData,
  algorithm,
  extractable,
  keyUsages,
) {
  validateHmacImportKeyAlgorithm(algorithm);
  const usagesSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(usagesSet, ['sign', 'verify'])) {
    throw lazyDOMException(
      'Unsupported key usage for an HMAC key',
      'SyntaxError');
  }
  switch (format) {
    case 'KeyObject': {
      keyData = keyData[kHandle].export();
      break;
    }
    case 'raw': {
      keyData = new Uint8Array(keyData);
      break;
    }
    case 'jwk': {
      if (!keyData.kty)
        throw lazyDOMException('Invalid keyData', 'DataError');

      if (keyData.kty !== 'oct')
        throw lazyDOMException('Invalid JWK "kty" Parameter', 'DataError');

      if (usagesSet.size > 0 &&
          keyData.use !== undefined &&
          keyData.use !== 'sig') {
        throw lazyDOMException('Invalid JWK "use" Parameter', 'DataError');
      }

      validateKeyOps(keyData.key_ops, usagesSet);

      if (keyData.ext !== undefined &&
          keyData.ext === false &&
          extractable === true) {
        throw lazyDOMException(
          'JWK "ext" Parameter and extractable mismatch',
          'DataError');
      }

      if (keyData.alg !== undefined) {
        if (keyData.alg !== getAlgorithmName(algorithm.hash.name))
          throw lazyDOMException(
            'JWK "alg" does not match the requested algorithm',
            'DataError');
      }

      const handle = new KeyObjectHandle();
      try {
        handle.initJwk(keyData);
      } catch (err) {
        throw lazyDOMException(
          'Invalid keyData', { name: 'DataError', cause: err });
      }
      keyData = handle.export();
      break;
    }
    default:
      throw lazyDOMException(`Unable to import HMAC key with format ${format}`);
  }

  if (keyData.byteLength === 0)
    throw lazyDOMException('Zero-length key is not supported', 'DataError');

  if (algorithm.length !== undefined) {
    if (MathCeil(algorithm.length / 8) !== keyData.byteLength) {
      throw lazyDOMException('Invalid key length', 'DataError');
    }

    keyData = truncateToBitLength(algorithm.length, keyData);
  }

  const keyObject = createSecretKey(keyData);

  return new InternalCryptoKey(
    keyObject, {
      name: 'HMAC',
      hash: algorithm.hash,
      length: algorithm.length || keyData.byteLength * 8,
    },
    keyUsages,
    extractable);
}

function hmacSignVerify(key, data, algorithm, signature) {
  const mode = signature === undefined ? kSignJobModeSign : kSignJobModeVerify;
  return jobPromise(() => new HmacJob(
    kCryptoJobAsync,
    mode,
    normalizeHashName(key.algorithm.hash.name),
    key[kKeyObject][kHandle],
    data,
    signature));
}

module.exports = {
  hmacImportKey,
  hmacGenerateKey,
  hmacSignVerify,
};
