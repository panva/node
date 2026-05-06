'use strict';

const {
  FunctionPrototypeCall,
  ObjectSetPrototypeOf,
  StringPrototypeReplace,
  StringPrototypeToLowerCase,
  Symbol,
} = primordials;

const {
  Hash: _Hash,
  HashJob,
  Hmac: _Hmac,
  Kmac: _Kmac,
  kCryptoJobAsync,
  oneShotDigest,
  TurboShakeJob,
  KangarooTwelveJob,
} = internalBinding('crypto');

const {
  getArrayBufferOrView,
  getStringOption,
  jobPromise,
  normalizeHashName,
  validateMaxBufferLength,
  kHandle,
  getCachedHashId,
  getHashCache,
} = require('internal/crypto/util');

const {
  isKeyObject,
  prepareSecretKey,
} = require('internal/crypto/keys');

const {
  lazyDOMException,
  normalizeEncoding,
  encodingsMap,
  getDeprecationWarningEmitter,
} = require('internal/util');

const {
  Buffer,
} = require('buffer');

const {
  codes: {
    ERR_CRYPTO_HASH_FINALIZED,
    ERR_CRYPTO_HASH_UPDATE_FAILED,
    ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE,
    ERR_CRYPTO_KMAC_NOT_SUPPORTED,
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
  },
} = require('internal/errors');

const {
  validateEncoding,
  validateInteger,
  validateOneOf,
  validateString,
  validateObject,
  validateUint32,
} = require('internal/validators');

const {
  isAnyArrayBuffer,
  isArrayBufferView,
} = require('internal/util/types');

const LazyTransform = require('internal/streams/lazy_transform');

const kState = Symbol('kState');
const kFinalized = Symbol('kFinalized');

/**
 * @param {string} name
 * @returns {string}
 */
function normalizeAlgorithm(name) {
  return StringPrototypeReplace(StringPrototypeToLowerCase(name), '-', '');
}

const maybeEmitDeprecationWarning = getDeprecationWarningEmitter(
  'DEP0198',
  'Creating SHAKE128/256 digests without an explicit options.outputLength is deprecated.',
  undefined,
  false,
  (algorithm) => {
    const normalized = normalizeAlgorithm(algorithm);
    return normalized === 'shake128' || normalized === 'shake256';
  },
);

function Hash(algorithm, options) {
  if (!new.target)
    return new Hash(algorithm, options);
  const isCopy = algorithm instanceof _Hash;
  if (!isCopy)
    validateString(algorithm, 'algorithm');
  const xofLen = typeof options === 'object' && options !== null ?
    options.outputLength : undefined;
  if (xofLen !== undefined)
    validateUint32(xofLen, 'options.outputLength');
  // Lookup the cached ID from JS land because it's faster than decoding
  // the string in C++ land.
  const algorithmId = isCopy ? -1 : getCachedHashId(algorithm);
  this[kHandle] = new _Hash(algorithm, xofLen, algorithmId, getHashCache());
  this[kState] = {
    [kFinalized]: false,
  };
  if (!isCopy && xofLen === undefined) {
    maybeEmitDeprecationWarning(algorithm);
  }
  FunctionPrototypeCall(LazyTransform, this, options);
}

ObjectSetPrototypeOf(Hash.prototype, LazyTransform.prototype);
ObjectSetPrototypeOf(Hash, LazyTransform);

Hash.prototype.copy = function copy(options) {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  return new Hash(this[kHandle], options);
};

Hash.prototype._transform = function _transform(chunk, encoding, callback) {
  this[kHandle].update(chunk, encoding);
  callback();
};

Hash.prototype._flush = function _flush(callback) {
  this.push(this[kHandle].digest());
  callback();
};

Hash.prototype.update = function update(data, encoding) {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  if (typeof data === 'string') {
    validateEncoding(data, encoding);
  } else if (!isArrayBufferView(data)) {
    throw new ERR_INVALID_ARG_TYPE(
      'data', ['string', 'Buffer', 'TypedArray', 'DataView'], data);
  }

  if (!this[kHandle].update(data, encoding))
    throw new ERR_CRYPTO_HASH_UPDATE_FAILED();
  return this;
};


Hash.prototype.digest = function digest(outputEncoding) {
  const state = this[kState];
  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  // Explicit conversion of truthy values for backward compatibility.
  const ret = this[kHandle].digest(outputEncoding && `${outputEncoding}`);
  state[kFinalized] = true;
  return ret;
};

function Hmac(hmac, key, options) {
  if (!(this instanceof Hmac))
    return new Hmac(hmac, key, options);
  validateString(hmac, 'hmac');
  const encoding = getStringOption(options, 'encoding');
  key = prepareSecretKey(key, encoding);
  this[kHandle] = new _Hmac();
  this[kHandle].init(hmac, key);
  this[kState] = {
    [kFinalized]: false,
  };
  FunctionPrototypeCall(LazyTransform, this, options);
}

ObjectSetPrototypeOf(Hmac.prototype, LazyTransform.prototype);
ObjectSetPrototypeOf(Hmac, LazyTransform);

Hmac.prototype.update = Hash.prototype.update;

Hmac.prototype.digest = function digest(outputEncoding) {
  const state = this[kState];

  if (state[kFinalized]) {
    const buf = Buffer.from('');
    if (outputEncoding && outputEncoding !== 'buffer')
      return buf.toString(outputEncoding);
    return buf;
  }

  // Explicit conversion of truthy values for backward compatibility.
  const ret = this[kHandle].digest(outputEncoding && `${outputEncoding}`);
  state[kFinalized] = true;
  return ret;
};

Hmac.prototype._flush = Hash.prototype._flush;
Hmac.prototype._transform = Hash.prototype._transform;

function isBufferSource(value) {
  return isArrayBufferView(value) || isAnyArrayBuffer(value);
}

function validateKmacKeyLength(byteLength, name) {
  validateInteger(byteLength, name, 4, 512);
}

function prepareKmacKey(key) {
  if (isKeyObject(key)) {
    if (key.type !== 'secret')
      throw new ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE(key.type, 'secret');
    validateKmacKeyLength(key.symmetricKeySize, 'key.symmetricKeySize');
    return key[kHandle];
  }

  if (!isBufferSource(key)) {
    throw new ERR_INVALID_ARG_TYPE(
      'key',
      ['ArrayBuffer', 'Buffer', 'TypedArray', 'DataView', 'KeyObject'],
      key);
  }

  validateKmacKeyLength(key.byteLength, 'key.byteLength');
  return getArrayBufferOrView(key, 'key');
}

function getKmacAlgorithmName(algorithm) {
  validateString(algorithm, 'algorithm');
  validateOneOf(algorithm, 'algorithm', ['kmac-128', 'kmac-256']);
  return algorithm === 'kmac-128' ? 'KMAC128' : 'KMAC256';
}

function getKmacOptions(options) {
  if (options === undefined)
    return { custom: undefined, outputLength: undefined };

  validateObject(options, 'options');

  const { custom, outputLength } = options;
  if (outputLength !== undefined)
    validateUint32(outputLength, 'options.outputLength');

  if (custom !== undefined) {
    if (!isBufferSource(custom)) {
      throw new ERR_INVALID_ARG_TYPE(
        'options.custom',
        ['ArrayBuffer', 'Buffer', 'TypedArray', 'DataView'],
        custom);
    }
    validateInteger(custom.byteLength, 'options.custom.byteLength', 0, 512);
  }

  return { custom, outputLength };
}

function Kmac(algorithm, key, options) {
  if (!(this instanceof Kmac))
    return new Kmac(algorithm, key, options);
  if (_Kmac === undefined)
    throw new ERR_CRYPTO_KMAC_NOT_SUPPORTED();
  const kmac = getKmacAlgorithmName(algorithm);
  key = prepareKmacKey(key);
  const { custom, outputLength } = getKmacOptions(options);
  this[kHandle] = new _Kmac();
  this[kHandle].init(kmac, key, outputLength, custom);
  this[kState] = {
    [kFinalized]: false,
  };
  FunctionPrototypeCall(LazyTransform, this, options);
}

ObjectSetPrototypeOf(Kmac.prototype, LazyTransform.prototype);
ObjectSetPrototypeOf(Kmac, LazyTransform);

Kmac.prototype.update = Hash.prototype.update;

Kmac.prototype.digest = function digest(outputEncoding) {
  const state = this[kState];

  if (state[kFinalized])
    throw new ERR_CRYPTO_HASH_FINALIZED();

  // Explicit conversion of truthy values for compatibility with Hash/Hmac.
  const ret = this[kHandle].digest(outputEncoding && `${outputEncoding}`);
  state[kFinalized] = true;
  return ret;
};

Kmac.prototype._flush = function _flush(callback) {
  this.push(this.digest());
  callback();
};

Kmac.prototype._transform = Hash.prototype._transform;

// Implementation for WebCrypto subtle.digest()

async function asyncDigest(algorithm, data) {
  validateMaxBufferLength(data, 'data');

  switch (algorithm.name) {
    case 'SHA-1':
      // Fall through
    case 'SHA-256':
      // Fall through
    case 'SHA-384':
      // Fall through
    case 'SHA-512':
      // Fall through
    case 'SHA3-256':
      // Fall through
    case 'SHA3-384':
      // Fall through
    case 'SHA3-512':
      // Fall through
    case 'cSHAKE128':
      // Fall through
    case 'cSHAKE256':
      return await jobPromise(() => new HashJob(
        kCryptoJobAsync,
        normalizeHashName(algorithm.name),
        data,
        algorithm.outputLength));
    case 'TurboSHAKE128':
      // Fall through
    case 'TurboSHAKE256':
      return await jobPromise(() => new TurboShakeJob(
        kCryptoJobAsync,
        algorithm.name,
        algorithm.domainSeparation ?? 0x1f,
        algorithm.outputLength / 8,
        data));
    case 'KT128':
      // Fall through
    case 'KT256':
      return await jobPromise(() => new KangarooTwelveJob(
        kCryptoJobAsync,
        algorithm.name,
        algorithm.customization,
        algorithm.outputLength / 8,
        data));
  }

  throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
}

function hash(algorithm, input, options) {
  validateString(algorithm, 'algorithm');
  if (typeof input !== 'string' && !isArrayBufferView(input)) {
    throw new ERR_INVALID_ARG_TYPE('input', ['Buffer', 'TypedArray', 'DataView', 'string'], input);
  }
  let outputEncoding;
  let outputLength;

  if (typeof options === 'string') {
    outputEncoding = options;
  } else if (options !== undefined) {
    validateObject(options, 'options');
    outputLength = options.outputLength;
    outputEncoding = options.outputEncoding;
  }

  outputEncoding ??= 'hex';

  let normalized = outputEncoding;
  // Fast case: if it's 'hex', we don't need to validate it further.
  if (normalized !== 'hex') {
    validateString(outputEncoding, 'outputEncoding');
    normalized = normalizeEncoding(outputEncoding);
    // If the encoding is invalid, normalizeEncoding() returns undefined.
    if (normalized === undefined) {
      // normalizeEncoding() doesn't handle 'buffer'.
      if (StringPrototypeToLowerCase(outputEncoding) === 'buffer') {
        normalized = 'buffer';
      } else {
        throw new ERR_INVALID_ARG_VALUE('outputEncoding', outputEncoding);
      }
    }
  }

  if (outputLength !== undefined) {
    validateUint32(outputLength, 'outputLength');
  }

  if (outputLength === undefined) {
    maybeEmitDeprecationWarning(algorithm);
  }

  return oneShotDigest(algorithm, getCachedHashId(algorithm), getHashCache(),
                       input, normalized, encodingsMap[normalized], outputLength);
}

module.exports = {
  Hash,
  Hmac,
  Kmac,
  asyncDigest,
  hash,
};
