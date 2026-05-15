'use strict';

const {
  ArrayBufferPrototypeSlice,
  ArrayPrototypeSlice,
  SafeSet,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
} = primordials;

const { Buffer } = require('buffer');

const {
  getCryptoKeyExtractable,
  getCryptoKeyData,
  getCryptoKeyHandle,
  getCryptoKeySecondaryHandle,
  getCryptoKeyType,
  getCryptoKeyUsages,
  InternalCryptoKey,
} = require('internal/crypto/keys');

const {
  KeyObjectHandle,
  kKeyFormatRawPrivate,
  kKeyFormatRawPublic,
  kKeyFormatRawSeed,
  kKeyTypePrivate,
  kKeyTypePublic,
} = internalBinding('crypto');

const {
  getUsagesMask,
  getUsagesUnion,
  hasAnyNotIn,
} = require('internal/crypto/util');

const {
  lazyDOMException,
} = require('internal/util');

const {
  hash,
} = require('internal/crypto/hash');

const {
  randomBytes,
} = require('internal/crypto/random');

const {
  ecdhDeriveBits,
} = require('internal/crypto/diffiehellman');

const {
  mlKemDecapsulate,
  mlKemEncapsulate,
} = require('internal/crypto/ml_kem');

const {
  validateJwk,
} = require('internal/crypto/webcrypto_util');

const kName = 'MLKEM768-X25519';
const kMlKemName = 'ML-KEM-768';
const kX25519Name = 'X25519';
const kSeedLength = 32;
const kMlKemSeedLength = 64;
const kMlKemPublicKeyLength = 1184;
const kX25519KeyLength = 32;
const kPublicKeyLength = kMlKemPublicKeyLength + kX25519KeyLength;
const kMlKemCiphertextLength = 1088;
const kCiphertextLength = kMlKemCiphertextLength + kX25519KeyLength;
const kLabel = Buffer.from('5c2e2f2f5e5c', 'hex');

const kMlKemAlgorithm = { name: kMlKemName };
const kX25519Algorithm = { name: kX25519Name };
const kMlKemPublicUsagesMask =
  getUsagesMask(new SafeSet(['encapsulateBits']));
const kMlKemPrivateUsagesMask =
  getUsagesMask(new SafeSet(['decapsulateBits']));
const kX25519PrivateUsagesMask = getUsagesMask(new SafeSet(['deriveBits']));

function operationFailure(cause) {
  return lazyDOMException(
    'The operation failed for an operation-specific reason',
    { name: 'OperationError', cause });
}

function dataFailure(cause) {
  return lazyDOMException('Invalid keyData', { name: 'DataError', cause });
}

function bufferFromKeyData(keyData) {
  return Buffer.from(keyData);
}

function toArrayBuffer(data) {
  const offset = TypedArrayPrototypeGetByteOffset(data);
  return ArrayBufferPrototypeSlice(
    TypedArrayPrototypeGetBuffer(data),
    offset,
    offset + TypedArrayPrototypeGetByteLength(data));
}

function validateLength(data, length) {
  if (data.byteLength !== length) {
    throw lazyDOMException('Invalid keyData', 'DataError');
  }
}

function verifyAcceptableKeyUse(name, isPublic, usages) {
  const checkSet = isPublic ?
    ['encapsulateKey', 'encapsulateBits'] :
    ['decapsulateKey', 'decapsulateBits'];
  if (hasAnyNotIn(usages, checkSet)) {
    throw lazyDOMException(
      `Unsupported key usage for a ${name} key`,
      'SyntaxError');
  }
}

function splitPublicKey(rawPublic) {
  return {
    mlKem: Buffer.from(
      rawPublic.subarray(0, kMlKemPublicKeyLength)),
    x25519: Buffer.from(
      rawPublic.subarray(kMlKemPublicKeyLength, kPublicKeyLength)),
  };
}

function importRawKeyHandle(keyType, keyData, format, asymmetricKeyType) {
  const handle = new KeyObjectHandle();
  handle.init(keyType, keyData, format, asymmetricKeyType, null, null);
  return handle;
}

function importMlKemPrivateHandle(seed) {
  return importRawKeyHandle(
    kKeyTypePrivate,
    seed,
    kKeyFormatRawSeed,
    kMlKemName);
}

function importMlKemPublicHandle(rawPublic) {
  return importRawKeyHandle(
    kKeyTypePublic,
    rawPublic,
    kKeyFormatRawPublic,
    kMlKemName);
}

function importX25519PrivateHandle(seed) {
  return importRawKeyHandle(
    kKeyTypePrivate,
    seed,
    kKeyFormatRawPrivate,
    kX25519Name);
}

function importX25519PublicHandle(rawPublic) {
  return importRawKeyHandle(
    kKeyTypePublic,
    rawPublic,
    kKeyFormatRawPublic,
    kX25519Name);
}

function createMlKemCryptoKey(handle, type) {
  return new InternalCryptoKey(
    handle,
    kMlKemAlgorithm,
    type === 'public' ? kMlKemPublicUsagesMask : kMlKemPrivateUsagesMask,
    type === 'public');
}

function createX25519CryptoKey(handle, type) {
  return new InternalCryptoKey(
    handle,
    kX25519Algorithm,
    type === 'private' ? kX25519PrivateUsagesMask : 0,
    type === 'public');
}

function rawPublicKey(handle) {
  return Buffer.from(handle.rawPublicKey());
}

function rawPublicKeyFromHandles(mlKemHandle, x25519Handle) {
  return Buffer.concat([
    rawPublicKey(mlKemHandle),
    rawPublicKey(x25519Handle),
  ], kPublicKeyLength);
}

function createPublicKeyFromComponents(
  mlKemPublicHandle,
  x25519PublicHandle,
  extractable,
  keyUsages) {
  const usagesSet = new SafeSet(keyUsages);
  return new InternalCryptoKey(
    mlKemPublicHandle,
    { name: kName },
    getUsagesMask(usagesSet),
    extractable,
    x25519PublicHandle);
}

function createPrivateKeyFromComponents(
  mlKemPrivateHandle,
  x25519PrivateHandle,
  seed,
  extractable,
  keyUsages) {
  const usagesSet = new SafeSet(keyUsages);
  const key = new InternalCryptoKey(
    mlKemPrivateHandle,
    { name: kName },
    getUsagesMask(usagesSet),
    extractable,
    x25519PrivateHandle,
    seed);
  return key;
}

function createPublicKeyFromRaw(rawPublic, extractable, keyUsages) {
  validateLength(rawPublic, kPublicKeyLength);

  const { mlKem, x25519 } = splitPublicKey(rawPublic);
  let mlKemPublicHandle;
  let x25519PublicHandle;
  try {
    mlKemPublicHandle = importMlKemPublicHandle(mlKem);
    x25519PublicHandle = importX25519PublicHandle(x25519);
  } catch (err) {
    throw dataFailure(err);
  }

  return createPublicKeyFromComponents(
    mlKemPublicHandle,
    x25519PublicHandle,
    extractable,
    keyUsages);
}

function createPrivateKeyFromSeed(seed, extractable, keyUsages) {
  validateLength(seed, kSeedLength);

  const expanded = hash('shake256', seed, {
    outputEncoding: 'buffer',
    outputLength: kMlKemSeedLength + kX25519KeyLength,
  });
  const mlKemSeed = Buffer.from(expanded.subarray(0, kMlKemSeedLength));
  const x25519Seed = Buffer.from(expanded.subarray(kMlKemSeedLength));

  let mlKemPrivateHandle;
  let x25519PrivateHandle;
  try {
    mlKemPrivateHandle = importMlKemPrivateHandle(mlKemSeed);
    x25519PrivateHandle = importX25519PrivateHandle(x25519Seed);
  } catch (err) {
    throw dataFailure(err);
  }

  return createPrivateKeyFromComponents(
    mlKemPrivateHandle,
    x25519PrivateHandle,
    seed,
    extractable,
    keyUsages);
}

function getHybridKeyHandles(key) {
  const mlKemHandle = getCryptoKeyHandle(key);
  const x25519Handle = getCryptoKeySecondaryHandle(key);
  if (x25519Handle === undefined) {
    throw operationFailure();
  }
  return { __proto__: null, mlKemHandle, x25519Handle };
}

function getHybridSeed(key) {
  const seed = getCryptoKeyData(key);
  if (seed === undefined) {
    throw operationFailure();
  }
  return Buffer.from(seed);
}

async function deriveX25519Bits(publicKey, privateKey) {
  try {
    return Buffer.from(await ecdhDeriveBits({
      name: kX25519Name,
      public: publicKey,
    }, privateKey, null));
  } catch (err) {
    throw operationFailure(err);
  }
}

function combineSharedSecret(
  mlKemSharedKey,
  x25519SharedKey,
  x25519Ciphertext,
  rawPublic) {
  return hash('sha3-256', Buffer.concat([
    mlKemSharedKey,
    x25519SharedKey,
    x25519Ciphertext,
    rawPublic.subarray(kMlKemPublicKeyLength),
    kLabel,
  ]), { outputEncoding: 'buffer' });
}

async function mlkemX25519GenerateKey(algorithm, extractable, keyUsages) {
  const { name } = algorithm;

  const usageSet = new SafeSet(keyUsages);
  if (hasAnyNotIn(usageSet, [
    'encapsulateKey',
    'encapsulateBits',
    'decapsulateKey',
    'decapsulateBits',
  ])) {
    throw lazyDOMException(
      `Unsupported key usage for an ${name} key`,
      'SyntaxError');
  }

  const privateUsages = getUsagesUnion(
    usageSet, 'decapsulateKey', 'decapsulateBits');
  const publicUsages = getUsagesUnion(
    usageSet, 'encapsulateKey', 'encapsulateBits');
  const privateKey = createPrivateKeyFromSeed(
    randomBytes(kSeedLength),
    extractable,
    privateUsages);
  const { mlKemHandle, x25519Handle } = getHybridKeyHandles(privateKey);
  const publicKey = createPublicKeyFromRaw(
    rawPublicKeyFromHandles(mlKemHandle, x25519Handle),
    true,
    publicUsages);

  return { __proto__: null, privateKey, publicKey };
}

function mlkemX25519ImportKey(
  format,
  input,
  algorithm,
  extractable,
  keyUsages) {

  const { name } = algorithm;
  const usagesSet = new SafeSet(keyUsages);

  switch (format) {
    case 'raw-public': {
      verifyAcceptableKeyUse(name, true, usagesSet);
      return createPublicKeyFromRaw(
        bufferFromKeyData(input),
        extractable,
        usagesSet);
    }
    case 'raw-seed': {
      verifyAcceptableKeyUse(name, false, usagesSet);
      return createPrivateKeyFromSeed(
        bufferFromKeyData(input),
        extractable,
        usagesSet);
    }
    case 'jwk': {
      validateJwk(input, 'AKP', extractable, usagesSet, 'enc');
      if (input.alg !== name) {
        throw lazyDOMException(
          'JWK "alg" Parameter and algorithm name mismatch', 'DataError');
      }

      const rawPublic = Buffer.from(input.pub, 'base64url');
      validateLength(rawPublic, kPublicKeyLength);

      if (input.priv === undefined) {
        verifyAcceptableKeyUse(name, true, usagesSet);
        return createPublicKeyFromRaw(rawPublic, extractable, usagesSet);
      }

      verifyAcceptableKeyUse(name, false, usagesSet);
      const seed = Buffer.from(input.priv, 'base64url');
      const key = createPrivateKeyFromSeed(seed, extractable, usagesSet);
      const { mlKemHandle, x25519Handle } = getHybridKeyHandles(key);
      const derivedRawPublic =
        rawPublicKeyFromHandles(mlKemHandle, x25519Handle);
      if (!derivedRawPublic.equals(rawPublic)) {
        throw lazyDOMException('Invalid keyData', 'DataError');
      }
      return key;
    }
    default:
      return undefined;
  }
}

function mlkemX25519ExportKey(key, format) {
  const { mlKemHandle, x25519Handle } = getHybridKeyHandles(key);
  const rawPublic = rawPublicKeyFromHandles(mlKemHandle, x25519Handle);
  switch (format) {
    case 'raw-public':
      return toArrayBuffer(rawPublic);
    case 'raw-seed':
      if (getCryptoKeyType(key) === 'private') {
        return toArrayBuffer(getHybridSeed(key));
      }
      return undefined;
    case 'jwk': {
      const jwk = {
        kty: 'AKP',
        alg: kName,
        pub: rawPublic.toString('base64url'),
        key_ops: ArrayPrototypeSlice(getCryptoKeyUsages(key), 0),
        ext: getCryptoKeyExtractable(key),
      };
      if (getCryptoKeyType(key) === 'private') {
        jwk.priv = getHybridSeed(key).toString('base64url');
      }
      return jwk;
    }
    default:
      return undefined;
  }
}

function mlkemX25519GetPublicKey(privateKey, keyUsages) {
  const { mlKemHandle, x25519Handle } = getHybridKeyHandles(privateKey);
  const usageSet = new SafeSet(keyUsages);
  verifyAcceptableKeyUse(kName, true, usageSet);
  return createPublicKeyFromRaw(
    rawPublicKeyFromHandles(mlKemHandle, x25519Handle),
    true,
    usageSet);
}

async function mlkemX25519Encapsulate(encapsulationKey) {
  if (getCryptoKeyType(encapsulationKey) !== 'public') {
    throw lazyDOMException('Key must be a public key', 'InvalidAccessError');
  }

  const { mlKemHandle, x25519Handle } =
    getHybridKeyHandles(encapsulationKey);
  const mlKemResult = await mlKemEncapsulate(
    createMlKemCryptoKey(mlKemHandle, 'public'));
  const x25519EphemeralHandle =
    importX25519PrivateHandle(randomBytes(kX25519KeyLength));
  const x25519Ciphertext = rawPublicKey(x25519EphemeralHandle);
  const x25519SharedKey = await deriveX25519Bits(
    createX25519CryptoKey(x25519Handle, 'public'),
    createX25519CryptoKey(x25519EphemeralHandle, 'private'));
  const rawPublic = rawPublicKeyFromHandles(mlKemHandle, x25519Handle);

  const sharedKey = combineSharedSecret(
    Buffer.from(mlKemResult.sharedKey),
    x25519SharedKey,
    x25519Ciphertext,
    rawPublic);
  const ciphertext = Buffer.concat([
    Buffer.from(mlKemResult.ciphertext),
    x25519Ciphertext,
  ], kCiphertextLength);

  return {
    __proto__: null,
    sharedKey: toArrayBuffer(sharedKey),
    ciphertext: toArrayBuffer(ciphertext),
  };
}

async function mlkemX25519Decapsulate(decapsulationKey, ciphertext) {
  if (getCryptoKeyType(decapsulationKey) !== 'private') {
    throw lazyDOMException('Key must be a private key', 'InvalidAccessError');
  }

  const { mlKemHandle, x25519Handle } =
    getHybridKeyHandles(decapsulationKey);
  const ciphertextBuffer = bufferFromKeyData(ciphertext);
  if (ciphertextBuffer.byteLength !== kCiphertextLength) {
    throw operationFailure();
  }

  const mlKemCiphertext = ciphertextBuffer.subarray(0, kMlKemCiphertextLength);
  const x25519Ciphertext =
    Buffer.from(ciphertextBuffer.subarray(kMlKemCiphertextLength));
  let x25519PublicHandle;
  try {
    x25519PublicHandle = importX25519PublicHandle(x25519Ciphertext);
  } catch (err) {
    throw operationFailure(err);
  }

  const mlKemSharedKey = await mlKemDecapsulate(
    createMlKemCryptoKey(mlKemHandle, 'private'),
    mlKemCiphertext);
  const x25519SharedKey = await deriveX25519Bits(
    createX25519CryptoKey(x25519PublicHandle, 'public'),
    createX25519CryptoKey(x25519Handle, 'private'));
  return toArrayBuffer(combineSharedSecret(
    Buffer.from(mlKemSharedKey),
    x25519SharedKey,
    x25519Ciphertext,
    rawPublicKeyFromHandles(mlKemHandle, x25519Handle)));
}

module.exports = {
  mlkemX25519Decapsulate,
  mlkemX25519Encapsulate,
  mlkemX25519ExportKey,
  mlkemX25519GenerateKey,
  mlkemX25519GetPublicKey,
  mlkemX25519ImportKey,
};
