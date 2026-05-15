'use strict';

const {
  ArrayBufferPrototypeSlice,
  ArrayPrototypeSlice,
  BigInt,
  SafeSet,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
} = primordials;

const { Buffer } = require('buffer');

const {
  getCryptoKeyExtractable,
  getCryptoKeyAlgorithm,
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
  crypto: {
    POINT_CONVERSION_UNCOMPRESSED,
  },
} = internalBinding('constants');

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

const kMlKemSeedLength = 64;
const kSeedLength = 32;
const kX25519KeyLength = 32;
const kP256KeyLength = 32;
const kP384KeyLength = 48;
const kEcPointPrefixLength = 1;
const kMlKem768PublicKeyLength = 1184;
const kMlKem768CiphertextLength = 1088;
const kMlKem1024PublicKeyLength = 1568;
const kMlKem1024CiphertextLength = 1568;
const kMlKem768Name = 'ML-KEM-768';
const kMlKem1024Name = 'ML-KEM-1024';
const kX25519Name = 'X25519';
const kEcdhName = 'ECDH';
const kEcKeyType = 'ec';
const kP256Name = 'P-256';
const kP384Name = 'P-384';
const kP256Order =
  BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const kP384Order =
  BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe' +
         'ffffffff0000000000000000ffffffff');

const kMlKemPublicUsagesMask =
  getUsagesMask(new SafeSet(['encapsulateBits']));
const kMlKemPrivateUsagesMask =
  getUsagesMask(new SafeSet(['decapsulateBits']));
const kTraditionalPrivateUsagesMask =
  getUsagesMask(new SafeSet(['deriveBits']));

const kAlgorithms = {
  '__proto__': null,
  'MLKEM768-P256': {
    name: 'MLKEM768-P256',
    mlKemName: kMlKem768Name,
    mlKemPublicKeyLength: kMlKem768PublicKeyLength,
    mlKemCiphertextLength: kMlKem768CiphertextLength,
    traditionalName: kEcdhName,
    traditionalKeyType: kEcKeyType,
    namedCurve: kP256Name,
    traditionalPublicKeyLength: kEcPointPrefixLength + 2 * kP256KeyLength,
    traditionalCiphertextLength: kEcPointPrefixLength + 2 * kP256KeyLength,
    traditionalScalarLength: kP256KeyLength,
    traditionalSeedLength: 4 * kP256KeyLength,
    traditionalOrder: kP256Order,
    label: Buffer.from('MLKEM768-P256'),
  },
  'MLKEM768-X25519': {
    name: 'MLKEM768-X25519',
    mlKemName: kMlKem768Name,
    mlKemPublicKeyLength: kMlKem768PublicKeyLength,
    mlKemCiphertextLength: kMlKem768CiphertextLength,
    traditionalName: kX25519Name,
    traditionalKeyType: kX25519Name,
    traditionalPublicKeyLength: kX25519KeyLength,
    traditionalCiphertextLength: kX25519KeyLength,
    traditionalScalarLength: kX25519KeyLength,
    traditionalSeedLength: kX25519KeyLength,
    label: Buffer.from('5c2e2f2f5e5c', 'hex'),
  },
  'MLKEM1024-P384': {
    name: 'MLKEM1024-P384',
    mlKemName: kMlKem1024Name,
    mlKemPublicKeyLength: kMlKem1024PublicKeyLength,
    mlKemCiphertextLength: kMlKem1024CiphertextLength,
    traditionalName: kEcdhName,
    traditionalKeyType: kEcKeyType,
    namedCurve: kP384Name,
    traditionalPublicKeyLength: kEcPointPrefixLength + 2 * kP384KeyLength,
    traditionalCiphertextLength: kEcPointPrefixLength + 2 * kP384KeyLength,
    traditionalScalarLength: kP384KeyLength,
    traditionalSeedLength: kP384KeyLength,
    traditionalOrder: kP384Order,
    label: Buffer.from('MLKEM1024-P384'),
  },
};

for (const config of [
  kAlgorithms['MLKEM768-P256'],
  kAlgorithms['MLKEM768-X25519'],
  kAlgorithms['MLKEM1024-P384'],
]) {
  config.publicKeyLength =
    config.mlKemPublicKeyLength + config.traditionalPublicKeyLength;
  config.ciphertextLength =
    config.mlKemCiphertextLength + config.traditionalCiphertextLength;
}

function isMlKemHybridAlgorithm(name) {
  return kAlgorithms[name] !== undefined;
}

function getAlgorithmConfig(name) {
  const config = kAlgorithms[name];
  if (config !== undefined)
    return config;

  throw lazyDOMException('Unrecognized algorithm name', 'NotSupportedError');
}

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

function splitPublicKey(rawPublic, config) {
  return {
    mlKem: Buffer.from(
      rawPublic.subarray(0, config.mlKemPublicKeyLength)),
    traditional: Buffer.from(
      rawPublic.subarray(
        config.mlKemPublicKeyLength,
        config.publicKeyLength)),
  };
}

function os2ip(data) {
  let value = 0n;
  for (let n = 0; n < data.length; n++)
    value = (value << 8n) | BigInt(data[n]);
  return value;
}

function randomScalar(seed, config) {
  if (config.traditionalOrder === undefined)
    return Buffer.from(seed);

  const { traditionalOrder, traditionalScalarLength } = config;
  for (let offset = 0;
    offset + traditionalScalarLength <= seed.length;
    offset += traditionalScalarLength) {
    const scalar = Buffer.from(
      seed.subarray(offset, offset + traditionalScalarLength));
    const value = os2ip(scalar);
    if (value !== 0n && value < traditionalOrder)
      return scalar;
  }

  throw operationFailure();
}

function importRawKeyHandle(
  keyType,
  keyData,
  format,
  asymmetricKeyType,
  namedCurve) {
  const handle = new KeyObjectHandle();
  handle.init(
    keyType,
    keyData,
    format,
    asymmetricKeyType,
    null,
    namedCurve ?? null);
  if (asymmetricKeyType === kEcKeyType && !handle.checkEcKeyData())
    throw lazyDOMException('Invalid keyData', 'DataError');
  return handle;
}

function importMlKemPrivateHandle(seed, config) {
  return importRawKeyHandle(
    kKeyTypePrivate,
    seed,
    kKeyFormatRawSeed,
    config.mlKemName);
}

function importMlKemPublicHandle(rawPublic, config) {
  return importRawKeyHandle(
    kKeyTypePublic,
    rawPublic,
    kKeyFormatRawPublic,
    config.mlKemName);
}

function importTraditionalPrivateHandle(seed, config) {
  return importRawKeyHandle(
    kKeyTypePrivate,
    seed,
    kKeyFormatRawPrivate,
    config.traditionalKeyType,
    config.namedCurve);
}

function importTraditionalPublicHandle(rawPublic, config) {
  return importRawKeyHandle(
    kKeyTypePublic,
    rawPublic,
    kKeyFormatRawPublic,
    config.traditionalKeyType,
    config.namedCurve);
}

function mlKemAlgorithm(config) {
  return { name: config.mlKemName };
}

function traditionalAlgorithm(config) {
  if (config.traditionalKeyType === kEcKeyType) {
    return {
      name: config.traditionalName,
      namedCurve: config.namedCurve,
    };
  }
  return { name: config.traditionalName };
}

function createMlKemCryptoKey(handle, type, config) {
  return new InternalCryptoKey(
    handle,
    mlKemAlgorithm(config),
    type === 'public' ? kMlKemPublicUsagesMask : kMlKemPrivateUsagesMask,
    type === 'public');
}

function createTraditionalCryptoKey(handle, type, config) {
  return new InternalCryptoKey(
    handle,
    traditionalAlgorithm(config),
    type === 'private' ? kTraditionalPrivateUsagesMask : 0,
    type === 'public');
}

function rawMlKemPublicKey(handle) {
  return Buffer.from(handle.rawPublicKey());
}

function rawTraditionalPublicKey(handle, config) {
  if (config.traditionalKeyType === kEcKeyType) {
    return Buffer.from(
      handle.exportECPublicRaw(POINT_CONVERSION_UNCOMPRESSED));
  }
  return Buffer.from(handle.rawPublicKey());
}

function rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config) {
  return Buffer.concat([
    rawMlKemPublicKey(mlKemHandle),
    rawTraditionalPublicKey(traditionalHandle, config),
  ], config.publicKeyLength);
}

function createPublicKeyFromComponents(
  mlKemPublicHandle,
  traditionalPublicHandle,
  config,
  extractable,
  keyUsages) {
  const usagesSet = new SafeSet(keyUsages);
  return new InternalCryptoKey(
    mlKemPublicHandle,
    { name: config.name },
    getUsagesMask(usagesSet),
    extractable,
    traditionalPublicHandle);
}

function createPrivateKeyFromComponents(
  mlKemPrivateHandle,
  traditionalPrivateHandle,
  seed,
  config,
  extractable,
  keyUsages) {
  const usagesSet = new SafeSet(keyUsages);
  return new InternalCryptoKey(
    mlKemPrivateHandle,
    { name: config.name },
    getUsagesMask(usagesSet),
    extractable,
    traditionalPrivateHandle,
    seed);
}

function createPublicKeyFromRaw(rawPublic, config, extractable, keyUsages) {
  validateLength(rawPublic, config.publicKeyLength);

  const { mlKem, traditional } = splitPublicKey(rawPublic, config);
  let mlKemPublicHandle;
  let traditionalPublicHandle;
  try {
    mlKemPublicHandle = importMlKemPublicHandle(mlKem, config);
    traditionalPublicHandle =
      importTraditionalPublicHandle(traditional, config);
  } catch (err) {
    throw dataFailure(err);
  }

  return createPublicKeyFromComponents(
    mlKemPublicHandle,
    traditionalPublicHandle,
    config,
    extractable,
    keyUsages);
}

function createPrivateKeyFromSeed(seed, config, extractable, keyUsages) {
  validateLength(seed, kSeedLength);

  const expanded = hash('shake256', seed, {
    outputEncoding: 'buffer',
    outputLength: kMlKemSeedLength + config.traditionalSeedLength,
  });
  const mlKemSeed = Buffer.from(expanded.subarray(0, kMlKemSeedLength));
  const traditionalSeed = randomScalar(
    expanded.subarray(kMlKemSeedLength),
    config);

  let mlKemPrivateHandle;
  let traditionalPrivateHandle;
  try {
    mlKemPrivateHandle = importMlKemPrivateHandle(mlKemSeed, config);
    traditionalPrivateHandle =
      importTraditionalPrivateHandle(traditionalSeed, config);
  } catch (err) {
    throw operationFailure(err);
  }

  return createPrivateKeyFromComponents(
    mlKemPrivateHandle,
    traditionalPrivateHandle,
    seed,
    config,
    extractable,
    keyUsages);
}

function getHybridKeyHandles(key) {
  const mlKemHandle = getCryptoKeyHandle(key);
  const traditionalHandle = getCryptoKeySecondaryHandle(key);
  if (traditionalHandle === undefined) {
    throw operationFailure();
  }
  return { __proto__: null, mlKemHandle, traditionalHandle };
}

function getHybridSeed(key) {
  const seed = getCryptoKeyData(key);
  if (seed === undefined) {
    throw operationFailure();
  }
  return Buffer.from(seed);
}

async function deriveTraditionalBits(publicKey, privateKey, config) {
  const { name } = traditionalAlgorithm(config);
  try {
    return Buffer.from(await ecdhDeriveBits({
      name,
      public: publicKey,
    }, privateKey, null));
  } catch (err) {
    throw operationFailure(err);
  }
}

function combineSharedSecret(
  mlKemSharedKey,
  traditionalSharedKey,
  traditionalCiphertext,
  rawPublic,
  config) {
  return hash('sha3-256', Buffer.concat([
    mlKemSharedKey,
    traditionalSharedKey,
    traditionalCiphertext,
    rawPublic.subarray(config.mlKemPublicKeyLength),
    config.label,
  ]), { outputEncoding: 'buffer' });
}

async function mlKemHybridGenerateKey(algorithm, extractable, keyUsages) {
  const { name } = algorithm;
  const config = getAlgorithmConfig(name);

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
    config,
    extractable,
    privateUsages);
  const { mlKemHandle, traditionalHandle } = getHybridKeyHandles(privateKey);
  const publicKey = createPublicKeyFromRaw(
    rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config),
    config,
    true,
    publicUsages);

  return { __proto__: null, privateKey, publicKey };
}

function mlKemHybridImportKey(
  format,
  input,
  algorithm,
  extractable,
  keyUsages) {

  const { name } = algorithm;
  const config = getAlgorithmConfig(name);
  const usagesSet = new SafeSet(keyUsages);

  switch (format) {
    case 'raw-public': {
      verifyAcceptableKeyUse(name, true, usagesSet);
      return createPublicKeyFromRaw(
        bufferFromKeyData(input),
        config,
        extractable,
        usagesSet);
    }
    case 'raw-seed': {
      verifyAcceptableKeyUse(name, false, usagesSet);
      return createPrivateKeyFromSeed(
        bufferFromKeyData(input),
        config,
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
      validateLength(rawPublic, config.publicKeyLength);

      if (input.priv === undefined) {
        verifyAcceptableKeyUse(name, true, usagesSet);
        return createPublicKeyFromRaw(
          rawPublic,
          config,
          extractable,
          usagesSet);
      }

      verifyAcceptableKeyUse(name, false, usagesSet);
      const seed = Buffer.from(input.priv, 'base64url');
      const key = createPrivateKeyFromSeed(seed, config, extractable, usagesSet);
      const { mlKemHandle, traditionalHandle } = getHybridKeyHandles(key);
      const derivedRawPublic =
        rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config);
      if (!derivedRawPublic.equals(rawPublic)) {
        throw lazyDOMException('Invalid keyData', 'DataError');
      }
      return key;
    }
    default:
      return undefined;
  }
}

function mlKemHybridExportKey(key, format) {
  const config = getAlgorithmConfig(getCryptoKeyAlgorithm(key).name);
  const { mlKemHandle, traditionalHandle } = getHybridKeyHandles(key);
  const rawPublic =
    rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config);
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
        alg: config.name,
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

function mlKemHybridGetPublicKey(privateKey, keyUsages) {
  const config = getAlgorithmConfig(getCryptoKeyAlgorithm(privateKey).name);
  const { mlKemHandle, traditionalHandle } = getHybridKeyHandles(privateKey);
  const usageSet = new SafeSet(keyUsages);
  verifyAcceptableKeyUse(config.name, true, usageSet);
  return createPublicKeyFromRaw(
    rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config),
    config,
    true,
    usageSet);
}

function createEphemeralTraditionalPrivateHandle(config) {
  const seed = randomScalar(randomBytes(config.traditionalSeedLength), config);
  return importTraditionalPrivateHandle(seed, config);
}

async function mlKemHybridEncapsulate(encapsulationKey) {
  if (getCryptoKeyType(encapsulationKey) !== 'public') {
    throw lazyDOMException('Key must be a public key', 'InvalidAccessError');
  }

  const config = getAlgorithmConfig(getCryptoKeyAlgorithm(encapsulationKey).name);
  const { mlKemHandle, traditionalHandle } =
    getHybridKeyHandles(encapsulationKey);
  const mlKemResult = await mlKemEncapsulate(
    createMlKemCryptoKey(mlKemHandle, 'public', config));
  const traditionalEphemeralHandle =
    createEphemeralTraditionalPrivateHandle(config);
  const traditionalCiphertext =
    rawTraditionalPublicKey(traditionalEphemeralHandle, config);
  const traditionalSharedKey = await deriveTraditionalBits(
    createTraditionalCryptoKey(traditionalHandle, 'public', config),
    createTraditionalCryptoKey(traditionalEphemeralHandle, 'private', config),
    config);
  const rawPublic =
    rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config);

  const sharedKey = combineSharedSecret(
    Buffer.from(mlKemResult.sharedKey),
    traditionalSharedKey,
    traditionalCiphertext,
    rawPublic,
    config);
  const ciphertext = Buffer.concat([
    Buffer.from(mlKemResult.ciphertext),
    traditionalCiphertext,
  ], config.ciphertextLength);

  return {
    __proto__: null,
    sharedKey: toArrayBuffer(sharedKey),
    ciphertext: toArrayBuffer(ciphertext),
  };
}

async function mlKemHybridDecapsulate(decapsulationKey, ciphertext) {
  if (getCryptoKeyType(decapsulationKey) !== 'private') {
    throw lazyDOMException('Key must be a private key', 'InvalidAccessError');
  }

  const config = getAlgorithmConfig(getCryptoKeyAlgorithm(decapsulationKey).name);
  const { mlKemHandle, traditionalHandle } =
    getHybridKeyHandles(decapsulationKey);
  const ciphertextBuffer = bufferFromKeyData(ciphertext);
  if (ciphertextBuffer.byteLength !== config.ciphertextLength) {
    throw operationFailure();
  }

  const mlKemCiphertext =
    ciphertextBuffer.subarray(0, config.mlKemCiphertextLength);
  const traditionalCiphertext =
    Buffer.from(ciphertextBuffer.subarray(config.mlKemCiphertextLength));
  let traditionalPublicHandle;
  try {
    traditionalPublicHandle =
      importTraditionalPublicHandle(traditionalCiphertext, config);
  } catch (err) {
    throw operationFailure(err);
  }

  const mlKemSharedKey = await mlKemDecapsulate(
    createMlKemCryptoKey(mlKemHandle, 'private', config),
    mlKemCiphertext);
  const traditionalSharedKey = await deriveTraditionalBits(
    createTraditionalCryptoKey(traditionalPublicHandle, 'public', config),
    createTraditionalCryptoKey(traditionalHandle, 'private', config),
    config);
  return toArrayBuffer(combineSharedSecret(
    Buffer.from(mlKemSharedKey),
    traditionalSharedKey,
    traditionalCiphertext,
    rawPublicKeyFromHandles(mlKemHandle, traditionalHandle, config),
    config));
}

module.exports = {
  isMlKemHybridAlgorithm,
  mlKemHybridDecapsulate,
  mlKemHybridEncapsulate,
  mlKemHybridExportKey,
  mlKemHybridGenerateKey,
  mlKemHybridGetPublicKey,
  mlKemHybridImportKey,
};
