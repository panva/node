'use strict';

const {
  ObjectFreeze,
  Symbol,
  TypedArrayPrototypeIncludes,
  Uint8Array,
} = primordials;

const {
  Buffer,
  constants: {
    MAX_LENGTH,
  },
} = require('buffer');

const {
  codes: {
    ERR_CRYPTO_HPKE_NOT_SUPPORTED,
    ERR_CRYPTO_INVALID_STATE,
    ERR_ILLEGAL_CONSTRUCTOR,
    ERR_INVALID_ARG_VALUE,
    ERR_MISSING_OPTION,
    ERR_OUT_OF_RANGE,
  },
} = require('internal/errors');

const {
  validateInteger,
  validateObject,
  validateUint32,
} = require('internal/validators');

const {
  isArrayBufferView,
} = require('internal/util/types');

const {
  preparePrivateKey,
  preparePublicOrPrivateKey,
  SecretKeyObject,
} = require('internal/crypto/keys');

const {
  validateBufferSource,
} = require('internal/crypto/util');

const {
  kEmptyObject,
} = require('internal/util');

const {
  HPKEContext,
  constants: _constants,
  getCiphertextSize: _getCiphertextSize,
  getPublicEncapSize: _getPublicEncapSize,
  isSuiteSupported: _isSuiteSupported,
} = internalBinding('crypto');

if (HPKEContext === undefined)
  throw new ERR_CRYPTO_HPKE_NOT_SUPPORTED();

const constants = ObjectFreeze(_constants);

const {
  AEAD_EXPORT_ONLY,
  MAX_INFO_LENGTH,
  MAX_PARAMETER_LENGTH,
  MIN_PSK_LENGTH,
} = constants;

const kModeBase = 0;
const kModePsk = 1;
const kRoleSender = 0;
const kRoleRecipient = 1;
const kConstruct = Symbol('HPKEContext construct');
const kMaxHPKESuiteId = 0xffff;

function getOptionalByteSource(value, name) {
  if (value !== undefined)
    return validateBufferSource(value, name);
  return value;
}

function getUint8Array(value) {
  if (isArrayBufferView(value))
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return new Uint8Array(value);
}

function copyByteSource(value) {
  return Buffer.from(getUint8Array(value));
}

function validateNoNul(value, name) {
  const bytes = getUint8Array(value);
  if (TypedArrayPrototypeIncludes(bytes, 0)) {
    throw new ERR_INVALID_ARG_VALUE(
      name, value, 'must not contain null bytes');
  }
}

function validateByteLength(value, name, min, max) {
  const { byteLength } = getUint8Array(value);
  if (byteLength < min || byteLength > max) {
    throw new ERR_OUT_OF_RANGE(
      `${name}.byteLength`,
      `>= ${min} && <= ${max}`,
      byteLength);
  }
}

function validateHPKESuiteId(value, name) {
  validateUint32(value, name);
  validateInteger(value, name, 0, kMaxHPKESuiteId);
}

function validateSize(value, name) {
  validateInteger(value, name, 0, MAX_LENGTH);
}

function validateSuite(suite, name = 'suite') {
  validateObject(suite, name);
  validateHPKESuiteId(suite.kemId, `${name}.kemId`);
  validateHPKESuiteId(suite.kdfId, `${name}.kdfId`);
  validateHPKESuiteId(suite.aeadId, `${name}.aeadId`);

  return {
    __proto__: null,
    kemId: suite.kemId,
    kdfId: suite.kdfId,
    aeadId: suite.aeadId,
  };
}

function validatePsk(options) {
  const { psk, pskId } = options;

  if (psk === undefined && pskId === undefined) {
    return {
      __proto__: null,
      mode: kModeBase,
      psk: undefined,
      pskId: undefined,
    };
  }

  if (psk === undefined)
    throw new ERR_MISSING_OPTION('options.psk');
  if (pskId === undefined)
    throw new ERR_MISSING_OPTION('options.pskId');

  const pskSource = validateBufferSource(psk, 'options.psk');
  const pskIdSource = validateBufferSource(pskId, 'options.pskId');
  validateByteLength(
    pskSource, 'options.psk', MIN_PSK_LENGTH, MAX_PARAMETER_LENGTH);
  validateByteLength(pskIdSource, 'options.pskId', 1, MAX_PARAMETER_LENGTH);

  const pskBytes = copyByteSource(pskSource);
  const pskIdBytes = copyByteSource(pskIdSource);
  validateNoNul(pskIdBytes, 'options.pskId');

  return {
    __proto__: null,
    mode: kModePsk,
    psk: pskBytes,
    pskId: pskIdBytes,
  };
}

function createContext(role, mode, suite, psk, pskId) {
  return new HPKEContext(
    role,
    mode,
    suite.kemId,
    suite.kdfId,
    suite.aeadId,
    psk,
    pskId);
}

function validateOptions(options) {
  validateObject(options, 'options');
  const info = getOptionalByteSource(options.info, 'options.info');
  if (info !== undefined)
    validateByteLength(info, 'options.info', 0, MAX_INFO_LENGTH);

  return {
    __proto__: null,
    info,
    psk: validatePsk(options),
  };
}

function isSuiteSupported(suite) {
  suite = validateSuite(suite, 'suite');
  return _isSuiteSupported(suite.kemId, suite.kdfId, suite.aeadId);
}

function getPublicEncapSize(suite) {
  suite = validateSuite(suite, 'suite');
  return _getPublicEncapSize(suite.kemId, suite.kdfId, suite.aeadId);
}

function getCiphertextSize(suite, plaintextLength) {
  suite = validateSuite(suite, 'suite');
  validateSize(plaintextLength, 'plaintextLength');
  return _getCiphertextSize(
    suite.kemId,
    suite.kdfId,
    suite.aeadId,
    plaintextLength);
}

class SenderContext {
  #handle;
  #encapsulatedKey;
  #isExportOnly;

  constructor(key, handle, encapsulatedKey, isExportOnly) {
    if (key !== kConstruct)
      throw new ERR_ILLEGAL_CONSTRUCTOR();

    this.#handle = handle;
    this.#encapsulatedKey = encapsulatedKey;
    this.#isExportOnly = isExportOnly;
  }

  get encapsulatedKey() {
    return Buffer.from(this.#encapsulatedKey);
  }

  seal(plaintext, aad) {
    if (this.#isExportOnly)
      throw new ERR_CRYPTO_INVALID_STATE('seal');

    plaintext = validateBufferSource(plaintext, 'plaintext');
    aad = getOptionalByteSource(aad, 'aad');
    return this.#handle.seal(plaintext, aad);
  }

  export(label, length) {
    label = validateBufferSource(label, 'label');
    validateByteLength(label, 'label', 0, MAX_PARAMETER_LENGTH);
    validateSize(length, 'length');
    return new SecretKeyObject(this.#handle.export(label, length));
  }
}

class RecipientContext {
  #handle;
  #isExportOnly;

  constructor(key, handle, isExportOnly) {
    if (key !== kConstruct)
      throw new ERR_ILLEGAL_CONSTRUCTOR();

    this.#handle = handle;
    this.#isExportOnly = isExportOnly;
  }

  open(ciphertext, aad) {
    if (this.#isExportOnly)
      throw new ERR_CRYPTO_INVALID_STATE('open');

    ciphertext = validateBufferSource(ciphertext, 'ciphertext');
    aad = getOptionalByteSource(aad, 'aad');
    return this.#handle.open(ciphertext, aad);
  }

  export(label, length) {
    label = validateBufferSource(label, 'label');
    validateByteLength(label, 'label', 0, MAX_PARAMETER_LENGTH);
    validateSize(length, 'length');
    return new SecretKeyObject(this.#handle.export(label, length));
  }
}

function createSenderContext(suite, publicKey, options = kEmptyObject) {
  suite = validateSuite(suite);

  const {
    info,
    psk: {
      mode,
      psk,
      pskId,
    },
  } = validateOptions(options);

  const {
    data: keyData,
    format: keyFormat,
    type: keyType,
    passphrase: keyPassphrase,
    namedCurve: keyNamedCurve,
  } = preparePublicOrPrivateKey(publicKey, 'publicKey');

  const handle = createContext(kRoleSender, mode, suite, psk, pskId);
  const encapsulatedKey = handle.encap(
    keyData,
    keyFormat,
    keyType,
    keyPassphrase,
    keyNamedCurve,
    info);

  return new SenderContext(
    kConstruct,
    handle,
    encapsulatedKey,
    suite.aeadId === AEAD_EXPORT_ONLY);
}

function createRecipientContext(
  suite,
  privateKey,
  encapsulatedKey,
  options = kEmptyObject,
) {
  suite = validateSuite(suite);

  const {
    info,
    psk: {
      mode,
      psk,
      pskId,
    },
  } = validateOptions(options);

  encapsulatedKey = validateBufferSource(encapsulatedKey, 'encapsulatedKey');

  const {
    data: keyData,
    format: keyFormat,
    type: keyType,
    passphrase: keyPassphrase,
    namedCurve: keyNamedCurve,
  } = preparePrivateKey(privateKey, 'privateKey');

  const handle = createContext(kRoleRecipient, mode, suite, psk, pskId);
  handle.decap(
    keyData,
    keyFormat,
    keyType,
    keyPassphrase,
    keyNamedCurve,
    encapsulatedKey,
    info);

  return new RecipientContext(
    kConstruct,
    handle,
    suite.aeadId === AEAD_EXPORT_ONLY);
}

function seal(suite, publicKey, plaintext, options = kEmptyObject) {
  validateObject(options, 'options');
  plaintext = validateBufferSource(plaintext, 'plaintext');
  const aad = getOptionalByteSource(options.aad, 'options.aad');

  const sender = createSenderContext(suite, publicKey, options);
  return {
    __proto__: null,
    encapsulatedKey: sender.encapsulatedKey,
    ciphertext: sender.seal(plaintext, aad),
  };
}

function open(
  suite,
  privateKey,
  encapsulatedKey,
  ciphertext,
  options = kEmptyObject,
) {
  validateObject(options, 'options');
  ciphertext = validateBufferSource(ciphertext, 'ciphertext');
  const aad = getOptionalByteSource(options.aad, 'options.aad');

  return createRecipientContext(
    suite,
    privateKey,
    encapsulatedKey,
    options).open(ciphertext, aad);
}

function sendExport(suite, publicKey, label, length, options = kEmptyObject) {
  validateObject(options, 'options');
  label = validateBufferSource(label, 'label');
  validateByteLength(label, 'label', 0, MAX_PARAMETER_LENGTH);
  validateSize(length, 'length');

  const sender = createSenderContext(suite, publicKey, options);
  return {
    __proto__: null,
    encapsulatedKey: sender.encapsulatedKey,
    exportedSecret: sender.export(label, length),
  };
}

function receiveExport(
  suite,
  privateKey,
  encapsulatedKey,
  label,
  length,
  options = kEmptyObject,
) {
  validateObject(options, 'options');
  label = validateBufferSource(label, 'label');
  validateByteLength(label, 'label', 0, MAX_PARAMETER_LENGTH);
  validateSize(length, 'length');

  return createRecipientContext(
    suite,
    privateKey,
    encapsulatedKey,
    options).export(label, length);
}

module.exports = ObjectFreeze({
  createSenderContext,
  createRecipientContext,
  seal,
  open,
  sendExport,
  receiveExport,
  isSuiteSupported,
  getPublicEncapSize,
  getCiphertextSize,
  SenderContext,
  RecipientContext,
  constants,
});
