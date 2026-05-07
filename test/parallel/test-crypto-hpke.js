'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const { builtinModules } = require('module');
const { spawnSyncAndAssert } = require('../common/child_process');
const {
  constants: {
    MAX_LENGTH,
  },
} = require('buffer');
const fixtures = require('../common/fixtures');
const { hasOpenSSL } = require('../common/crypto');

const hasHPKE = hasOpenSSL(3, 2);
const kOpenSSLFailedDuringDerivation = {
  code: 'ERR_OSSL_FAILED_DURING_DERIVATION',
  reason: 'failed during derivation',
};
const kOpenSSLInternalError = {
  code: 'ERR_OSSL_CRYPTO_INTERNAL_ERROR',
  reason: 'internal error',
};
const kOpenSSLEvpUnsupported = {
  code: 'ERR_OSSL_EVP_UNSUPPORTED',
  reason: 'unsupported',
};
const kOpenSSLInvalidKey = {
  code: 'ERR_OSSL_INVALID_KEY',
  reason: 'invalid key',
};
const kOpenSSLInvalidArgument = {
  code: 'ERR_OSSL_CRYPTO_PASSED_INVALID_ARGUMENT',
  reason: 'passed invalid argument',
};
const kInvalidHPKEPublicKey = {
  code: 'ERR_CRYPTO_OPERATION_FAILED',
  message: 'Failed to get HPKE public key',
};
const kUnsupportedHPKESuite = {
  code: 'ERR_CRYPTO_UNSUPPORTED_OPERATION',
  message: 'Unsupported HPKE suite',
};

assert(builtinModules.includes('node:hpke'));
assert.strictEqual(process.getBuiltinModule('hpke'), undefined);
assert.throws(() => require('hpke'), { code: 'MODULE_NOT_FOUND' });
assert.throws(() => require('node:crypto/hpke'), {
  code: 'ERR_UNKNOWN_BUILTIN_MODULE',
});

if (!hasHPKE) {
  assert.strictEqual(
    Object.getOwnPropertyDescriptor(crypto, 'hpke').enumerable,
    false);
  assert.throws(() => require('node:hpke'), {
    code: 'ERR_CRYPTO_HPKE_NOT_SUPPORTED',
  });
  assert.throws(() => crypto.hpke, {
    code: 'ERR_CRYPTO_HPKE_NOT_SUPPORTED',
  });
  assert.throws(() => process.getBuiltinModule('node:hpke'), {
    code: 'ERR_CRYPTO_HPKE_NOT_SUPPORTED',
  });
  spawnSyncAndAssert(process.execPath, [
    '--input-type=module',
    '--eval',
    `
      import crypto, { randomBytes } from 'node:crypto';
      randomBytes(1);
      try {
        crypto.hpke;
      } catch (err) {
        if (err?.code === 'ERR_CRYPTO_HPKE_NOT_SUPPORTED')
          process.exit(0);
        throw err;
      }
      throw new Error('expected crypto.hpke to throw');
    `,
  ], { status: 0 });
  return;
}

const hpke = require('node:hpke');
const { constants } = hpke;

assert(Object.isFrozen(constants));
assert.strictEqual(require('node:hpke'), hpke);
assert.strictEqual(crypto.hpke, hpke);
assert.strictEqual(Object.getOwnPropertyDescriptor(crypto, 'hpke').enumerable,
                   true);
assert.strictEqual(process.getBuiltinModule('node:hpke'), hpke);

assert.strictEqual(constants.MAX_PARAMETER_LENGTH, 66);
assert.strictEqual(constants.MIN_PSK_LENGTH, 32);
assert.strictEqual(constants.MAX_INFO_LENGTH, 1024);
assert.deepStrictEqual(Object.keys(constants), [
  'KEM_DHKEM_P256_HKDF_SHA256',
  'KEM_DHKEM_P384_HKDF_SHA384',
  'KEM_DHKEM_P521_HKDF_SHA512',
  'KEM_DHKEM_X25519_HKDF_SHA256',
  'KEM_DHKEM_X448_HKDF_SHA512',
  'KDF_HKDF_SHA256',
  'KDF_HKDF_SHA384',
  'KDF_HKDF_SHA512',
  'AEAD_AES_128_GCM',
  'AEAD_AES_256_GCM',
  'AEAD_ChaCha20Poly1305',
  'AEAD_EXPORT_ONLY',
  'MAX_PARAMETER_LENGTH',
  'MIN_PSK_LENGTH',
  'MAX_INFO_LENGTH',
]);

const x25519Suite = {
  kemId: constants.KEM_DHKEM_X25519_HKDF_SHA256,
  kdfId: constants.KDF_HKDF_SHA256,
  aeadId: constants.AEAD_AES_128_GCM,
};

const p256Suite = {
  kemId: constants.KEM_DHKEM_P256_HKDF_SHA256,
  kdfId: constants.KDF_HKDF_SHA256,
  aeadId: constants.AEAD_AES_128_GCM,
};

function loadFixtureKeyPair(publicKeyFile, privateKeyFile) {
  const publicKeyPem = fixtures.readKey(publicKeyFile, 'ascii');
  const privateKeyPem = fixtures.readKey(privateKeyFile, 'ascii');

  return {
    publicKey: crypto.createPublicKey(publicKeyPem),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem,
    privateKeyPem,
  };
}

const x25519Keys =
  loadFixtureKeyPair('x25519_public.pem', 'x25519_private.pem');
const p256Keys =
  loadFixtureKeyPair('ec_p256_public.pem', 'ec_p256_private.pem');
const p384Keys =
  loadFixtureKeyPair('ec_p384_public.pem', 'ec_p384_private.pem');
const rsaKeys =
  loadFixtureKeyPair('rsa_public_2048.pem', 'rsa_private_2048.pem');
const ed25519Keys =
  loadFixtureKeyPair('ed25519_public.pem', 'ed25519_private.pem');

const x25519Supported = {
  name: 'x25519',
  suite: x25519Suite,
  keys: x25519Keys,
};

const p256Supported = {
  name: 'p256',
  suite: p256Suite,
  keys: p256Keys,
};

const supportedSuites = [
  x25519Supported,
  p256Supported,
];

function kdfHashLength(kdfId) {
  switch (kdfId) {
    case constants.KDF_HKDF_SHA256:
      return 32;
    case constants.KDF_HKDF_SHA384:
      return 48;
    case constants.KDF_HKDF_SHA512:
      return 64;
  }
}

function createArrayBuffer(size, fill = 0) {
  const buffer = new ArrayBuffer(size);
  new Uint8Array(buffer).fill(fill);
  return buffer;
}

function createSender(suite, publicKey, options = {}) {
  return hpke.createSenderContext(suite, publicKey, {
    info: Buffer.from('node.js hpke info'),
    ...options,
  });
}

function createRecipient(suite, privateKey, encapsulatedKey, options = {}) {
  return hpke.createRecipientContext(suite, privateKey, encapsulatedKey, {
    info: Buffer.from('node.js hpke info'),
    ...options,
  });
}

function assertExactError(fn, expected) {
  assert.throws(fn, expected);
}

function kOutOfRange(name, min, max, received) {
  return {
    code: 'ERR_OUT_OF_RANGE',
    message: `The value of "${name}" is out of range. ` +
      `It must be >= ${min} && <= ${max}. Received ${received}`,
  };
}

function assertRoundTrip({ suite, keys, pskOptions }) {
  const { publicKey, privateKey } = keys;
  const sender = createSender(suite, publicKey, pskOptions);
  const encapsulatedKey = sender.encapsulatedKey;
  const encapsulatedKeyCopy = Buffer.from(encapsulatedKey);

  assert(sender instanceof hpke.SenderContext);
  assert(Buffer.isBuffer(encapsulatedKey));
  assert.strictEqual(
    encapsulatedKey.length,
    hpke.getPublicEncapSize(suite));
  encapsulatedKey[0] ^= 0xff;
  assert.deepStrictEqual(sender.encapsulatedKey, encapsulatedKeyCopy);

  const recipient =
    createRecipient(suite, privateKey, sender.encapsulatedKey, pskOptions);
  assert(recipient instanceof hpke.RecipientContext);

  const messages = [
    Buffer.from('first plaintext'),
    new Uint8Array([1, 2, 3, 4]),
  ];
  const aad = Buffer.from('aad');
  for (const message of messages) {
    const ciphertext = sender.seal(message, aad);
    assert(Buffer.isBuffer(ciphertext));
    assert.strictEqual(
      ciphertext.length,
      hpke.getCiphertextSize(suite, message.byteLength));
    assert.deepStrictEqual(recipient.open(ciphertext, aad), Buffer.from(message));
  }

  const label = Buffer.from('exporter label');
  const senderExport = sender.export(label, 32);
  const recipientExport = recipient.export(label, 32);
  assert.strictEqual(senderExport.type, 'secret');
  assert.strictEqual(recipientExport.type, 'secret');
  assert(senderExport.equals(recipientExport));

  assertExactError(
    () => sender.export(Buffer.alloc(0), 0),
    kOpenSSLInvalidArgument);
}

function assertOneShotRoundTrip({ suite, keys, pskOptions }) {
  const { publicKey, privateKey } = keys;
  const info = Buffer.from('node.js hpke one-shot info');
  const plaintext = Buffer.from('one-shot plaintext');
  const aad = Buffer.from('one-shot aad');
  const label = Buffer.from('one-shot label');
  const baseOptions = {
    info,
    ...pskOptions,
  };
  const sealed = hpke.seal(suite, publicKey, plaintext, {
    aad,
    ...baseOptions,
  });

  assert(Buffer.isBuffer(sealed.encapsulatedKey));
  assert(Buffer.isBuffer(sealed.ciphertext));
  assert.deepStrictEqual(hpke.open(
    suite,
    privateKey,
    sealed.encapsulatedKey,
    sealed.ciphertext,
    {
      aad,
      ...baseOptions,
    }), plaintext);

  const senderExport =
    hpke.sendExport(suite, publicKey, label, 32, baseOptions);
  const recipientExport = hpke.receiveExport(
    suite,
    privateKey,
    senderExport.encapsulatedKey,
    label,
    32,
    baseOptions);

  assert(Buffer.isBuffer(senderExport.encapsulatedKey));
  assert.strictEqual(senderExport.exportedSecret.type, 'secret');
  assert.strictEqual(recipientExport.type, 'secret');
  assert(senderExport.exportedSecret.equals(recipientExport));
}

for (const supported of supportedSuites) {
  assertRoundTrip(supported);
  assertRoundTrip({
    ...supported,
    pskOptions: {
      psk: Buffer.alloc(32, 1),
      pskId: Buffer.from([1, 2, 3]),
    },
  });
}

assertOneShotRoundTrip(p256Supported);
assertOneShotRoundTrip({
  ...p256Supported,
  pskOptions: {
    psk: Buffer.alloc(32, 1),
    pskId: Buffer.from([1, 2, 3]),
  },
});

{
  const { suite, keys: { publicKey, privateKey } } = p256Supported;
  const publicKeyJwk = publicKey.export({ format: 'jwk' });
  const privateKeyJwk = privateKey.export({ format: 'jwk' });
  const publicKeyRaw = publicKey.export({ format: 'raw-public' });
  const privateKeyRaw = privateKey.export({ format: 'raw-private' });

  for (const [publicKeyInput, privateKeyInput] of [
    [
      { key: publicKeyJwk, format: 'jwk' },
      { key: privateKeyJwk, format: 'jwk' },
    ],
    [
      {
        key: publicKeyRaw,
        format: 'raw-public',
        asymmetricKeyType: 'ec',
        namedCurve: 'prime256v1',
      },
      {
        key: privateKeyRaw,
        format: 'raw-private',
        asymmetricKeyType: 'ec',
        namedCurve: 'prime256v1',
      },
    ],
  ]) {
    const sender = createSender(suite, publicKeyInput);
    const recipient =
      createRecipient(suite, privateKeyInput, sender.encapsulatedKey);
    const plaintext = Buffer.from('key input round trip');

    assert.deepStrictEqual(
      recipient.open(sender.seal(plaintext)),
      plaintext);
  }
}

// Sender public key input uses the same public-or-private key preparation
// path as crypto.verify(), so private keys are accepted here.
for (const { suite, keys } of supportedSuites) {
  const { privateKey, privateKeyPem } = keys;

  for (const publicKey of [privateKey, privateKeyPem]) {
    const sender = createSender(suite, publicKey);
    const recipient =
      createRecipient(suite, privateKey, sender.encapsulatedKey);
    const plaintext = Buffer.from('private key public input');

    assert.deepStrictEqual(
      recipient.open(sender.seal(plaintext)),
      plaintext);
  }
}

{
  assertExactError(
    () => createSender(x25519Supported.suite, p256Keys.publicKey),
    kInvalidHPKEPublicKey);
  assertExactError(
    () => createSender(p256Supported.suite, x25519Keys.publicKey),
    kInvalidHPKEPublicKey);

  const x25519Sender =
    createSender(x25519Supported.suite, x25519Keys.publicKey);
  const p256Sender = createSender(p256Supported.suite, p256Keys.publicKey);

  assertExactError(
    () => createRecipient(
      x25519Supported.suite,
      p256Keys.privateKey,
      x25519Sender.encapsulatedKey),
    kOpenSSLInvalidKey);
  assertExactError(
    () => createRecipient(
      p256Supported.suite,
      x25519Keys.privateKey,
      p256Sender.encapsulatedKey),
    kOpenSSLInvalidKey);
}

{
  assertExactError(
    () => createSender(p256Supported.suite, p384Keys.publicKey),
    kInvalidHPKEPublicKey);
  assertExactError(
    () => createSender(p256Supported.suite, rsaKeys.publicKey),
    kInvalidHPKEPublicKey);
  assertExactError(
    () => createSender(p256Supported.suite, ed25519Keys.publicKey),
    kInvalidHPKEPublicKey);

  const sender = createSender(p256Supported.suite, p256Keys.publicKey);

  assertExactError(
    () => createRecipient(
      p256Supported.suite,
      p384Keys.privateKey,
      sender.encapsulatedKey),
    kOpenSSLInvalidKey);
  assertExactError(
    () => createRecipient(
      p256Supported.suite,
      rsaKeys.privateKey,
      sender.encapsulatedKey),
    kOpenSSLInternalError);
  assertExactError(
    () => createRecipient(
      p256Supported.suite,
      ed25519Keys.privateKey,
      sender.encapsulatedKey),
    kOpenSSLEvpUnsupported);
}

{
  const supported = p256Supported;
  const { publicKey, privateKey } = supported.keys;
  const plaintext = Buffer.from('undefined defaults');
  const sender = hpke.createSenderContext(supported.suite, publicKey);
  const recipient = hpke.createRecipientContext(
    supported.suite,
    privateKey,
    sender.encapsulatedKey,
    {
      info: undefined,
    });
  const ciphertext = sender.seal(plaintext, undefined);

  assert.deepStrictEqual(recipient.open(ciphertext, undefined), plaintext);
}

{
  const supported = p256Supported;
  const { publicKey, privateKey } = supported.keys;
  const sender = createSender(supported.suite, publicKey);
  const recipient =
    createRecipient(supported.suite, privateKey, sender.encapsulatedKey);
  const first = sender.seal(Buffer.from('first'));
  const second = sender.seal(Buffer.from('second'));

  assertExactError(() => recipient.open(second), kOpenSSLInternalError);

  const orderedRecipient =
    createRecipient(supported.suite, privateKey, sender.encapsulatedKey);
  assert.deepStrictEqual(orderedRecipient.open(first), Buffer.from('first'));
  assert.deepStrictEqual(orderedRecipient.open(second), Buffer.from('second'));
}

{
  const supported = p256Supported;
  const { publicKey, privateKey } = supported.keys;
  const sender = createSender(
    supported.suite,
    publicKey,
    { psk: Buffer.alloc(32, 1), pskId: Buffer.from('id') });
  const recipient = createRecipient(
    supported.suite,
    privateKey,
    sender.encapsulatedKey,
    { psk: Buffer.alloc(32, 2), pskId: Buffer.from('id') });
  const ciphertext = sender.seal(Buffer.from('plaintext'));

  assertExactError(() => recipient.open(ciphertext), kOpenSSLInternalError);
}

{
  const exportOnlySupported = {
    ...p256Supported,
    suite: {
      ...p256Supported.suite,
      aeadId: constants.AEAD_EXPORT_ONLY,
    },
  };

  if (hpke.isSuiteSupported(exportOnlySupported.suite)) {
    const { publicKey, privateKey } = exportOnlySupported.keys;
    const sender = createSender(exportOnlySupported.suite, publicKey);
    const recipient = createRecipient(
      exportOnlySupported.suite,
      privateKey,
      sender.encapsulatedKey);

    assert.strictEqual(sender.export(Buffer.from('label'), 32).type, 'secret');
    assert.throws(() => sender.seal(Buffer.from('plaintext')), {
      code: 'ERR_CRYPTO_INVALID_STATE',
    });
    assert.throws(() => recipient.open(Buffer.from('ciphertext')), {
      code: 'ERR_CRYPTO_INVALID_STATE',
    });

    const senderExport = hpke.sendExport(
      exportOnlySupported.suite,
      publicKey,
      Buffer.from('label'),
      32);
    const recipientExport = hpke.receiveExport(
      exportOnlySupported.suite,
      privateKey,
      senderExport.encapsulatedKey,
      Buffer.from('label'),
      32);

    assert(senderExport.exportedSecret.equals(recipientExport));
    assert.throws(() => hpke.seal(
      exportOnlySupported.suite,
      publicKey,
      Buffer.from('plaintext')), {
      code: 'ERR_CRYPTO_INVALID_STATE',
    });
    assert.throws(() => hpke.open(
      exportOnlySupported.suite,
      privateKey,
      sender.encapsulatedKey,
      Buffer.from('ciphertext')), {
      code: 'ERR_CRYPTO_INVALID_STATE',
    });
  }
}

{
  const supported = p256Supported;
  const { publicKey, privateKey } = supported.keys;
  const sender = createSender(supported.suite, publicKey, {
    info: Buffer.alloc(constants.MAX_INFO_LENGTH),
    psk: Buffer.alloc(constants.MAX_PARAMETER_LENGTH, 1),
    pskId: Buffer.alloc(constants.MAX_PARAMETER_LENGTH, 1),
  });
  const recipient = createRecipient(
    supported.suite,
    privateKey,
    sender.encapsulatedKey,
    {
      info: Buffer.alloc(constants.MAX_INFO_LENGTH),
      psk: Buffer.alloc(constants.MAX_PARAMETER_LENGTH, 1),
      pskId: Buffer.alloc(constants.MAX_PARAMETER_LENGTH, 1),
    });
  const ciphertext = sender.seal(Buffer.from('limits'), Buffer.alloc(0));

  assert.deepStrictEqual(recipient.open(ciphertext), Buffer.from('limits'));

  assert.throws(() => new hpke.SenderContext(), {
    code: 'ERR_ILLEGAL_CONSTRUCTOR',
  });
  assert.throws(() => new hpke.RecipientContext(), {
    code: 'ERR_ILLEGAL_CONSTRUCTOR',
  });
  assertExactError(() => hpke.createRecipientContext(
    supported.suite,
    privateKey,
    Buffer.alloc(0)), kOpenSSLInvalidArgument);
  assertExactError(() => {
    sender.export(Buffer.alloc(constants.MAX_PARAMETER_LENGTH + 1), 32);
  }, kOutOfRange(
    'label.byteLength',
    0,
    constants.MAX_PARAMETER_LENGTH,
    constants.MAX_PARAMETER_LENGTH + 1));
  assert.strictEqual(
    sender.export(Buffer.alloc(constants.MAX_PARAMETER_LENGTH), 1).type,
    'secret');
  assertExactError(
    () => sender.export(Buffer.alloc(0), 255 * 32 + 1),
    kOpenSSLFailedDuringDerivation);
  assertExactError(
    () => sender.seal(Buffer.alloc(0)),
    kOpenSSLInvalidArgument);
  assert.strictEqual(hpke.getCiphertextSize(supported.suite, 0), 16);
  assert.strictEqual(hpke.getCiphertextSize(supported.suite, 1), 17);
  assert.strictEqual(
    hpke.getCiphertextSize(supported.suite, MAX_LENGTH - 16),
    MAX_LENGTH);
  assert.throws(
    () => hpke.getCiphertextSize(supported.suite, MAX_LENGTH - 15),
    { code: 'ERR_BUFFER_TOO_LARGE' });
  assert.throws(
    () => hpke.getCiphertextSize(supported.suite, MAX_LENGTH + 1),
    { code: 'ERR_OUT_OF_RANGE' });
  assert.throws(
    () => sender.export(Buffer.alloc(0), MAX_LENGTH + 1),
    { code: 'ERR_OUT_OF_RANGE' });
}

{
  const supported = p256Supported;
  const kdfIds = [
    constants.KDF_HKDF_SHA256,
    constants.KDF_HKDF_SHA384,
    constants.KDF_HKDF_SHA512,
  ];

  for (const kdfId of kdfIds) {
    const suite = { ...supported.suite, kdfId };
    if (!hpke.isSuiteSupported(suite))
      continue;

    const { publicKey } = supported.keys;
    const sender = createSender(suite, publicKey);
    const maxExportLength = 255 * kdfHashLength(kdfId);

    assert.strictEqual(
      sender.export(Buffer.alloc(0), maxExportLength).symmetricKeySize,
      maxExportLength);
    assertExactError(
      () => sender.export(Buffer.alloc(0), maxExportLength + 1),
      kOpenSSLFailedDuringDerivation);
  }
}

{
  const supported = p256Supported;
  const { publicKey, privateKey } = supported.keys;
  const options = {
    info: createArrayBuffer(constants.MAX_INFO_LENGTH, 1),
    psk: createArrayBuffer(constants.MIN_PSK_LENGTH, 2),
    pskId: createArrayBuffer(constants.MAX_PARAMETER_LENGTH, 3),
  };
  const sender = createSender(supported.suite, publicKey, options);
  const recipient = createRecipient(
    supported.suite,
    privateKey,
    sender.encapsulatedKey,
    options);
  const plaintext = createArrayBuffer(1, 4);
  const aad = createArrayBuffer(0);
  const ciphertext = sender.seal(plaintext, aad);
  const label = createArrayBuffer(constants.MAX_PARAMETER_LENGTH, 5);

  assert.deepStrictEqual(recipient.open(ciphertext, aad), Buffer.from([4]));
  assert.strictEqual(sender.export(label, 1).type, 'secret');
  assert.throws(() => createSender(supported.suite, publicKey, {
    info: new SharedArrayBuffer(0),
  }), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assert.throws(() => hpke.createSenderContext(
    supported.suite,
    publicKey,
    {
      psk: createArrayBuffer(constants.MIN_PSK_LENGTH, 1),
      pskId: createArrayBuffer(1),
    }), {
    code: 'ERR_INVALID_ARG_VALUE',
  });
}

{
  const supported = p256Supported;
  const { publicKey } = supported.keys;
  const { suite } = supported;

  assert.throws(() => hpke.createSenderContext(suite, publicKey, {
    info: 'info',
  }), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assert.throws(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(32, 1),
  }), {
    code: 'ERR_MISSING_OPTION',
  });
  assert.throws(() => hpke.createSenderContext(suite, publicKey, {
    pskId: Buffer.from('id'),
  }), {
    code: 'ERR_MISSING_OPTION',
  });
  assert.throws(() => hpke.createSenderContext(suite, publicKey, {
    psk: 'psk',
    pskId: Buffer.from('id'),
  }), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assertExactError(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(constants.MIN_PSK_LENGTH - 1),
    pskId: Buffer.from('id'),
  }), kOutOfRange(
    'options.psk.byteLength',
    constants.MIN_PSK_LENGTH,
    constants.MAX_PARAMETER_LENGTH,
    constants.MIN_PSK_LENGTH - 1));
  assertExactError(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(constants.MAX_PARAMETER_LENGTH + 1),
    pskId: Buffer.from('id'),
  }), kOutOfRange(
    'options.psk.byteLength',
    constants.MIN_PSK_LENGTH,
    constants.MAX_PARAMETER_LENGTH,
    constants.MAX_PARAMETER_LENGTH + 1));
  assertExactError(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(32),
    pskId: Buffer.alloc(0),
  }), kOutOfRange(
    'options.pskId.byteLength',
    1,
    constants.MAX_PARAMETER_LENGTH,
    0));
  assertExactError(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(32),
    pskId: Buffer.alloc(constants.MAX_PARAMETER_LENGTH + 1, 1),
  }), kOutOfRange(
    'options.pskId.byteLength',
    1,
    constants.MAX_PARAMETER_LENGTH,
    constants.MAX_PARAMETER_LENGTH + 1));
  assert.throws(() => hpke.createSenderContext(suite, publicKey, {
    psk: Buffer.alloc(32),
    pskId: Buffer.from([1, 0, 2]),
  }), {
    code: 'ERR_INVALID_ARG_VALUE',
  });
  assertExactError(() => hpke.createSenderContext(suite, publicKey, {
    info: Buffer.alloc(constants.MAX_INFO_LENGTH + 1),
  }), kOutOfRange(
    'options.info.byteLength',
    0,
    constants.MAX_INFO_LENGTH,
    constants.MAX_INFO_LENGTH + 1));
}

{
  const supported = p256Supported;
  const { publicKeyPem, privateKeyPem } = supported.keys;
  const sender = createSender(supported.suite, publicKeyPem);
  const recipient =
    createRecipient(supported.suite, privateKeyPem, sender.encapsulatedKey);
  const ciphertext = sender.seal(Buffer.from('key strings are accepted'));

  assert.deepStrictEqual(
    recipient.open(ciphertext),
    Buffer.from('key strings are accepted'));
  assert.throws(() => sender.seal('plaintext'), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assert.throws(() => sender.export('label', 32), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assert.throws(() => recipient.open('ciphertext'), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
}

{
  const unsupportedSuite = {
    kemId: 0,
    kdfId: constants.KDF_HKDF_SHA256,
    aeadId: constants.AEAD_AES_128_GCM,
  };
  const supported = p256Supported;
  const { publicKey } = supported.keys;

  assert.strictEqual(hpke.isSuiteSupported(unsupportedSuite), false);
  assert.strictEqual(hpke.getPublicEncapSize(unsupportedSuite), 0);
  assert.strictEqual(hpke.getCiphertextSize(unsupportedSuite, 1), 0);
  assertExactError(
    () => hpke.createSenderContext(unsupportedSuite, publicKey),
    kUnsupportedHPKESuite);
  assert.throws(() => hpke.isSuiteSupported({
    kemId: '0',
    kdfId: constants.KDF_HKDF_SHA256,
    aeadId: constants.AEAD_AES_128_GCM,
  }), {
    code: 'ERR_INVALID_ARG_TYPE',
  });
  assert.throws(() => hpke.isSuiteSupported({
    kemId: 0x10000,
    kdfId: constants.KDF_HKDF_SHA256,
    aeadId: constants.AEAD_AES_128_GCM,
  }), {
    code: 'ERR_OUT_OF_RANGE',
  });
}
