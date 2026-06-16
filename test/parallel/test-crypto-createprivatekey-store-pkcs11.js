'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL3 } = require('../common/crypto');
if (!hasOpenSSL3)
  common.skip('this test requires OpenSSL 3.x');

if (process.env.NODE_TEST_PKCS11_PROVIDER !== '1' &&
    process.env.NODE_TEST_PKCS11_PROVIDER_CHILD !== '1') {
  common.skip('missing external pkcs11 test provider');
}

const tmpdir = require('../common/tmpdir');
const assert = require('node:assert');
const { execFileSync, fork } = require('node:child_process');
const fs = require('node:fs');
const {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  publicEncrypt,
  sign,
  verify,
} = require('node:crypto');

const kPin = '1234';

function assertNotExportable(fn) {
  assert.throws(fn, {
    code: 'ERR_CRYPTO_KEY_NOT_EXPORTABLE',
  });
}

function assertToCryptoKey(key, algorithm) {
  assert.throws(
    () => key.toCryptoKey(algorithm, true, ['sign']),
    { code: 'ERR_CRYPTO_KEY_NOT_EXPORTABLE' });

  const cryptoKey = key.toCryptoKey(algorithm, false, ['sign']);
  assert.strictEqual(cryptoKey.type, 'private');
  assert.strictEqual(cryptoKey.extractable, false);
}

function assertPublicUseRejected(key, verifyAlgorithm) {
  assertNotExportable(() => createPublicKey(key));
  assertNotExportable(() => verify(
    verifyAlgorithm,
    Buffer.from('public use'),
    key,
    Buffer.alloc(0)));
  assertNotExportable(() => publicEncrypt(key, Buffer.from('public use')));
  assertNotExportable(() => diffieHellman({
    privateKey: key,
    publicKey: key,
  }));
}

if (process.env.NODE_TEST_PKCS11_PROVIDER_CHILD !== '1') {
  const provider = process.env.NODE_TEST_PKCS11_PROVIDER_MODULE;
  const softhsm = process.env.NODE_TEST_SOFTHSM_MODULE;

  if (provider === undefined || softhsm === undefined) {
    common.skip('missing pkcs11-provider or SoftHSM module path');
  }

  tmpdir.refresh();
  const tokenDir = tmpdir.resolve('tokens');
  fs.mkdirSync(tokenDir);

  const softhsmConf = tmpdir.resolve('softhsm2.conf');
  fs.writeFileSync(softhsmConf, `
directories.tokendir = ${tokenDir}
objectstore.backend = file
log.level = ERROR
slots.removable = false
`);

  const opensslConf = tmpdir.resolve('openssl-pkcs11.cnf');
  fs.writeFileSync(opensslConf, `
nodejs_conf = nodejs_init

[nodejs_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = ${provider}
pkcs11-module-path = ${softhsm}
activate = 1
`);

  const env = {
    ...process.env,
    SOFTHSM2_CONF: softhsmConf,
  };

  execFileSync('softhsm2-util', [
    '--init-token',
    '--free',
    '--label',
    'node-test',
    '--pin',
    kPin,
    '--so-pin',
    kPin,
  ], { env });

  for (const [keyType, id, label] of [
    ['RSA:2048', '01', 'node-rsa'],
    ['EC:prime256v1', '02', 'node-ec'],
    ['EC:ED25519', '03', 'node-ed25519'],
    ['EC:ED448', '04', 'node-ed448'],
  ]) {
    execFileSync('pkcs11-tool', [
      '--module',
      softhsm,
      '--login',
      '--pin',
      kPin,
      '--keypairgen',
      '--key-type',
      keyType,
      '--id',
      id,
      '--label',
      label,
      '--usage-sign',
    ], { env });
  }

  const child = fork(__filename, {
    execArgv: [
      `--openssl-config=${opensslConf}`,
      '--permission',
      '--allow-crypto-store',
      '--allow-fs-read=*',
    ],
    env: {
      ...env,
      NODE_TEST_PKCS11_PROVIDER_CHILD: '1',
    },
  });
  child.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(code, 0);
    assert.strictEqual(signal, null);
  }));
  return;
}

function loadPrivateKey(label) {
  return createPrivateKey({
    key: new URL(`pkcs11:object=${label};type=private`),
    passphrase: kPin,
  });
}

async function testRsa() {
  const key = loadPrivateKey('node-rsa');
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.asymmetricKeyType, 'rsa');
  assert.strictEqual(key.asymmetricKeyDetails.modulusLength, 2048);
  assert.strictEqual(key.asymmetricKeyDetails.publicExponent, 65537n);

  const data = Buffer.from('pkcs11 rsa');
  const signature = sign('sha256', data, key);
  assert(signature.byteLength > 0);
  assertPublicUseRejected(key, 'sha256');

  assertNotExportable(() => key.export({ format: 'der', type: 'pkcs8' }));
  assertNotExportable(() => key.export({ format: 'jwk' }));

  assertToCryptoKey(key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' });
}

async function testEc() {
  const key = loadPrivateKey('node-ec');
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.asymmetricKeyType, 'ec');
  assert.strictEqual(key.asymmetricKeyDetails.namedCurve, 'prime256v1');

  assertPublicUseRejected(key, 'sha256');

  assertNotExportable(() => key.export({ format: 'raw-private' }));
  assertNotExportable(() => key.export({ format: 'der', type: 'pkcs8' }));
  assertNotExportable(() => key.export({ format: 'jwk' }));

  assertToCryptoKey(key, { name: 'ECDSA', namedCurve: 'P-256' });
}

async function testEd25519() {
  const key = loadPrivateKey('node-ed25519');
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.asymmetricKeyType, 'ed25519');
  assert.deepStrictEqual(key.asymmetricKeyDetails, {});

  const data = Buffer.from('pkcs11 ed25519');
  const signature = sign(null, data, key);
  assert(signature.byteLength > 0);
  assertPublicUseRejected(key, null);

  assertNotExportable(() => key.export({ format: 'raw-private' }));
  assertNotExportable(() => key.export({ format: 'der', type: 'pkcs8' }));
  assertNotExportable(() => key.export({ format: 'jwk' }));

  assertToCryptoKey(key, { name: 'Ed25519' });
}

function testEd448() {
  const key = loadPrivateKey('node-ed448');
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.asymmetricKeyType, 'ed448');
  assert.deepStrictEqual(key.asymmetricKeyDetails, {});

  const data = Buffer.from('pkcs11 ed448');
  const signature = sign(null, data, key);
  assert(signature.byteLength > 0);
  assertPublicUseRejected(key, null);

  assertNotExportable(() => key.export({ format: 'raw-private' }));
  assertNotExportable(() => key.export({ format: 'der', type: 'pkcs8' }));
  assertNotExportable(() => key.export({ format: 'jwk' }));
}

(async () => {
  await testRsa();
  await testEc();
  await testEd25519();
  testEd448();
})().then(common.mustCall());
