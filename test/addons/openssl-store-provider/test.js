'use strict';

const common = require('../../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL, hasOpenSSL3 } = require('../../common/crypto');
if (!hasOpenSSL3)
  common.skip('this test requires OpenSSL 3.x');

const tmpdir = require('../../common/tmpdir');
const fixtures = require('../../common/fixtures');
const assert = require('node:assert');
const { fork } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const provider = path.join(
  __dirname,
  'build',
  common.buildType,
  'nodejs_test_store_provider.so');

if (!fs.existsSync(provider))
  common.skip('missing OpenSSL STORE provider');

if (process.env.NODE_TEST_STORE_PROVIDER_CHILD !== '1') {
  tmpdir.refresh();
  const conf = path.join(tmpdir.path, 'openssl-store-provider.cnf');
  fs.writeFileSync(conf, `
nodejs_conf = nodejs_init

[nodejs_init]
providers = provider_sect

[provider_sect]
default = default_sect
nodejs_test_store = nodejs_test_store_sect

[default_sect]
activate = 1

[nodejs_test_store_sect]
module = ${provider}
activate = 1
`);

  const child = fork(__filename, {
    execArgv: [
      `--openssl-config=${conf}`,
      '--permission',
      '--allow-crypto-store',
      '--allow-fs-read=*',
    ],
    env: {
      ...process.env,
      NODE_TEST_STORE_PROVIDER_CHILD: '1',
      NODE_TEST_STORE_PROVIDER_FIXTURE_ROOT: fixtures.fixturesDir,
    },
  });
  child.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(code, 0);
    assert.strictEqual(signal, null);
  }));
  return;
}

const {
  createPrivateKey,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  privateDecrypt,
  publicEncrypt,
  sign,
  verify,
} = require('node:crypto');

const data = Buffer.from('store-backed key operation');

function storeKey(name) {
  return createPrivateKey(new URL(`nodejs-test-store:${name}`));
}

function fixturePublicKey(name) {
  return createPublicKey(fixtures.readKey(name));
}

function fixturePrivateKey(name) {
  return createPrivateKey(fixtures.readKey(name));
}

function assertNotExportable(fn) {
  assert.throws(fn, {
    code: 'ERR_CRYPTO_KEY_NOT_EXPORTABLE',
  });
}

function assertStoreBackedPrivateKey(key, type, details = undefined) {
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.asymmetricKeyType, type);
  if (details !== undefined)
    assert.deepStrictEqual(key.asymmetricKeyDetails, details);

  assertNotExportable(() => createPublicKey(key));
  assertNotExportable(() => key.export({ format: 'der', type: 'pkcs8' }));
  assertNotExportable(() => key.export({ format: 'jwk' }));
}

function assertToCryptoKey(key, algorithm, usages, operation) {
  assertToCryptoKeyNotExportable(key, algorithm, usages);

  const cryptoKey = key.toCryptoKey(algorithm, false, usages);
  assert.strictEqual(cryptoKey.type, 'private');
  assert.strictEqual(cryptoKey.extractable, false);

  return operation?.(cryptoKey);
}

function assertToCryptoKeyNotExportable(key, algorithm, usages) {
  assert.throws(
    () => key.toCryptoKey(algorithm, true, usages),
    { code: 'ERR_CRYPTO_KEY_NOT_EXPORTABLE' });
}

function assertSignVerify(key, publicKey, algorithm = 'sha256', options = {}) {
  const signature = sign(algorithm, data, { key, ...options });
  assert.strictEqual(
    verify(algorithm, data, { key: publicKey, ...options }, signature),
    true);
  assertNotExportable(
    () => verify(algorithm, data, { key, ...options }, signature));
  return signature;
}

function assertDiffieHellman(key, publicKey, fixturePrivate) {
  assert.deepStrictEqual(
    diffieHellman({ privateKey: key, publicKey }),
    diffieHellman({ privateKey: fixturePrivate, publicKey }));
  assertNotExportable(() => diffieHellman({
    privateKey: fixturePrivate,
    publicKey: key,
  }));
}

(async () => {
  {
    const key = storeKey('rsa');
    const publicKey = fixturePublicKey('rsa_public_2048.pem');

    assertStoreBackedPrivateKey(key, 'rsa', {
      modulusLength: 2048,
      publicExponent: 65537n,
    });

    assertSignVerify(key, publicKey);

    const ciphertext = publicEncrypt(publicKey, data);
    assert.deepStrictEqual(privateDecrypt(key, ciphertext), data);
    assertNotExportable(() => publicEncrypt(key, data));

    await assertToCryptoKey(
      key,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      ['sign'],
      common.mustCall(async (cryptoKey) => {
        const signature = Buffer.from(await globalThis.crypto.subtle.sign(
          'RSASSA-PKCS1-v1_5',
          cryptoKey,
          data));
        assert.strictEqual(verify('sha256', data, publicKey, signature), true);
      }));
  }

  {
    const key = storeKey('rsa-pss');
    const publicKey =
      fixturePublicKey('rsa_pss_public_2048_sha256_sha256_16.pem');

    assertStoreBackedPrivateKey(key, 'rsa-pss', {
      modulusLength: 2048,
      publicExponent: 65537n,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
      saltLength: 16,
    });

    assertSignVerify(key, publicKey);

    // Regular RSA-PSS KeyObjects cannot be converted to WebCrypto either.
    assertToCryptoKeyNotExportable(
      key,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      ['sign']);
  }

  {
    const key = storeKey('dsa');
    const publicKey = fixturePublicKey('dsa_public.pem');

    assertStoreBackedPrivateKey(key, 'dsa', {
      modulusLength: 2048,
      divisorLength: 256,
    });

    assertSignVerify(key, publicKey);
  }

  {
    const key = storeKey('dh');
    const publicKey = fixturePublicKey('dh_public.pem');
    const privateKey = fixturePrivateKey('dh_private.pem');

    assertStoreBackedPrivateKey(key, 'dh', {});
    assertDiffieHellman(key, publicKey, privateKey);
  }

  {
    const key = storeKey('ec-p256');
    const publicKey = fixturePublicKey('ec_p256_public.pem');
    const privateKey = fixturePrivateKey('ec_p256_private.pem');

    assertStoreBackedPrivateKey(key, 'ec', { namedCurve: 'prime256v1' });
    assertSignVerify(key, publicKey);
    assertDiffieHellman(key, publicKey, privateKey);

    await assertToCryptoKey(
      key,
      { name: 'ECDSA', namedCurve: 'P-256' },
      ['sign'],
      common.mustCall(async (cryptoKey) => {
        const signature = Buffer.from(await globalThis.crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          cryptoKey,
          data));
        assert.strictEqual(
          verify(
            'sha256',
            data,
            { key: publicKey, dsaEncoding: 'ieee-p1363' },
            signature),
          true);
      }));
  }

  for (const [name, fixture, algorithm] of [
    ['ed25519', 'ed25519_public.pem', 'Ed25519'],
    ['ed448', 'ed448_public.pem', 'Ed448'],
  ]) {
    const key = storeKey(name);
    const publicKey = fixturePublicKey(fixture);

    assertStoreBackedPrivateKey(key, name, {});
    assertSignVerify(key, publicKey, null);

    await assertToCryptoKey(key, algorithm, ['sign'], common.mustCall(async (cryptoKey) => {
      const signature = Buffer.from(await globalThis.crypto.subtle.sign(
        algorithm,
        cryptoKey,
        data));
      assert.strictEqual(verify(null, data, publicKey, signature), true);
    }));
  }

  for (const [name, fixturePublic, fixturePrivate, algorithm] of [
    ['x25519', 'x25519_public.pem', 'x25519_private.pem', 'X25519'],
    ['x448', 'x448_public.pem', 'x448_private.pem', 'X448'],
  ]) {
    const key = storeKey(name);
    const publicKey = fixturePublicKey(fixturePublic);
    const privateKey = fixturePrivateKey(fixturePrivate);

    assertStoreBackedPrivateKey(key, name, {});
    assertDiffieHellman(key, publicKey, privateKey);

    await assertToCryptoKey(
      key,
      algorithm,
      ['deriveBits'],
      common.mustCall(async (cryptoKey) => {
        const publicCryptoKey = publicKey.toCryptoKey(
          algorithm,
          true,
          []);
        const bits = await globalThis.crypto.subtle.deriveBits(
          { name: algorithm, public: publicCryptoKey },
          cryptoKey,
          null);
        assert(bits.byteLength > 0);
      }));
  }

  if (hasOpenSSL(3, 5)) {
    {
      const key = storeKey('ml-kem-768');
      const publicKey = fixturePublicKey('ml_kem_768_public.pem');

      assertStoreBackedPrivateKey(key, 'ml-kem-768', {});

      const { sharedKey, ciphertext } = encapsulate(publicKey);
      assert.deepStrictEqual(decapsulate(key, ciphertext), sharedKey);
      assertNotExportable(() => encapsulate(key));

      await assertToCryptoKey(
        key,
        { name: 'ML-KEM-768' },
        ['decapsulateBits'],
        common.mustCall(async (cryptoKey) => {
          const publicCryptoKey = publicKey.toCryptoKey(
            { name: 'ML-KEM-768' },
            true,
            ['encapsulateBits']);
          const result = await globalThis.crypto.subtle.encapsulateBits(
            { name: 'ML-KEM-768' },
            publicCryptoKey);
          const bits = await globalThis.crypto.subtle.decapsulateBits(
            { name: 'ML-KEM-768' },
            cryptoKey,
            result.ciphertext);
          assert.deepStrictEqual(
            Buffer.from(bits),
            Buffer.from(result.sharedKey));
        }));
    }

    {
      const key = storeKey('ml-dsa-44');
      const publicKey = fixturePublicKey('ml_dsa_44_public.pem');

      assertStoreBackedPrivateKey(key, 'ml-dsa-44', {});
      assertSignVerify(key, publicKey, null);

      await assertToCryptoKey(
        key,
        { name: 'ML-DSA-44' },
        ['sign'],
        common.mustCall(async (cryptoKey) => {
          const signature = Buffer.from(await globalThis.crypto.subtle.sign(
            { name: 'ML-DSA-44' },
            cryptoKey,
            data));
          assert.strictEqual(verify(null, data, publicKey, signature), true);
        }));
    }

    {
      const key = storeKey('slh-dsa-sha2-128f');
      const publicKey = fixturePublicKey('slh_dsa_sha2_128f_public.pem');

      assertStoreBackedPrivateKey(key, 'slh-dsa-sha2-128f', {});
      assertSignVerify(key, publicKey, null);
    }
  }
})().then(common.mustCall());
