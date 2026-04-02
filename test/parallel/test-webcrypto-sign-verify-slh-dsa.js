'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3, 5))
  common.skip('requires OpenSSL >= 3.5');

const assert = require('assert');
const crypto = require('crypto');
const { subtle } = globalThis.crypto;

const fixtures = require('../common/fixtures');

function getKeyFileName(type, suffix) {
  return `${type.replaceAll('-', '_')}_${suffix}.pem`;
}

// Use only the fast 128f variants for parallel tests
const algorithms = ['SLH-DSA-SHA2-128f', 'SLH-DSA-SHAKE-128f'];

const data = Buffer.from(
  '2b7ed0bc7795694ab4acd35903fe8cd7d80f6a1c8688a6c3414409457514a1457855bb' +
  'b219e30a1beea8fe869082d99fc8282f9050d024e59eaf0730ba9db70a', 'hex');

async function testSignVerifyRoundtrip(name) {
  const lcName = name.toLowerCase();
  const privPem = fixtures.readKey(getKeyFileName(lcName, 'private'), 'ascii');
  const pubPem = fixtures.readKey(getKeyFileName(lcName, 'public'), 'ascii');

  const [publicKey, privateKey] = await Promise.all([
    crypto.createPublicKey(pubPem).toCryptoKey(name, false, ['verify']),
    crypto.createPrivateKey(privPem).toCryptoKey(name, false, ['sign']),
  ]);

  // Sign and verify
  const sig = await subtle.sign({ name }, privateKey, data);
  assert(sig.byteLength > 0);
  assert(await subtle.verify({ name }, publicKey, sig, data));

  // Verify with altered data fails
  const alteredData = Buffer.from(data);
  alteredData[0] = 255 - alteredData[0];
  assert(!(await subtle.verify({ name }, publicKey, sig, alteredData)));

  // Verify with altered signature fails
  const alteredSig = Buffer.from(sig);
  alteredSig[0] = 255 - alteredSig[0];
  assert(!(await subtle.verify({ name }, publicKey, alteredSig, data)));

  // Verify with truncated signature fails
  assert(!(await subtle.verify({ name }, publicKey, alteredSig.slice(1), data)));
}

async function testSignVerifyWithContext(name) {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name },
    false,
    ['sign', 'verify']);

  // Test with context
  const context = crypto.randomBytes(32);
  const sig = await subtle.sign({ name, context }, privateKey, data);
  assert(await subtle.verify({ name, context }, publicKey, sig, data));

  // Wrong context should fail
  assert(!(await subtle.verify(
    { name, context: crypto.randomBytes(32) },
    publicKey, sig, data)));

  // Empty context
  const sigNoCtx = await subtle.sign({ name, context: new Uint8Array(0) }, privateKey, data);
  assert(await subtle.verify({ name, context: new Uint8Array(0) }, publicKey, sigNoCtx, data));
  // With no context parameter should also verify (equivalent to empty context)
  assert(await subtle.verify({ name }, publicKey, sigNoCtx, data));
}

async function testSignVerifyWrongKeyUsage(name) {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name },
    false,
    ['sign', 'verify']);

  // Can't sign with public key
  await assert.rejects(
    subtle.sign({ name }, publicKey, data), {
      message: /Unable to use this key to sign/,
    });

  // Can't verify with private key
  await assert.rejects(
    subtle.verify({ name }, privateKey, Buffer.alloc(100), data), {
      message: /Unable to use this key to verify/,
    });
}

async function testSignVerifyWrongAlgorithm(name) {
  const hmacKey = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']);

  const rsaKeys = await subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    ['sign']);

  const ecKeys = await subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false,
    ['sign']);

  await assert.rejects(
    subtle.verify({ name }, hmacKey, Buffer.alloc(100), data), {
      message: /Unable to use this key to verify/,
    });

  await assert.rejects(
    subtle.verify({ name }, rsaKeys.publicKey, Buffer.alloc(100), data), {
      message: /Unable to use this key to verify/,
    });

  await assert.rejects(
    subtle.verify({ name }, ecKeys.publicKey, Buffer.alloc(100), data), {
      message: /Unable to use this key to verify/,
    });
}

async function testContextTooLong(name) {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name },
    false,
    ['sign', 'verify']);

  await assert.rejects(
    subtle.sign({ name, context: new Uint8Array(256) }, privateKey, data), (err) => {
      assert.strictEqual(err.name, 'OperationError');
      assert.strictEqual(err.cause.code, 'ERR_OUT_OF_RANGE');
      assert.strictEqual(err.cause.message, 'context string must be at most 255 bytes');
      return true;
    });

  await assert.rejects(
    subtle.verify({ name, context: new Uint8Array(256) }, publicKey, Buffer.alloc(100), data), (err) => {
      assert.strictEqual(err.name, 'OperationError');
      assert.strictEqual(err.cause.code, 'ERR_OUT_OF_RANGE');
      assert.strictEqual(err.cause.message, 'context string must be at most 255 bytes');
      return true;
    });
}

async function testNoVerifyUsage(name) {
  const lcName = name.toLowerCase();
  const pubPem = fixtures.readKey(getKeyFileName(lcName, 'public'), 'ascii');
  const noVerifyKey = await crypto.createPublicKey(pubPem)
    .toCryptoKey(name, false, [/* No usages */]);

  const privPem = fixtures.readKey(getKeyFileName(lcName, 'private'), 'ascii');
  const privateKey = await crypto.createPrivateKey(privPem)
    .toCryptoKey(name, false, ['sign']);

  const sig = await subtle.sign({ name }, privateKey, data);

  await assert.rejects(
    subtle.verify({ name }, noVerifyKey, sig, data), {
      message: /Unable to use this key to verify/,
    });
}

async function testSignBufferCopiedBeforeSign(name) {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name },
    false,
    ['sign', 'verify']);

  const copy = Buffer.from(data);
  const p = subtle.sign({ name }, privateKey, copy);
  copy[0] = 255 - copy[0];
  const sig = await p;
  assert(await subtle.verify({ name }, publicKey, sig, data));
}

(async function() {
  const tests = [];
  for (const name of algorithms) {
    tests.push(testSignVerifyRoundtrip(name));
    tests.push(testSignVerifyWithContext(name));
    tests.push(testSignVerifyWrongKeyUsage(name));
    tests.push(testSignVerifyWrongAlgorithm(name));
    tests.push(testContextTooLong(name));
    tests.push(testNoVerifyUsage(name));
    tests.push(testSignBufferCopiedBeforeSign(name));
  }
  await Promise.all(tests);
})().then(common.mustCall());
