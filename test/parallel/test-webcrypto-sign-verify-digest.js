'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

const assert = require('assert');
const crypto = require('crypto');
const { subtle } = globalThis.crypto;

// Test signDigest/verifyDigest for RSASSA-PKCS1-v1_5
async function testRSASSA() {
  const { publicKey, privateKey } = await subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, false, ['sign', 'verify']);

  const data = Buffer.from('test data');
  const digest = crypto.createHash('sha256').update(data).digest();

  // Sign the pre-computed digest
  const sig = await subtle.signDigest('RSASSA-PKCS1-v1_5', privateKey, digest);
  assert(sig instanceof ArrayBuffer);
  assert(sig.byteLength > 0);

  // Verify the signature against the pre-computed digest
  assert(await subtle.verifyDigest('RSASSA-PKCS1-v1_5', publicKey, sig, digest));

  // Cross-verify: signDigest output should be verifiable with verify (same signature scheme)
  assert(await subtle.verify('RSASSA-PKCS1-v1_5', publicKey, sig, data));

  // Cross-verify: sign output should be verifiable with verifyDigest
  const sig2 = await subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);
  assert(await subtle.verifyDigest('RSASSA-PKCS1-v1_5', publicKey, sig2, digest));

  // Tampered digest should fail
  const badDigest = Buffer.from(digest);
  badDigest[0] ^= 0xff;
  assert(!await subtle.verifyDigest('RSASSA-PKCS1-v1_5', publicKey, sig, badDigest));

  // Wrong digest length should fail
  await assert.rejects(
    subtle.signDigest('RSASSA-PKCS1-v1_5', privateKey, Buffer.alloc(20)),
    { name: 'OperationError' }
  );

  // Wrong key type should fail
  await assert.rejects(
    subtle.signDigest('RSASSA-PKCS1-v1_5', publicKey, digest),
    { message: /Unable to use this key to sign/ }
  );

  await assert.rejects(
    subtle.verifyDigest('RSASSA-PKCS1-v1_5', privateKey, sig, digest),
    { message: /Unable to use this key to verify/ }
  );
}

// Test signDigest/verifyDigest for RSA-PSS
async function testRSAPSS() {
  const { publicKey, privateKey } = await subtle.generateKey({
    name: 'RSA-PSS',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, false, ['sign', 'verify']);

  const data = Buffer.from('test data');
  const digest = crypto.createHash('sha256').update(data).digest();
  const algorithm = { name: 'RSA-PSS', saltLength: 32 };

  // Sign the pre-computed digest
  const sig = await subtle.signDigest(algorithm, privateKey, digest);
  assert(sig instanceof ArrayBuffer);
  assert(sig.byteLength > 0);

  // Verify the signature against the pre-computed digest
  assert(await subtle.verifyDigest(algorithm, publicKey, sig, digest));

  // Cross-verify: signDigest output should be verifiable with verify
  assert(await subtle.verify(algorithm, publicKey, sig, data));

  // Cross-verify: sign output should be verifiable with verifyDigest
  const sig2 = await subtle.sign(algorithm, privateKey, data);
  assert(await subtle.verifyDigest(algorithm, publicKey, sig2, digest));

  // Tampered digest should fail
  const badDigest = Buffer.from(digest);
  badDigest[0] ^= 0xff;
  assert(!await subtle.verifyDigest(algorithm, publicKey, sig, badDigest));

  // Wrong digest length should fail
  await assert.rejects(
    subtle.signDigest(algorithm, privateKey, Buffer.alloc(48)),
    { name: 'OperationError' }
  );
}

// Test signDigest/verifyDigest for ECDSA
async function testECDSA() {
  for (const { namedCurve, hash, digestSize } of [
    { namedCurve: 'P-256', hash: 'SHA-256', digestSize: 32 },
    { namedCurve: 'P-384', hash: 'SHA-384', digestSize: 48 },
    { namedCurve: 'P-521', hash: 'SHA-512', digestSize: 64 },
  ]) {
    const { publicKey, privateKey } = await subtle.generateKey({
      name: 'ECDSA',
      namedCurve,
    }, false, ['sign', 'verify']);

    const data = Buffer.from('test data');
    const hashName = hash.toLowerCase().replace('-', '');
    const digest = crypto.createHash(hashName).update(data).digest();
    const algorithm = { name: 'ECDSA', hash };

    // Sign the pre-computed digest
    const sig = await subtle.signDigest(algorithm, privateKey, digest);
    assert(sig instanceof ArrayBuffer);
    assert(sig.byteLength > 0);

    // Verify the signature against the pre-computed digest
    assert(await subtle.verifyDigest(algorithm, publicKey, sig, digest));

    // Cross-verify: signDigest output should be verifiable with verify
    assert(await subtle.verify(algorithm, publicKey, sig, data));

    // Cross-verify: sign output should be verifiable with verifyDigest
    const sig2 = await subtle.sign(algorithm, privateKey, data);
    assert(await subtle.verifyDigest(algorithm, publicKey, sig2, digest));

    // Tampered digest should fail
    const badDigest = Buffer.from(digest);
    badDigest[0] ^= 0xff;
    assert(!await subtle.verifyDigest(algorithm, publicKey, sig, badDigest));

    // Wrong digest length should fail
    const wrongSize = digestSize === 32 ? 48 : 32;
    const wrongHash = wrongSize === 32 ? 'SHA-256' : 'SHA-384';
    await assert.rejects(
      subtle.signDigest({ name: 'ECDSA', hash: wrongHash }, privateKey, digest),
      { name: 'OperationError' }
    );
  }
}

// Test signDigest/verifyDigest for Ed25519 (Ed25519ph)
async function testEd25519ph() {
  if (!hasOpenSSL(3, 2)) {
    return;
  }

  const { publicKey, privateKey } = await subtle.generateKey(
    'Ed25519',
    false,
    ['sign', 'verify']
  );

  const data = Buffer.from('test data');
  const digest = crypto.createHash('sha512').update(data).digest();

  // Sign the pre-computed digest (Ed25519ph)
  const sig = await subtle.signDigest('Ed25519', privateKey, digest);
  assert(sig instanceof ArrayBuffer);
  assert.strictEqual(sig.byteLength, 64);

  // Verify the signature against the pre-computed digest
  assert(await subtle.verifyDigest('Ed25519', publicKey, sig, digest));

  // Ed25519ph signatures are NOT cross-verifiable with Ed25519 pure
  // sign output cannot be verified with verifyDigest and vice versa
  const pureSig = await subtle.sign('Ed25519', privateKey, data);
  assert(!await subtle.verifyDigest('Ed25519', publicKey, pureSig, digest));
  assert(!await subtle.verify('Ed25519', publicKey, sig, data));

  // Tampered digest should fail
  const badDigest = Buffer.from(digest);
  badDigest[0] ^= 0xff;
  assert(!await subtle.verifyDigest('Ed25519', publicKey, sig, badDigest));

  // Wrong digest length should fail (Ed25519ph requires exactly 64 bytes)
  await assert.rejects(
    subtle.signDigest('Ed25519', privateKey, Buffer.alloc(32)),
    { name: 'OperationError' }
  );

  // Test with context parameter
  {
    const context = Buffer.from('my context');
    const algorithm = { name: 'Ed25519', context };

    const sig = await subtle.signDigest(algorithm, privateKey, digest);
    assert(sig instanceof ArrayBuffer);
    assert.strictEqual(sig.byteLength, 64);

    // Verify with matching context
    assert(await subtle.verifyDigest(algorithm, publicKey, sig, digest));

    // Verify with no context should fail
    assert(!await subtle.verifyDigest('Ed25519', publicKey, sig, digest));

    // Verify with different context should fail
    assert(!await subtle.verifyDigest(
      { name: 'Ed25519', context: Buffer.from('other context') },
      publicKey, sig, digest));
  }

  // Context longer than 255 bytes should fail
  await assert.rejects(
    subtle.signDigest(
      { name: 'Ed25519', context: Buffer.alloc(256) },
      privateKey,
      digest
    ),
    { name: 'OperationError' }
  );
}

// Test signDigest/verifyDigest for Ed448 (Ed448ph)
async function testEd448ph() {
  if (!hasOpenSSL(3, 2)) {
    return;
  }

  if (process.features.openssl_is_boringssl) {
    return;
  }

  const { publicKey, privateKey } = await subtle.generateKey(
    'Ed448',
    false,
    ['sign', 'verify']
  );

  const data = Buffer.from('test data');
  // Ed448ph uses SHAKE256 with 64 bytes output
  const digest = crypto.hash('shake256', data, { outputLength: 64, outputEncoding: 'buffer' });

  // Sign the pre-computed digest (Ed448ph)
  const sig = await subtle.signDigest('Ed448', privateKey, digest);
  assert(sig instanceof ArrayBuffer);
  assert.strictEqual(sig.byteLength, 114);

  // Verify the signature against the pre-computed digest
  assert(await subtle.verifyDigest('Ed448', publicKey, sig, digest));

  // Ed448ph signatures are NOT cross-verifiable with Ed448 pure
  const pureSig = await subtle.sign('Ed448', privateKey, data);
  assert(!await subtle.verifyDigest('Ed448', publicKey, pureSig, digest));
  assert(!await subtle.verify('Ed448', publicKey, sig, data));

  // Tampered digest should fail
  const badDigest = Buffer.from(digest);
  badDigest[0] ^= 0xff;
  assert(!await subtle.verifyDigest('Ed448', publicKey, sig, badDigest));

  // Wrong digest length should fail (Ed448ph requires exactly 64 bytes)
  await assert.rejects(
    subtle.signDigest('Ed448', privateKey, Buffer.alloc(32)),
    { name: 'OperationError' }
  );

  // Test with context parameter
  {
    const context = Buffer.from('my context');
    const algorithm = { name: 'Ed448', context };

    const sig = await subtle.signDigest(algorithm, privateKey, digest);
    assert(sig instanceof ArrayBuffer);
    assert.strictEqual(sig.byteLength, 114);

    // Verify with matching context
    assert(await subtle.verifyDigest(algorithm, publicKey, sig, digest));

    // Verify with no context should fail
    assert(!await subtle.verifyDigest('Ed448', publicKey, sig, digest));

    // Verify with different context should fail
    assert(!await subtle.verifyDigest(
      { name: 'Ed448', context: Buffer.from('other context') },
      publicKey, sig, digest));
  }

  // Context longer than 255 bytes should fail
  await assert.rejects(
    subtle.signDigest(
      { name: 'Ed448', context: Buffer.alloc(256) },
      privateKey,
      digest
    ),
    { name: 'OperationError' }
  );
}

// Test signDigest/verifyDigest for ML-DSA (external mu)
async function testMLDSA() {
  if (!hasOpenSSL(3, 5)) {
    return;
  }

  for (const name of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
    const { publicKey, privateKey } = await subtle.generateKey(
      name,
      false,
      ['sign', 'verify']
    );

    // ML-DSA external mu is always 64 bytes
    const mu = crypto.randomBytes(64);

    // Sign with the external mu
    const sig = await subtle.signDigest(name, privateKey, mu);
    assert(sig instanceof ArrayBuffer);
    assert(sig.byteLength > 0);

    // Verify the signature against the mu
    assert(await subtle.verifyDigest(name, publicKey, sig, mu));

    // Tampered mu should fail
    const badMu = Buffer.from(mu);
    badMu[0] ^= 0xff;
    assert(!await subtle.verifyDigest(name, publicKey, sig, badMu));

    // Wrong mu length should fail (must be exactly 64 bytes)
    await assert.rejects(
      subtle.signDigest(name, privateKey, Buffer.alloc(32)),
      { name: 'OperationError' }
    );
  }
}

// Test that unsupported algorithms reject
async function testUnsupported() {
  const hmacKey = await subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );

  const digest = Buffer.alloc(32);

  await assert.rejects(
    subtle.signDigest('HMAC', hmacKey, digest),
    { name: 'NotSupportedError' }
  );

  await assert.rejects(
    subtle.verifyDigest('HMAC', hmacKey, Buffer.alloc(32), digest),
    { name: 'NotSupportedError' }
  );
}

Promise.all([
  testRSASSA(),
  testRSAPSS(),
  testECDSA(),
  testEd25519ph(),
  testEd448ph(),
  testMLDSA(),
  testUnsupported(),
]).then(common.mustCall());
