'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const fixtures = require('../common/fixtures');
const {
  hasOpenSSL,
} = require('../common/crypto');

// Test crypto.signDigest() and crypto.verifyDigest() one-shot APIs.
// These accept a pre-hashed digest and sign/verify it directly.

const data = Buffer.from('Hello world');

// --- RSA PKCS#1 v1.5 ---
{
  const privKey = fixtures.readKey('rsa_private_2048.pem', 'ascii');
  const pubKey = fixtures.readKey('rsa_public_2048.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  const sig = crypto.signDigest('sha256', digest, privKey);
  assert(Buffer.isBuffer(sig));
  assert.strictEqual(sig.length, 256);

  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig), true);

  // Cross-verify: sign with crypto.sign, verify with crypto.verifyDigest
  const sig2 = crypto.sign('sha256', data, privKey);
  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig2), true);

  // Cross-verify: sign with crypto.signDigest, verify with crypto.verify
  assert.strictEqual(crypto.verify('sha256', data, pubKey, sig), true);

  // Wrong digest should fail verification
  const wrongDigest = crypto.createHash('sha256').update(Buffer.from('wrong')).digest();
  assert.strictEqual(crypto.verifyDigest('sha256', wrongDigest, pubKey, sig), false);

  // KeyObject forms
  const privKeyObj = crypto.createPrivateKey(privKey);
  const pubKeyObj = crypto.createPublicKey(pubKey);

  const sig3 = crypto.signDigest('sha256', digest, privKeyObj);
  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKeyObj, sig3), true);

  // Verify with private key (extracts public)
  assert.strictEqual(crypto.verifyDigest('sha256', digest, privKeyObj, sig3), true);
}

// --- RSA-PSS ---
{
  const privKey = fixtures.readKey('rsa_private_2048.pem', 'ascii');
  const pubKey = fixtures.readKey('rsa_public_2048.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  const sig = crypto.signDigest('sha256', digest, {
    key: privKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  assert(Buffer.isBuffer(sig));

  assert.strictEqual(crypto.verifyDigest('sha256', digest, {
    key: pubKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }, sig), true);

  // Verify with auto salt length
  assert.strictEqual(crypto.verifyDigest('sha256', digest, {
    key: pubKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
  }, sig), true);

  // Cross-verify with crypto.verify
  assert.strictEqual(crypto.verify('sha256', data, {
    key: pubKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
  }, sig), true);
}

// --- RSA-PSS key type (hash/padding/salt baked into key) ---
{
  const privKey = fixtures.readKey('rsa_pss_private_2048_sha256_sha256_16.pem', 'ascii');
  const pubKey = fixtures.readKey('rsa_pss_public_2048_sha256_sha256_16.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  const sig = crypto.signDigest('sha256', digest, privKey);
  assert(Buffer.isBuffer(sig));

  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig), true);

  // Cross-verify
  assert.strictEqual(crypto.verify('sha256', data, pubKey, sig), true);
  const sig2 = crypto.sign('sha256', data, privKey);
  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig2), true);

  // Wrong digest
  const wrongDigest = crypto.createHash('sha256').update(Buffer.from('wrong')).digest();
  assert.strictEqual(crypto.verifyDigest('sha256', wrongDigest, pubKey, sig), false);
}

// --- ECDSA (DER encoding, default) ---
{
  const curves = [
    { priv: 'ec_p256_private.pem', pub: 'ec_p256_public.pem', hash: 'sha256' },
    { priv: 'ec_p384_private.pem', pub: 'ec_p384_public.pem', hash: 'sha384' },
    { priv: 'ec_p521_private.pem', pub: 'ec_p521_public.pem', hash: 'sha512' },
  ];

  for (const { priv, pub, hash } of curves) {
    const privKey = fixtures.readKey(priv, 'ascii');
    const pubKey = fixtures.readKey(pub, 'ascii');

    const digest = crypto.createHash(hash).update(data).digest();

    const sig = crypto.signDigest(hash, digest, privKey);
    assert(Buffer.isBuffer(sig));

    assert.strictEqual(crypto.verifyDigest(hash, digest, pubKey, sig), true);

    // Cross-verify with crypto.sign / crypto.verify
    assert.strictEqual(crypto.verify(hash, data, pubKey, sig), true);

    const sig2 = crypto.sign(hash, data, privKey);
    assert.strictEqual(crypto.verifyDigest(hash, digest, pubKey, sig2), true);

    // Wrong digest
    const wrongDigest = crypto.createHash(hash).update(Buffer.from('wrong')).digest();
    assert.strictEqual(crypto.verifyDigest(hash, wrongDigest, pubKey, sig), false);
  }
}

// --- ECDSA (ieee-p1363 encoding) ---
{
  const privKey = fixtures.readKey('ec_p256_private.pem', 'ascii');
  const pubKey = fixtures.readKey('ec_p256_public.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  const sig = crypto.signDigest('sha256', digest, {
    key: privKey,
    dsaEncoding: 'ieee-p1363',
  });
  assert(Buffer.isBuffer(sig));
  // P-256 ieee-p1363 signature is exactly 64 bytes (2 * 32)
  assert.strictEqual(sig.length, 64);

  assert.strictEqual(crypto.verifyDigest('sha256', digest, {
    key: pubKey,
    dsaEncoding: 'ieee-p1363',
  }, sig), true);

  // Cross-verify with crypto.verify
  assert.strictEqual(crypto.verify('sha256', data, {
    key: pubKey,
    dsaEncoding: 'ieee-p1363',
  }, sig), true);
}

// --- DSA ---
{
  const privKey = fixtures.readKey('dsa_private.pem', 'ascii');
  const pubKey = fixtures.readKey('dsa_public.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  const sig = crypto.signDigest('sha256', digest, privKey);
  assert(Buffer.isBuffer(sig));

  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig), true);

  // Cross-verify
  assert.strictEqual(crypto.verify('sha256', data, pubKey, sig), true);
  const sig2 = crypto.sign('sha256', data, privKey);
  assert.strictEqual(crypto.verifyDigest('sha256', digest, pubKey, sig2), true);

  // Wrong digest
  const wrongDigest = crypto.createHash('sha256').update(Buffer.from('wrong')).digest();
  assert.strictEqual(crypto.verifyDigest('sha256', wrongDigest, pubKey, sig), false);
}

// --- Ed25519ph ---
if (hasOpenSSL(3, 2)) {
  const privKey = fixtures.readKey('ed25519_private.pem', 'ascii');
  const pubKey = fixtures.readKey('ed25519_public.pem', 'ascii');

  // Ed25519ph expects a SHA-512 prehash (64 bytes)
  const digest = crypto.createHash('sha512').update(data).digest();
  assert.strictEqual(digest.length, 64);

  const sig = crypto.signDigest(null, digest, privKey);
  assert(Buffer.isBuffer(sig));
  assert.strictEqual(sig.length, 64);

  assert.strictEqual(crypto.verifyDigest(null, digest, pubKey, sig), true);

  // Wrong digest should fail
  const wrongDigest = crypto.createHash('sha512').update(Buffer.from('wrong')).digest();
  assert.strictEqual(crypto.verifyDigest(null, wrongDigest, pubKey, sig), false);

  // Note: Ed25519ph signatures are NOT compatible with Ed25519 signatures
  // (crypto.sign(null, data, privKey)), so no cross-verify with crypto.sign.

  // KeyObject forms
  const privKeyObj = crypto.createPrivateKey(privKey);
  const pubKeyObj = crypto.createPublicKey(pubKey);

  const sig2 = crypto.signDigest(null, digest, privKeyObj);
  assert.strictEqual(crypto.verifyDigest(null, digest, pubKeyObj, sig2), true);

  // Ed25519ph with context string
  {
    const context = Buffer.from('my context');
    const sig3 = crypto.signDigest(null, digest, { key: privKey, context });
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey, context }, sig3), true);

    // Wrong context should fail
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey }, sig3), false);
    assert.strictEqual(crypto.verifyDigest(null, digest, {
      key: pubKey,
      context: Buffer.from('other'),
    }, sig3), false);
  }
}

// --- Ed448ph ---
if (hasOpenSSL(3, 2)) {
  const privKey = fixtures.readKey('ed448_private.pem', 'ascii');
  const pubKey = fixtures.readKey('ed448_public.pem', 'ascii');

  // Ed448ph expects a SHAKE256 prehash (64 bytes)
  const digest = crypto.createHash('shake256', { outputLength: 64 }).update(data).digest();
  assert.strictEqual(digest.length, 64);

  const sig = crypto.signDigest(null, digest, privKey);
  assert(Buffer.isBuffer(sig));
  assert.strictEqual(sig.length, 114);

  assert.strictEqual(crypto.verifyDigest(null, digest, pubKey, sig), true);

  // Wrong digest
  const wrongDigest = crypto.createHash('shake256', { outputLength: 64 }).update(Buffer.from('wrong')).digest();
  assert.strictEqual(crypto.verifyDigest(null, wrongDigest, pubKey, sig), false);

  // Ed448ph with context string
  {
    const context = Buffer.from('my context');
    const sig2 = crypto.signDigest(null, digest, { key: privKey, context });
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey, context }, sig2), true);

    // Wrong context should fail
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey }, sig2), false);
    assert.strictEqual(crypto.verifyDigest(null, digest, {
      key: pubKey,
      context: Buffer.from('other'),
    }, sig2), false);
  }

  // Ed448ph with empty context string
  {
    const context = new Uint8Array();
    const sig3 = crypto.signDigest(null, digest, { key: privKey, context });
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey, context }, sig3), true);
    // Empty context and no context should both verify for Ed448ph
    assert.strictEqual(crypto.verifyDigest(null, digest, { key: pubKey }, sig3), true);
  }
}

// --- Async (callback) mode ---
{
  const privKey = fixtures.readKey('rsa_private_2048.pem', 'ascii');
  const pubKey = fixtures.readKey('rsa_public_2048.pem', 'ascii');

  const digest = crypto.createHash('sha256').update(data).digest();

  crypto.signDigest('sha256', digest, privKey, common.mustSucceed((sig) => {
    assert(Buffer.isBuffer(sig));

    crypto.verifyDigest('sha256', digest, pubKey, sig, common.mustSucceed((result) => {
      assert.strictEqual(result, true);
    }));
  }));
}

// --- Error: unsupported key type for prehashed signing ---
{
  // ML-DSA keys are one-shot-only and don't support prehashed signing.
  if (hasOpenSSL(3, 5)) {
    const privKey = fixtures.readKey('ml_dsa_44_private.pem', 'ascii');
    const pubKey = fixtures.readKey('ml_dsa_44_public.pem', 'ascii');

    assert.throws(() => {
      crypto.signDigest(null, Buffer.alloc(32), privKey);
    }, { code: 'ERR_CRYPTO_OPERATION_FAILED', message: /Prehashed signing is not supported/ });

    assert.throws(() => {
      crypto.verifyDigest(null, Buffer.alloc(32), pubKey, Buffer.alloc(64));
    }, { code: 'ERR_CRYPTO_OPERATION_FAILED', message: /Prehashed signing is not supported/ });
  }

  // Ed25519ph/Ed448ph require OpenSSL >= 3.2. On older versions, they
  // should throw PrehashUnsupported.
  if (!hasOpenSSL(3, 2)) {
    const edPrivKey = fixtures.readKey('ed25519_private.pem', 'ascii');
    const edPubKey = fixtures.readKey('ed25519_public.pem', 'ascii');

    assert.throws(() => {
      crypto.signDigest(null, Buffer.alloc(64), edPrivKey);
    }, { code: 'ERR_CRYPTO_OPERATION_FAILED', message: /Prehashed signing is not supported/ });

    assert.throws(() => {
      crypto.verifyDigest(null, Buffer.alloc(64), edPubKey, Buffer.alloc(64));
    }, { code: 'ERR_CRYPTO_OPERATION_FAILED', message: /Prehashed signing is not supported/ });
  }

  // Invalid algorithm argument type
  assert.throws(() => {
    crypto.signDigest(123, Buffer.alloc(32), fixtures.readKey('rsa_private_2048.pem', 'ascii'));
  }, { code: 'ERR_INVALID_ARG_TYPE' });
}

// --- Error: non-signing key types (X25519, X448) ---
{
  const x25519Priv = fixtures.readKey('x25519_private.pem', 'ascii');
  const x25519Pub = fixtures.readKey('x25519_public.pem', 'ascii');

  assert.throws(() => {
    crypto.signDigest('sha256', Buffer.alloc(32), x25519Priv);
  }, { code: 'ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE' });

  assert.throws(() => {
    crypto.verifyDigest('sha256', Buffer.alloc(32), x25519Pub, Buffer.alloc(64));
  }, { code: 'ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE' });
}

// --- Error: invalid/unsupported digest algorithm ---
{
  const privKey = fixtures.readKey('rsa_private_2048.pem', 'ascii');

  assert.throws(() => {
    crypto.signDigest('nonexistent', Buffer.alloc(32), privKey);
  }, { code: 'ERR_CRYPTO_INVALID_DIGEST' });
}

// --- Error: wrong digest length for Ed25519ph/Ed448ph ---
if (hasOpenSSL(3, 2)) {
  // Ed25519ph requires exactly 64-byte SHA-512 digest
  {
    const privKey = fixtures.readKey('ed25519_private.pem', 'ascii');
    assert.throws(() => {
      crypto.signDigest(null, Buffer.alloc(32), privKey);
    }, { code: 'ERR_OSSL_INVALID_DIGEST_LENGTH' });
  }

  // Ed448ph requires exactly 64-byte SHAKE256 digest
  {
    const privKey = fixtures.readKey('ed448_private.pem', 'ascii');
    assert.throws(() => {
      crypto.signDigest(null, Buffer.alloc(32), privKey);
    }, { code: 'ERR_OSSL_INVALID_DIGEST_LENGTH' });
  }
}
