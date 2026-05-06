'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const fixtures = require('../common/fixtures');
const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3))
  common.skip('requires OpenSSL >= 3');

const vectors = require('../fixtures/crypto/kmac')();

assert.strictEqual(crypto.Kmac, undefined);

function nodeAlgorithm(name) {
  switch (name) {
    case 'KMAC128':
      return 'kmac-128';
    case 'KMAC256':
      return 'kmac-256';
    default:
      throw new Error(`Unexpected KMAC algorithm: ${name}`);
  }
}

function explicitOptions(vector) {
  return {
    custom: vector.customization,
    outputLength: vector.outputLength / 8,
  };
}

function defaultOptions(vector) {
  if (vector.customization === undefined)
    return undefined;
  return { custom: vector.customization };
}

function testKmac(vector, key, options) {
  const kmac = crypto.createKmac(nodeAlgorithm(vector.algorithm), key, options);
  kmac.update(vector.data);
  assert.deepStrictEqual(kmac.digest(), vector.expected);
}

function testDefaultDigestLength(key, options) {
  const kmac = crypto.createKmac('kmac-128', key, options);
  assert.strictEqual(kmac.update('data').digest().byteLength, 32);
}

for (const vector of vectors) {
  testKmac(vector, vector.key, explicitOptions(vector));
  testKmac(vector, crypto.createSecretKey(vector.key), explicitOptions(vector));
  testKmac(vector, vector.key, defaultOptions(vector));

  {
    const kmac = crypto.createKmac(
      nodeAlgorithm(vector.algorithm),
      vector.key,
      explicitOptions(vector));
    kmac.update(vector.data.subarray(0, 1));
    kmac.update(vector.data.subarray(1));
    assert.strictEqual(kmac.digest('hex'), vector.expected.toString('hex'));
  }

  {
    const kmac = crypto.createKmac(
      nodeAlgorithm(vector.algorithm),
      vector.key,
      explicitOptions(vector));
    kmac.update(vector.data);
    assert.deepStrictEqual(kmac.digest('buffer'), vector.expected);
  }
}

{
  const vector = vectors[0];
  const kmac = crypto.createKmac('kmac-128', vector.key, explicitOptions(vector));
  kmac.update(vector.data);
  assert.deepStrictEqual(kmac.digest(), vector.expected);
  assert.throws(() => kmac.digest(), { code: 'ERR_CRYPTO_HASH_FINALIZED' });
  assert.throws(() => kmac.update('data'), { code: 'ERR_CRYPTO_HASH_FINALIZED' });
}

{
  const vector = vectors[0];
  const kmac = crypto.createKmac('kmac-128', vector.key, explicitOptions(vector));
  kmac.on('data', common.mustCall((data) => {
    assert.strictEqual(data, vector.expected.toString('hex'));
    assert.throws(() => kmac.digest(), { code: 'ERR_CRYPTO_HASH_FINALIZED' });
    assert.throws(() => kmac.update('data'), { code: 'ERR_CRYPTO_HASH_FINALIZED' });
  }));
  kmac.setEncoding('hex');
  kmac.end(vector.data);
}

{
  const vector = vectors[0];
  const validKey = vector.key;

  for (const algorithm of ['KMAC128', 'kmac128', 'kmac-256 ']) {
    assert.throws(
      () => crypto.createKmac(algorithm, validKey),
      { code: 'ERR_INVALID_ARG_VALUE' });
  }

  assert.throws(
    () => crypto.createKmac(null, validKey),
    { code: 'ERR_INVALID_ARG_TYPE' });

  for (const key of [
    Buffer.alloc(4),
    Buffer.alloc(512),
    crypto.createSecretKey(Buffer.alloc(4)),
    crypto.createSecretKey(Buffer.alloc(512)),
  ]) {
    testDefaultDigestLength(key);
  }

  for (const { key, code } of [
    { key: 'abcd', code: 'ERR_INVALID_ARG_TYPE' },
    { key: {}, code: 'ERR_INVALID_ARG_TYPE' },
    { key: Buffer.alloc(3), code: 'ERR_OUT_OF_RANGE' },
    { key: Buffer.alloc(513), code: 'ERR_OUT_OF_RANGE' },
    {
      key: crypto.createSecretKey(Buffer.alloc(3)),
      code: 'ERR_OUT_OF_RANGE',
    },
    {
      key: crypto.createSecretKey(Buffer.alloc(513)),
      code: 'ERR_OUT_OF_RANGE',
    },
  ]) {
    assert.throws(
      () => crypto.createKmac('kmac-128', key),
      { code });
  }

  const publicKey = crypto.createPublicKey(fixtures.readKey('rsa_public.pem'));
  assert.throws(
    () => crypto.createKmac('kmac-128', publicKey),
    { code: 'ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE' });

  globalThis.crypto.subtle.importKey(
    'raw',
    validKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']).then(common.mustCall((key) => {
    assert.throws(
      () => crypto.createKmac('kmac-128', key),
      { code: 'ERR_INVALID_ARG_TYPE' });
  }));

  for (const outputLength of [0, 1, 32]) {
    const kmac = crypto.createKmac('kmac-128', validKey, { outputLength });
    assert.strictEqual(kmac.update('data').digest().byteLength, outputLength);
  }

  assert.throws(
    () => crypto.createKmac('kmac-128', validKey, null),
    { code: 'ERR_INVALID_ARG_TYPE' });

  for (const { outputLength, code } of [
    { outputLength: '32', code: 'ERR_INVALID_ARG_TYPE' },
    { outputLength: -1, code: 'ERR_OUT_OF_RANGE' },
    { outputLength: 2 ** 32, code: 'ERR_OUT_OF_RANGE' },
  ]) {
    assert.throws(
      () => crypto.createKmac('kmac-128', validKey, { outputLength }),
      { code });
  }

  for (const custom of [
    Buffer.alloc(0),
    Buffer.alloc(511),
    Buffer.alloc(512),
  ]) {
    testDefaultDigestLength(validKey, { custom });
  }

  for (const { custom, code } of [
    { custom: 'custom', code: 'ERR_INVALID_ARG_TYPE' },
    { custom: {}, code: 'ERR_INVALID_ARG_TYPE' },
    { custom: Buffer.alloc(513), code: 'ERR_OUT_OF_RANGE' },
  ]) {
    assert.throws(
      () => crypto.createKmac('kmac-128', validKey, { custom }),
      { code });
  }
}
