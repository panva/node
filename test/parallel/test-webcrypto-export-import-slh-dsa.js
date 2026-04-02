'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3, 5))
  common.skip('requires OpenSSL >= 3.5');

const assert = require('assert');
const { subtle } = globalThis.crypto;
const { createPrivateKey, createPublicKey } = require('crypto');

const fixtures = require('../common/fixtures');

function getKeyFileName(type, suffix) {
  return `${type.replaceAll('-', '_')}_${suffix}.pem`;
}

function toDer(pem) {
  const der = pem.replace(/(?:-----(?:BEGIN|END) (?:PRIVATE|PUBLIC) KEY-----|\s)/g, '');
  return Buffer.alloc(Buffer.byteLength(der, 'base64'), der, 'base64');
}

const keyData = {};

const allNames = [
  'SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s', 'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s', 'SLH-DSA-SHA2-256f',
  'SLH-DSA-SHAKE-128s', 'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s', 'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s', 'SLH-DSA-SHAKE-256f',
];

for (const name of allNames) {
  const lcName = name.toLowerCase();
  keyData[name] = {
    pkcs8: toDer(fixtures.readKey(getKeyFileName(lcName, 'private'), 'ascii')),
    spki: toDer(fixtures.readKey(getKeyFileName(lcName, 'public'), 'ascii')),
    jwk: JSON.parse(fixtures.readKey(`${lcName}.json`)),
  };
}

const testVectors = allNames.map((name) => ({
  name,
  privateUsages: ['sign'],
  publicUsages: ['verify'],
}));

async function testImportSpki({ name, publicUsages }, extractable) {
  const key = await subtle.importKey(
    'spki',
    keyData[name].spki,
    { name },
    extractable,
    publicUsages);
  assert.strictEqual(key.type, 'public');
  assert.strictEqual(key.extractable, extractable);
  assert.deepStrictEqual(key.usages, publicUsages);
  assert.deepStrictEqual(key.algorithm.name, name);
  assert.strictEqual(key.algorithm, key.algorithm);
  assert.strictEqual(key.usages, key.usages);

  if (extractable) {
    const spki = await subtle.exportKey('spki', key);
    assert.strictEqual(
      Buffer.from(spki).toString('hex'),
      keyData[name].spki.toString('hex'));
  } else {
    await assert.rejects(
      subtle.exportKey('spki', key), {
        message: /key is not extractable/,
        name: 'InvalidAccessError',
      });
  }

  // Bad usage
  await assert.rejects(
    subtle.importKey(
      'spki',
      keyData[name].spki,
      { name },
      extractable,
      ['wrapKey']),
    { message: /Unsupported key usage/ });
}

async function testImportPkcs8({ name, privateUsages }, extractable) {
  const key = await subtle.importKey(
    'pkcs8',
    keyData[name].pkcs8,
    { name },
    extractable,
    privateUsages);
  assert.strictEqual(key.type, 'private');
  assert.strictEqual(key.extractable, extractable);
  assert.deepStrictEqual(key.usages, privateUsages);
  assert.deepStrictEqual(key.algorithm.name, name);

  if (extractable) {
    const pkcs8 = await subtle.exportKey('pkcs8', key);
    assert.strictEqual(
      Buffer.from(pkcs8).toString('hex'),
      keyData[name].pkcs8.toString('hex'));
  } else {
    await assert.rejects(
      subtle.exportKey('pkcs8', key), {
        message: /key is not extractable/,
        name: 'InvalidAccessError',
      });
  }

  await assert.rejects(
    subtle.importKey(
      'pkcs8',
      keyData[name].pkcs8,
      { name },
      extractable,
      [/* empty usages */]),
    { name: 'SyntaxError', message: 'Usages cannot be empty when importing a private key.' });
}

async function testImportJwk({ name, publicUsages, privateUsages }, extractable) {
  const jwk = keyData[name].jwk;

  const [
    publicKey,
    privateKey,
  ] = await Promise.all([
    subtle.importKey(
      'jwk',
      { kty: jwk.kty, alg: jwk.alg, pub: jwk.pub },
      { name },
      extractable, publicUsages),
    subtle.importKey(
      'jwk',
      jwk,
      { name },
      extractable,
      privateUsages),
  ]);

  assert.strictEqual(publicKey.type, 'public');
  assert.strictEqual(privateKey.type, 'private');
  assert.strictEqual(publicKey.extractable, extractable);
  assert.strictEqual(privateKey.extractable, extractable);
  assert.deepStrictEqual(publicKey.usages, publicUsages);
  assert.deepStrictEqual(privateKey.usages, privateUsages);
  assert.strictEqual(publicKey.algorithm.name, name);
  assert.strictEqual(privateKey.algorithm.name, name);

  if (extractable) {
    const [pubJwk, pvtJwk] = await Promise.all([
      subtle.exportKey('jwk', publicKey),
      subtle.exportKey('jwk', privateKey),
    ]);

    assert.deepStrictEqual(pubJwk.key_ops, publicUsages);
    assert.strictEqual(pubJwk.ext, true);
    assert.strictEqual(pubJwk.kty, 'AKP');
    assert.strictEqual(pubJwk.pub, jwk.pub);

    assert.deepStrictEqual(pvtJwk.key_ops, privateUsages);
    assert.strictEqual(pvtJwk.ext, true);
    assert.strictEqual(pvtJwk.kty, 'AKP');
    assert.strictEqual(pvtJwk.pub, jwk.pub);
    assert.strictEqual(pvtJwk.priv, jwk.priv);

    assert.strictEqual(pubJwk.alg, jwk.alg);
    assert.strictEqual(pvtJwk.alg, jwk.alg);
  } else {
    await assert.rejects(
      subtle.exportKey('jwk', publicKey), {
        message: /key is not extractable/,
        name: 'InvalidAccessError',
      });
    await assert.rejects(
      subtle.exportKey('jwk', privateKey), {
        message: /key is not extractable/,
        name: 'InvalidAccessError',
      });
  }

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, use: 'enc' },
      { name },
      extractable,
      privateUsages),
    { message: 'Invalid JWK "use" Parameter' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, pub: undefined },
      { name },
      extractable,
      privateUsages),
    { message: 'Invalid keyData' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, priv: 'A'.repeat(86) },
      { name },
      extractable,
      privateUsages),
    { message: 'Invalid keyData' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, kty: 'OKP' },
      { name },
      extractable,
      privateUsages),
    { message: 'Invalid JWK "kty" Parameter' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk },
      { name },
      extractable,
      publicUsages),
    { message: /Unsupported key usage/ });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, ext: false },
      { name },
      true,
      privateUsages),
    { message: 'JWK "ext" Parameter and extractable mismatch' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, priv: undefined },
      { name },
      extractable,
      privateUsages),
    { message: /Unsupported key usage/ });

  const wrongAlg = name === 'SLH-DSA-SHA2-128f' ? 'SLH-DSA-SHAKE-128f' : 'SLH-DSA-SHA2-128f';
  for (const alg of [undefined, wrongAlg]) {
    await assert.rejects(
      subtle.importKey(
        'jwk',
        { kty: jwk.kty, pub: jwk.pub, alg },
        { name },
        extractable,
        publicUsages),
      { message: 'JWK "alg" Parameter and algorithm name mismatch' });

    await assert.rejects(
      subtle.importKey(
        'jwk',
        { ...jwk, alg },
        { name },
        extractable,
        privateUsages),
      { message: 'JWK "alg" Parameter and algorithm name mismatch' });
  }

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk },
      { name },
      extractable,
      [/* empty usages */]),
    { name: 'SyntaxError', message: 'Usages cannot be empty when importing a private key.' });

  await assert.rejects(
    subtle.importKey(
      'jwk',
      { kty: jwk.kty, /* missing pub */ alg: jwk.alg },
      { name },
      extractable,
      publicUsages),
    { name: 'DataError', message: 'Invalid keyData' });
}

async function testImportRawPublic({ name, publicUsages }, extractable) {
  const jwk = keyData[name].jwk;
  const pub = Buffer.from(jwk.pub, 'base64url');

  const publicKey = await subtle.importKey(
    'raw-public',
    pub,
    { name },
    extractable, publicUsages);

  assert.strictEqual(publicKey.type, 'public');
  assert.deepStrictEqual(publicKey.usages, publicUsages);
  assert.strictEqual(publicKey.algorithm.name, name);
  assert.strictEqual(publicKey.extractable, extractable);

  if (extractable) {
    const value = await subtle.exportKey('raw-public', publicKey);
    assert.deepStrictEqual(Buffer.from(value), pub);

    await assert.rejects(subtle.exportKey('raw', publicKey), {
      name: 'NotSupportedError',
      message: `Unable to export ${name} public key using raw format`,
    });
  }

  await assert.rejects(
    subtle.importKey(
      'raw-public',
      pub.subarray(0, pub.byteLength - 1),
      { name },
      extractable, publicUsages),
    { message: 'Invalid keyData' });

  // Pick a wrong algorithm with a different key size to ensure rejection.
  const wrongName = name.includes('128') ?
    name.replace('128', '256') : name.replace(/192|256/, '128');
  await assert.rejects(
    subtle.importKey(
      'raw-public',
      pub,
      { name: wrongName },
      extractable, publicUsages),
    { message: 'Invalid keyData' });
}

async function testImportRawPrivate({ name, privateUsages }, extractable) {
  const jwk = keyData[name].jwk;
  const priv = Buffer.from(jwk.priv, 'base64url');

  const privateKey = await subtle.importKey(
    'raw-private',
    priv,
    { name },
    extractable, privateUsages);

  assert.strictEqual(privateKey.type, 'private');
  assert.deepStrictEqual(privateKey.usages, privateUsages);
  assert.strictEqual(privateKey.algorithm.name, name);
  assert.strictEqual(privateKey.extractable, extractable);

  if (extractable) {
    const value = await subtle.exportKey('raw-private', privateKey);
    assert.deepStrictEqual(Buffer.from(value), priv);
  }

  await assert.rejects(
    subtle.importKey(
      'raw-private',
      priv.subarray(0, 30),
      { name },
      extractable,
      privateUsages),
    { message: 'Invalid keyData' });
}

(async function() {
  const tests = [];
  for (const vector of testVectors) {
    for (const extractable of [true, false]) {
      tests.push(testImportSpki(vector, extractable));
      tests.push(testImportPkcs8(vector, extractable));
      tests.push(testImportJwk(vector, extractable));
      tests.push(testImportRawPublic(vector, extractable));
      tests.push(testImportRawPrivate(vector, extractable));
    }
  }
  await Promise.all(tests);
})().then(common.mustCall());

(async function() {
  const alg = 'SLH-DSA-SHA2-128f';
  const pub = Buffer.from(keyData[alg].jwk.pub, 'base64url');
  await assert.rejects(subtle.importKey('raw', pub, alg, false, []), {
    name: 'NotSupportedError',
    message: `Unable to import ${alg} using raw format`,
  });
})().then(common.mustCall());

(async function() {
  // Test generateKey and roundtrip export/import
  for (const { name } of testVectors) {
    const { publicKey, privateKey } = await subtle.generateKey(
      { name },
      true,
      ['sign', 'verify']);

    assert.strictEqual(publicKey.type, 'public');
    assert.strictEqual(privateKey.type, 'private');
    assert.strictEqual(publicKey.algorithm.name, name);
    assert.strictEqual(privateKey.algorithm.name, name);
    assert.strictEqual(publicKey.extractable, true);
    assert.strictEqual(privateKey.extractable, true);

    // Roundtrip via all formats
    const [spki, pkcs8, pubJwk, pvtJwk, rawPub, rawPriv] = await Promise.all([
      subtle.exportKey('spki', publicKey),
      subtle.exportKey('pkcs8', privateKey),
      subtle.exportKey('jwk', publicKey),
      subtle.exportKey('jwk', privateKey),
      subtle.exportKey('raw-public', publicKey),
      subtle.exportKey('raw-private', privateKey),
    ]);

    // Reimport and verify
    const [reimportedPub, reimportedPriv] = await Promise.all([
      subtle.importKey('spki', spki, { name }, true, ['verify']),
      subtle.importKey('pkcs8', pkcs8, { name }, true, ['sign']),
    ]);

    const reExportedSpki = await subtle.exportKey('spki', reimportedPub);
    const reExportedPkcs8 = await subtle.exportKey('pkcs8', reimportedPriv);
    assert.deepStrictEqual(Buffer.from(reExportedSpki), Buffer.from(spki));
    assert.deepStrictEqual(Buffer.from(reExportedPkcs8), Buffer.from(pkcs8));

    // Reimport raw and verify roundtrip
    const reimportedRawPub = await subtle.importKey(
      'raw-public', rawPub, { name }, true, ['verify']);
    const reimportedRawPriv = await subtle.importKey(
      'raw-private', rawPriv, { name }, true, ['sign']);

    const reExportedRawPub = await subtle.exportKey('raw-public', reimportedRawPub);
    const reExportedRawPriv = await subtle.exportKey('raw-private', reimportedRawPriv);
    assert.deepStrictEqual(Buffer.from(reExportedRawPub), Buffer.from(rawPub));
    assert.deepStrictEqual(Buffer.from(reExportedRawPriv), Buffer.from(rawPriv));

    // Verify JWK data
    assert.strictEqual(pubJwk.kty, 'AKP');
    assert.strictEqual(pvtJwk.kty, 'AKP');
    assert.strictEqual(pubJwk.alg, name);
    assert.strictEqual(pvtJwk.alg, name);
    assert.ok(pubJwk.pub);
    assert.ok(pvtJwk.pub);
    assert.ok(pvtJwk.priv);
    assert.strictEqual(pubJwk.priv, undefined);
  }
})().then(common.mustCall());

// toCryptoKey
(async function() {
  for (const { name, privateUsages } of testVectors) {
    const lcName = name.toLowerCase();
    const pem = fixtures.readKey(getKeyFileName(lcName, 'private'), 'ascii');
    const keyObject = createPrivateKey(pem);
    const key = keyObject.toCryptoKey({ name }, true, privateUsages);
    assert.strictEqual(key.type, 'private');
    assert.strictEqual(key.algorithm.name, name);
    assert.deepStrictEqual(key.usages, privateUsages);

    const pubPem = fixtures.readKey(getKeyFileName(lcName, 'public'), 'ascii');
    const pubKeyObject = createPublicKey(pubPem);
    const pubKey = pubKeyObject.toCryptoKey({ name }, true, ['verify']);
    assert.strictEqual(pubKey.type, 'public');
    assert.strictEqual(pubKey.algorithm.name, name);
  }
})().then(common.mustCall());
