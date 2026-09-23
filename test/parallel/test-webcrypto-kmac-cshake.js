'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const { createSecretKey, getHashes, KeyObject, subtle } = require('crypto');
const { SubtleCrypto } = globalThis;
const hashes = getHashes();
if (!hashes.includes('cshake128') && !hashes.includes('cshake256'))
  common.skip('requires cSHAKE support');

const usages = ['sign', 'verify'];
const data = Buffer.from('KMAC over cSHAKE');

(async () => {
  for (const name of ['KMAC128', 'KMAC256']) {
    if (!hashes.includes(name === 'KMAC128' ? 'cshake128' : 'cshake256'))
      continue;

    for (const length of [33, 39, 129]) {
      const algorithm = { name, length };
      const raw = Buffer.alloc(Math.ceil(length / 8), 0xff);
      const canonical = Buffer.from(raw);
      canonical[canonical.length - 1] &= 0xff << (8 - length % 8);

      const keys = [
        await subtle.importKey('raw-secret', raw, algorithm, true, usages),
        await subtle.importKey(
          'jwk', { kty: 'oct', k: raw.toString('base64url') }, algorithm, true, usages),
        createSecretKey(raw).toCryptoKey(algorithm, true, usages),
      ];
      for (const key of keys) {
        assert.deepStrictEqual(key.algorithm, algorithm);
        assert.strictEqual(key.type, 'secret');
        assert.strictEqual(key.extractable, true);
        assert.deepStrictEqual(key.usages, usages);
        assert.deepStrictEqual(Buffer.from(await subtle.exportKey('raw-secret', key)), canonical);
        assert.deepStrictEqual(KeyObject.from(key).export(), canonical);
        const jwk = await subtle.exportKey('jwk', key);
        assert.deepStrictEqual(Buffer.from(jwk.k, 'base64url'), canonical);
        const reimported = await subtle.importKey('jwk', jwk, algorithm, true, usages);
        assert.deepStrictEqual(reimported.algorithm, algorithm);

        for (const outputLength of [0, 128, 129]) {
          const params = { name, outputLength, customization: Buffer.from('Node.js') };
          const signature = await subtle.sign(params, key, data);
          assert.strictEqual(signature.byteLength, Math.ceil(outputLength / 8));
          assert.strictEqual(await subtle.verify(params, reimported, signature, data), true);
          assert.deepStrictEqual(await subtle.sign(params, keys[0], data), signature);
        }
      }
      assert.strictEqual(raw[raw.length - 1], 0xff);

      const generated = await subtle.generateKey(algorithm, true, usages);
      assert.deepStrictEqual(generated.algorithm, algorithm);
      const exported = new Uint8Array(await subtle.exportKey('raw-secret', generated));
      assert.strictEqual(exported.length, raw.length);
      assert.strictEqual(exported[exported.length - 1] & ((1 << (8 - length % 8)) - 1), 0);
      const imported = await subtle.importKey('raw-secret', exported, algorithm, false, usages);
      const params = { name, outputLength: 129 };
      const signature = await subtle.sign(params, generated, data);
      assert.strictEqual(await subtle.verify(params, imported, signature, data), true);
    }

    const aligned = await subtle.importKey('raw-secret', Buffer.alloc(16), name, false, usages);
    const partial = await subtle.importKey(
      'raw-secret', Buffer.alloc(5), { name, length: 33 }, false, usages);
    for (const [customization, error] of [
      [Buffer.from([0]), { name: 'NotSupportedError' }],
      [Buffer.alloc(513, 1), { name: 'OperationError' }],
    ]) {
      for (const [key, outputLength] of [[aligned, 129], [partial, 128]]) {
        const params = { name, outputLength, customization };
        // supports() has no key argument, so only the output can select cSHAKE.
        assert.strictEqual(SubtleCrypto.supports('sign', params), outputLength === 128);
        assert.strictEqual(SubtleCrypto.supports('verify', params), outputLength === 128);
        await assert.rejects(subtle.sign(params, key, data), error);
        await assert.rejects(subtle.verify(params, key, new Uint8Array(), data), error);
      }
    }

    // The direct KMAC provider continues to accept null bytes in customization.
    const params = { name, outputLength: 128, customization: Buffer.from([0]) };
    const signature = await subtle.sign(params, aligned, data);
    assert.strictEqual(await subtle.verify(params, aligned, signature, data), true);
  }
})().then(common.mustCall());
