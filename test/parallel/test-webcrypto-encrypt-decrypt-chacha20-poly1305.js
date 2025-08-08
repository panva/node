'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const { subtle } = globalThis.crypto;

async function testEncrypt({ keyBuffer, algorithm, plaintext, result }) {
  // Using a copy of plaintext to prevent tampering of the original
  plaintext = Buffer.from(plaintext);

  const key = await subtle.importKey(
    'raw-secret',
    keyBuffer,
    { name: algorithm.name },
    false,
    ['encrypt', 'decrypt']);

  const output = await subtle.encrypt(algorithm, key, plaintext);
  plaintext[0] = 255 - plaintext[0];

  assert.strictEqual(
    Buffer.from(output).toString('hex'),
    Buffer.from(result).toString('hex'));

  // Converting the returned ArrayBuffer into a Buffer right away,
  // so that the next line works
  const check = Buffer.from(await subtle.decrypt(algorithm, key, output));
  check[0] = 255 - check[0];

  assert.strictEqual(
    Buffer.from(check).toString('hex'),
    Buffer.from(plaintext).toString('hex'));
}

async function testEncryptNoEncrypt({ keyBuffer, algorithm, plaintext }) {
  const key = await subtle.importKey(
    'raw-secret',
    keyBuffer,
    { name: algorithm.name },
    false,
    ['decrypt']);

  return assert.rejects(subtle.encrypt(algorithm, key, plaintext), {
    message: /The requested operation is not valid for the provided key/
  });
}

async function testEncryptNoDecrypt({ keyBuffer, algorithm, plaintext }) {
  const key = await subtle.importKey(
    'raw-secret',
    keyBuffer,
    { name: algorithm.name },
    false,
    ['encrypt']);

  const output = await subtle.encrypt(algorithm, key, plaintext);

  return assert.rejects(subtle.decrypt(algorithm, key, output), {
    message: /The requested operation is not valid for the provided key/
  });
}

async function testEncryptWrongAlg({ keyBuffer, algorithm, plaintext }, alg) {
  assert.notStrictEqual(algorithm.name, alg);
  const key = await subtle.importKey(
    'raw-secret',
    keyBuffer,
    { name: alg },
    false,
    ['encrypt']);

  return assert.rejects(subtle.encrypt(algorithm, key, plaintext), {
    message: /The requested operation is not valid for the provided key/
  });
}

async function testDecrypt({ keyBuffer, algorithm, result }) {
  const key = await subtle.importKey(
    'raw-secret',
    keyBuffer,
    { name: algorithm.name },
    false,
    ['encrypt', 'decrypt']);

  await subtle.decrypt(algorithm, key, result);
}

{
  const {
    passing,
    failing,
    decryptionFailing
  } = require('../fixtures/crypto/chacha20_poly1305')();

  (async function() {
    const variations = [];

    passing.forEach((vector) => {
      variations.push(testEncrypt(vector));
      variations.push(testEncryptNoEncrypt(vector));
      variations.push(testEncryptNoDecrypt(vector));
      variations.push(testEncryptWrongAlg(vector, 'AES-GCM'));
    });

    failing.forEach((vector) => {
      variations.push(assert.rejects(testEncrypt(vector), {
        message: /is not a valid ChaCha20-Poly1305 tag length/
      }));
      variations.push(assert.rejects(testDecrypt(vector), {
        message: /is not a valid ChaCha20-Poly1305 tag length/
      }));
    });

    decryptionFailing.forEach((vector) => {
      variations.push(assert.rejects(testDecrypt(vector), {
        name: 'OperationError'
      }));
    });

    await Promise.all(variations);
  })().then(common.mustCall());
}

{
  (async function() {
    const secretKey = await subtle.generateKey(
      {
        name: 'ChaCha20-Poly1305',
      },
      false,
      ['encrypt', 'decrypt'],
    );

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const aad = globalThis.crypto.getRandomValues(new Uint8Array(32));

    const encrypted = await subtle.encrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv,
        additionalData: aad,
      },
      secretKey,
      globalThis.crypto.getRandomValues(new Uint8Array(32))
    );

    await subtle.decrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv,
        additionalData: aad,
      },
      secretKey,
      new Uint8Array(encrypted),
    );
  })().then(common.mustCall());
}
