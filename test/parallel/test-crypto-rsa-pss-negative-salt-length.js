'use strict';

const common = require('../common');
if (!common.hasCrypto) common.skip('missing crypto');
const { isBoringSSL } = require('../common/crypto');
if (isBoringSSL)
  common.skip('BoringSSL does not support RSA-PSS key pair generation');
if (Number.parseInt(process.versions.openssl, 10) < 3)
  common.skip('requires OpenSSL 3');

const assert = require('assert');
const { createPrivateKey, createPublicKey, generateKeyPairSync } = require('crypto');

const { publicKey, privateKey } = generateKeyPairSync('rsa-pss', {
  modulusLength: 2048,
  hashAlgorithm: 'sha256',
  mgf1HashAlgorithm: 'sha256',
  saltLength: 32,
});
for (const original of [publicKey, privateKey]) {
  const type = original.type === 'public' ? 'spki' : 'pkcs8';
  const createKey = original.type === 'public' ? createPublicKey : createPrivateKey;
  const der = original.export({ format: 'der', type });
  const saltOffset = der.indexOf(Buffer.from([0xa2, 3, 2, 1, 32]));
  assert.notStrictEqual(saltOffset, -1);

  for (const saltLength of [0, 32, 127, -1, -128]) {
    const encoded = Buffer.from(der);
    encoded.writeInt8(saltLength, saltOffset + 4);
    const key = createKey({ key: encoded, format: 'der', type });
    const expected = { modulusLength: 2048, publicExponent: 65537n };
    if (saltLength >= 0) {
      Object.assign(expected, {
        hashAlgorithm: 'sha256',
        mgf1HashAlgorithm: 'sha256',
        saltLength,
      });
    }
    assert.deepStrictEqual(key.asymmetricKeyDetails, expected);
  }
}
