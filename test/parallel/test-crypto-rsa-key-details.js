'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const { createPrivateKey, createPublicKey, generateKeyPairSync } = require('crypto');
const { isBoringSSL } = require('../common/crypto');

const cases = [
  ['rsa', {}, {}],
];
if (!isBoringSSL) {
  const defaults = { hashAlgorithm: 'sha1', mgf1HashAlgorithm: 'sha1', saltLength: 20 };
  cases.push(
    ['rsa-pss', {}, {}],
    ['rsa-pss', defaults, defaults],
    ['rsa-pss', { saltLength: 0 }, { ...defaults, saltLength: 0 }],
    ['rsa-pss', { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha1', saltLength: 20 },
     { ...defaults, hashAlgorithm: 'sha256' }],
    ['rsa-pss', { mgf1HashAlgorithm: 'sha384' },
     { ...defaults, mgf1HashAlgorithm: 'sha384' }],
    ['rsa-pss', { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha512', saltLength: 32 },
     { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha512', saltLength: 32 }],
  );
}

for (const [algorithm, options, restrictions] of cases) {
  const { publicKey, privateKey } = generateKeyPairSync(algorithm, {
    modulusLength: 2048,
    ...options,
  });
  const expected = { modulusLength: 2048, publicExponent: 65537n, ...restrictions };
  for (const key of [publicKey, privateKey]) {
    const encoding = { format: 'der', type: key.type === 'public' ? 'spki' : 'pkcs8' };
    const encoded = key.export(encoding);
    const createKey = key.type === 'public' ? createPublicKey : createPrivateKey;
    const imported = createKey({ ...encoding, key: encoded });
    for (const candidate of [key, imported]) {
      assert.strictEqual(candidate.asymmetricKeyType, algorithm);
      assert.deepStrictEqual(candidate.asymmetricKeyDetails, expected);
      assert.deepStrictEqual(candidate.export(encoding), encoded);
      const derived = createPublicKey(candidate.type === 'private' ? candidate : {
        key: encoded, ...encoding,
      });
      assert.deepStrictEqual(derived.asymmetricKeyDetails, expected);
      assert.deepStrictEqual(derived.export({ format: 'der', type: 'spki' }),
                             publicKey.export({ format: 'der', type: 'spki' }));
    }
  }
}
