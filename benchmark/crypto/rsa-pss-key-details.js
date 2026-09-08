'use strict';

const common = require('../common.js');
const { createPublicKey, generateKeyPairSync } = require('crypto');

const restrictions = {
  absent: {},
  defaults: { hashAlgorithm: 'sha1', mgf1HashAlgorithm: 'sha1', saltLength: 20 },
  sha256: { hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32 },
};

const bench = common.createBenchmark(main, {
  restrictions: Object.keys(restrictions),
  n: [5000],
});

function main({ restrictions: name, n }) {
  const { publicKey } = generateKeyPairSync('rsa-pss', {
    modulusLength: 2048,
    ...restrictions[name],
  });
  const key = {
    key: publicKey.export({ type: 'spki', format: 'der' }),
    format: 'der',
    type: 'spki',
  };
  bench.start();
  for (let index = 0; index < n; index++) {
    if (createPublicKey(key).asymmetricKeyDetails.modulusLength !== 2048)
      throw new Error('Unexpected modulus length');
  }
  bench.end(n);
}
