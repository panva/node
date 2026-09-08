'use strict';

const common = require('../common.js');
const assert = require('assert');
const { createPrivateKey, createPublicKey, generateKeyPairSync } = require('crypto');

const algorithms = {
  'rsa': { type: 'rsa' },
  'rsa-pss': { type: 'rsa-pss' },
  'rsa-pss-defaults': {
    type: 'rsa-pss', hashAlgorithm: 'sha1', mgf1HashAlgorithm: 'sha1', saltLength: 20,
  },
  'rsa-pss-sha256': {
    type: 'rsa-pss', hashAlgorithm: 'sha256', mgf1HashAlgorithm: 'sha256', saltLength: 32,
  },
};

const bench = common.createBenchmark(main, {
  algorithm: Object.keys(algorithms),
  type: ['public', 'private'],
  n: [10000],
});

function main({ algorithm, type, n }) {
  const { type: keyType, ...restrictions } = algorithms[algorithm];
  const pair = generateKeyPairSync(keyType, {
    modulusLength: 2048,
    ...restrictions,
  });
  const options = { format: 'der', type: type === 'public' ? 'spki' : 'pkcs8' };
  const encoded = { ...options, key: pair[`${type}Key`].export(options) };
  const createKey = type === 'public' ? createPublicKey : createPrivateKey;
  const keys = Array.from({ length: n }, () => createKey(encoded));
  let details;
  bench.start();
  for (let index = 0; index < n; index++) {
    details = keys[index].asymmetricKeyDetails;
  }
  bench.end(n);
  assert.deepStrictEqual(details, {
    modulusLength: 2048,
    publicExponent: 65537n,
    ...restrictions,
  });
}
