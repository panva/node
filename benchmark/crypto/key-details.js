'use strict';

const common = require('../common.js');
const { KeyObject } = require('crypto');

const bench = common.createBenchmark(main, {
  algorithm: ['RSA-OAEP', 'RSA-PSS'],
  type: ['public', 'private'],
  n: [10000],
});

async function main({ algorithm, type, n }) {
  const pair = await crypto.subtle.generateKey({
    name: algorithm,
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, algorithm === 'RSA-OAEP' ? ['encrypt', 'decrypt'] : ['sign', 'verify']);
  const cryptoKey = pair[`${type}Key`];
  bench.start();
  for (let index = 0; index < n; index++) {
    if (KeyObject.from(cryptoKey).asymmetricKeyDetails.modulusLength !== 2048)
      throw new Error('Unexpected modulus length');
  }
  bench.end(n);
}
