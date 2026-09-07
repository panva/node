'use strict';

const common = require('../common.js');
const { constants, generateKeyPairSync, publicEncrypt, privateDecrypt } = require('crypto');

const bench = common.createBenchmark(main, {
  modulusLength: [1024, 2048],
  padding: ['RSA_PKCS1_PADDING', 'RSA_PKCS1_OAEP_PADDING'],
  n: [1000],
});

function main({ modulusLength, padding, n }) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
  const options = { key: privateKey, padding: constants[padding] };
  const ciphertext = publicEncrypt({ key: publicKey, padding: constants[padding] }, Buffer.alloc(32));
  bench.start();
  for (let index = 0; index < n; index++)
    privateDecrypt(options, ciphertext);
  bench.end(n);
}
