'use strict';

const common = require('../common.js');
const { createDiffieHellman, getDiffieHellman } = require('crypto');

const bench = common.createBenchmark(main, {
  group: ['modp14', 'modp15'],
  mode: ['named', 'explicit'],
  n: [1000],
});

function main({ group, mode, n }) {
  const peer = getDiffieHellman(group);
  const key = mode === 'named' ? getDiffieHellman(group) :
    createDiffieHellman(peer.getPrime(), peer.getGenerator());
  key.generateKeys();
  const publicKey = peer.generateKeys();
  bench.start();
  for (let index = 0; index < n; index++)
    key.computeSecret(publicKey);
  bench.end(n);
}
