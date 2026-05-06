'use strict';

const common = require('../common.js');
const { hasOpenSSL } = require('../../test/common/crypto.js');
const {
  createHmac,
  createKmac,
} = require('crypto');
const assert = require('assert');

const methods = [
  'hmac-sha256',
  'hmac-sha512',
];

if (hasOpenSSL(3)) {
  methods.push(
    'kmac-128',
    'kmac-256',
  );
}

const bench = common.createBenchmark(main, {
  n: [1e5],
  method: methods,
}, {
  test: {
    method: hasOpenSSL(3) ? ['hmac-sha256', 'kmac-128'] : ['hmac-sha256'],
  },
});

const key = Buffer.alloc(32);

function createMac(method) {
  switch (method) {
    case 'hmac-sha256':
      return createHmac('sha256', key);
    case 'hmac-sha512':
      return createHmac('sha512', key);
    case 'kmac-128':
      return createKmac('kmac-128', key);
    case 'kmac-256':
      return createKmac('kmac-256', key);
    default:
      throw new Error(`unknown method: ${method}`);
  }
}

function main({ n, method }) {
  const array = [];
  for (let i = 0; i < n; ++i) {
    array.push(null);
  }
  bench.start();
  for (let i = 0; i < n; ++i) {
    array[i] = createMac(method);
  }
  bench.end(n);
  assert.strictEqual(typeof array[n - 1], 'object');
}
