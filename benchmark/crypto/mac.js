'use strict';

const common = require('../common.js');
const { hasOpenSSL } = require('../../test/common/crypto.js');
const assert = require('node:assert');
const {
  createHmac,
  createMac,
  getMacs,
} = require('node:crypto');

if (!hasOpenSSL(3) ||
    process.features.openssl_is_boringssl ||
    typeof createMac !== 'function' ||
    typeof getMacs !== 'function') {
  console.log('Skipping: generic MAC API requires OpenSSL >= 3');
  process.exit(0);
}

const isTest = process.argv.includes('--test');
const configurations = {
  'hmac-sha256': {
    algorithm: 'HMAC',
    key: Buffer.alloc(32, 0x42),
    options: { digest: 'SHA256' },
  },
  'kmac-128': {
    algorithm: 'KMAC-128',
    key: Buffer.alloc(32, 0x42),
    options: { outputLength: 32 },
  },
};

const bench = common.createBenchmark(main, {
  operation: [
    'get-macs-cold',
    'get-macs-warm',
    'create-cold',
    'create-warm',
    'create-hmac',
    'update',
    'stream',
  ],
  algorithm: Object.keys(configurations),
  length: [0, 64, 4096],
  n: [1, 10_000, 20_000, 500_000],
}, {
  combinationFilter({ operation, algorithm, length, n }) {
    if (isTest) {
      return algorithm === 'hmac-sha256' && length === 0 && n === 1;
    }

    if (operation === 'get-macs-cold') {
      return algorithm === 'hmac-sha256' && length === 0 && n === 1;
    }
    if (operation === 'get-macs-warm') {
      return algorithm === 'hmac-sha256' && length === 0 && n === 500_000;
    }
    if (operation === 'create-cold')
      return length === 0 && n === 1;
    if (operation === 'create-warm')
      return length === 0 && n === 20_000;
    if (operation === 'create-hmac' && algorithm !== 'hmac-sha256')
      return false;
    return n === 10_000;
  },
  test: {
    algorithm: ['hmac-sha256'],
    length: [0],
    n: [1],
  },
});

function main({ operation, algorithm, length, n }) {
  const configuration = configurations[algorithm];
  const data = Buffer.alloc(length, 0x61);

  switch (operation) {
    case 'get-macs-cold':
      measureGetMacs(n, false);
      break;
    case 'get-macs-warm':
      measureGetMacs(n, true);
      break;
    case 'create-cold':
      measureCreate(configuration, n, false);
      break;
    case 'create-warm':
      measureCreate(configuration, n, true);
      break;
    case 'create-hmac':
      measureCreateHmac(configuration, data, n);
      break;
    case 'update':
      measureUpdate(configuration, data, n);
      break;
    case 'stream':
      measureStream(configuration, data, n);
      break;
    default:
      throw new Error(`unknown operation: ${operation}`);
  }
}

function measureGetMacs(n, warm) {
  if (warm)
    getMacs();

  let result;
  bench.start();
  for (let i = 0; i < n; ++i)
    result = getMacs();
  bench.end(n);

  assert(Array.isArray(result));
}

function measureCreate({ algorithm, key, options }, n, warm) {
  if (warm)
    createMac(algorithm, key, options).final();

  const contexts = new Array(n);
  bench.start();
  for (let i = 0; i < n; ++i)
    contexts[i] = createMac(algorithm, key, options);
  bench.end(n);

  assert.strictEqual(typeof contexts[n - 1], 'object');
}

function measureCreateHmac({ key, options }, data, n) {
  createHmac(options.digest, key).update(data).digest();

  let result;
  bench.start();
  for (let i = 0; i < n; ++i)
    result = createHmac(options.digest, key).update(data).digest();
  bench.end(n);

  assert(Buffer.isBuffer(result));
}

function measureUpdate({ algorithm, key, options }, data, n) {
  createMac(algorithm, key, options).update(data).final();

  let result;
  bench.start();
  for (let i = 0; i < n; ++i)
    result = createMac(algorithm, key, options).update(data).final();
  bench.end(n);

  assert(Buffer.isBuffer(result));
}

function measureStream({ algorithm, key, options }, data, n) {
  const warmup = createMac(algorithm, key, options);
  warmup.end(data);
  warmup.read();

  let result;
  bench.start();
  for (let i = 0; i < n; ++i) {
    const context = createMac(algorithm, key, options);
    context.end(data);
    result = context.read();
  }
  bench.end(n);

  assert(Buffer.isBuffer(result));
}
