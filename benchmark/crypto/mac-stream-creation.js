// Throughput benchmark
// creates a new MAC object for each input, then pushes data through it
'use strict';

const common = require('../common.js');
const { hasOpenSSL } = require('../../test/common/crypto.js');
const crypto = require('crypto');

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
  n: [500],
  method: methods,
  type: ['asc', 'utf', 'buf'],
  out: ['hex', 'binary', 'buffer'],
  len: [2, 1024, 102400, 1024 * 1024],
  api: ['legacy', 'stream'],
}, {
  test: {
    api: ['legacy', 'stream'],
    method: hasOpenSSL(3) ? ['hmac-sha256', 'kmac-128'] : ['hmac-sha256'],
  },
});

const key = Buffer.alloc(32);

function createMac(method) {
  switch (method) {
    case 'hmac-sha256':
      return crypto.createHmac('sha256', key);
    case 'hmac-sha512':
      return crypto.createHmac('sha512', key);
    case 'kmac-128':
      return crypto.createKmac('kmac-128', key);
    case 'kmac-256':
      return crypto.createKmac('kmac-256', key);
    default:
      throw new Error(`unknown method: ${method}`);
  }
}

function main({ api, type, len, out, n, method }) {
  let message;
  let encoding;
  switch (type) {
    case 'asc':
      message = 'a'.repeat(len);
      encoding = 'ascii';
      break;
    case 'utf':
      message = 'ü'.repeat(len / 2);
      encoding = 'utf8';
      break;
    case 'buf':
      message = Buffer.alloc(len, 'b');
      break;
    default:
      throw new Error(`unknown message type: ${type}`);
  }

  const fn = api === 'stream' ? streamWrite : legacyWrite;

  bench.start();
  fn(method, message, encoding, n, len, out);
}

function legacyWrite(method, message, encoding, n, len, outEnc) {
  const written = n * len;
  const bits = written * 8;
  const gbits = bits / (1024 * 1024 * 1024);

  while (n-- > 0) {
    const mac = createMac(method);
    mac.update(message, encoding);
    mac.digest(outEnc);
  }

  bench.end(gbits);
}

function streamWrite(method, message, encoding, n, len, outEnc) {
  const written = n * len;
  const bits = written * 8;
  const gbits = bits / (1024 * 1024 * 1024);

  while (n-- > 0) {
    const mac = createMac(method);

    if (outEnc !== 'buffer')
      mac.setEncoding(outEnc);

    mac.write(message, encoding);
    mac.end();
    mac.read();
  }

  bench.end(gbits);
}
