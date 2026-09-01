'use strict';

const common = require('../common');

if (!common.hasCrypto) {
  common.skip('missing crypto');
}

if ((!common.isWindows || process.arch !== 'x64') &&
    process.env.NODE_TEST_PBKDF2_ISSUE_65696 !== '1') {
  common.skip('Windows x64 reproducer');
}

const assert = require('assert');
const { pbkdf2, pbkdf2Sync } = require('crypto');
const { subtle } = globalThis.crypto;

const kPassword = 'pass';
const kPasswordBytes = new TextEncoder().encode(kPassword);
const kSalt = Buffer.from('a4b770fbe99a32070d977a04c0ebfde8c4', 'hex');
const kExpected = Buffer.from(
  'f6de9e4c4c32a4d293b4415584ac9cca18d7314d01c424650d13e7a853e44d04' +
  'b32d335f56f0940d2cb44e89c94ffbcf15f4c86cdb3c83969077f55aa25176fc',
  'hex');
const kIterations = 1_000_000;
const kLength = 64;
const kJobs = 32;

console.log(
  `Node ${process.version}, OpenSSL ${process.versions.openssl}, ` +
  `platform=${process.platform}, arch=${process.arch}, ` +
  `threadpool=${process.env.UV_THREADPOOL_SIZE || 'default'}`);

function check(api, index, value) {
  const actual = Buffer.from(
    value.buffer, value.byteOffset, value.byteLength);
  if (actual.equals(kExpected)) {
    return;
  }

  const mismatchOffsets = [];
  const length = Math.max(actual.length, kExpected.length);
  for (let offset = 0; offset < length; offset++) {
    if (actual[offset] !== kExpected[offset]) {
      mismatchOffsets.push(offset);
    }
  }

  assert.fail([
    `${api} mismatch index=${index}`,
    `expected=${kExpected.toString('hex')}`,
    `actual=${actual.toString('hex')}`,
    `mismatchOffsets=${mismatchOffsets.join(',')}`,
    `block1Matches=${actual.subarray(0, 32)
      .equals(kExpected.subarray(0, 32))}`,
    `block2Matches=${actual.subarray(32, 64)
      .equals(kExpected.subarray(32, 64))}`,
    `salt=${kSalt.toString('hex')}`,
  ].join('\n'));
}

function deriveCallback() {
  return new Promise((resolve, reject) => {
    pbkdf2(kPassword, kSalt, kIterations, kLength, 'sha256',
           (error, value) => {
             if (error) {
               reject(error);
             } else {
               resolve(value);
             }
           });
  });
}

async function deriveWebCrypto() {
  const key = await subtle.importKey(
    'raw', kPasswordBytes, 'PBKDF2', false, ['deriveBits']);
  const value = await subtle.deriveBits({
    hash: 'SHA-256',
    iterations: kIterations,
    name: 'PBKDF2',
    salt: kSalt,
  }, key, kLength * 8);
  return new Uint8Array(value);
}

async function run(api, derive) {
  const settled = await Promise.allSettled(Array.from(
    { length: kJobs },
    () => derive()));
  for (let index = 0; index < settled.length; index++) {
    const result = settled[index];
    if (result.status === 'rejected') {
      assert.fail(
        `${api} rejected index=${index}\n${result.reason?.stack ||
          result.reason}`);
    }
    check(api, index, result.value);
  }
  console.log(`${api}: ${kJobs} concurrent jobs passed`);
}

async function main() {
  check('crypto.pbkdf2Sync', 'sync',
        pbkdf2Sync(kPassword, kSalt, kIterations, kLength, 'sha256'));
  await run('crypto.pbkdf2', deriveCallback);
  await run('WebCrypto', deriveWebCrypto);
}

main().then(common.mustCall());
