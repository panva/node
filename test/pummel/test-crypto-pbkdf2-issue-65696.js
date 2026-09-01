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
const os = require('os');
const { getFips, pbkdf2, pbkdf2Sync } = require('crypto');
const { subtle } = globalThis.crypto;

const kPassword = 'pass';
const kSalt = Buffer.from('a4b770fbe99a32070d977a04c0ebfde8c4', 'hex');
const kOriginalSalt = Buffer.from(kSalt);
const kExpected = Buffer.from(
  'f6de9e4c4c32a4d293b4415584ac9cca18d7314d01c424650d13e7a853e44d04' +
  'b32d335f56f0940d2cb44e89c94ffbcf15f4c86cdb3c83969077f55aa25176fc',
  'hex');
const kIterations = 1_000_000;
const kLength = 64;
const kBatches = 20;
const kJobs = 32;
const kStarted = Date.now();

const metadata = {
  arch: process.arch,
  batches: kBatches,
  cpuCount: os.cpus().length,
  cpuModels: Array.from(new Set(os.cpus().map(({ model }) => model))),
  execPath: process.execPath,
  fips: getFips(),
  jobs: kJobs,
  opensslIa32cap: process.env.OPENSSL_ia32cap || 'unset',
  osRelease: os.release(),
  platform: process.platform,
  sharedOpenSSL: Boolean(process.config.variables.node_shared_openssl),
  threadpoolSize: process.env.UV_THREADPOOL_SIZE || 'default',
  version: process.version,
  versions: process.versions,
};

console.log(`PBKDF2 issue 65696 metadata: ${JSON.stringify(metadata)}`);

function deriveNodePbkdf2(password, salt) {
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, kIterations, kLength, 'sha256',
           (error, actual) => {
             if (error) {
               reject(error);
             } else {
               resolve(actual);
             }
           });
  });
}

async function deriveWebCrypto(password, salt) {
  const key = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']);
  const actual = await subtle.deriveBits({
    hash: 'SHA-256',
    iterations: kIterations,
    name: 'PBKDF2',
    salt,
  }, key, kLength * 8);
  return new Uint8Array(actual);
}

function inspectResult(api, batch, index, actual) {
  const actualBuffer = Buffer.from(
    actual.buffer, actual.byteOffset, actual.byteLength);
  if (actualBuffer.equals(kExpected)) {
    return undefined;
  }
  const mismatchOffsets = [];
  const length = Math.max(actualBuffer.length, kExpected.length);
  for (let offset = 0; offset < length; offset++) {
    if (actualBuffer[offset] !== kExpected[offset]) {
      mismatchOffsets.push(offset);
    }
  }
  return {
    actual: actualBuffer.toString('hex'),
    api,
    batch,
    block1Matches: actualBuffer.subarray(0, 32)
      .equals(kExpected.subarray(0, 32)),
    block2Matches: actualBuffer.subarray(32, 64)
      .equals(kExpected.subarray(32, 64)),
    expected: kExpected.toString('hex'),
    index,
    length: actualBuffer.length,
    mismatchOffsets,
  };
}

function inspectError(api, batch, index, error) {
  return {
    api,
    batch,
    error: error?.stack ? error.stack : String(error),
    index,
  };
}

async function runBatch(api, derive, batch) {
  const failures = [];
  const syncFailure = inspectResult(
    'crypto.pbkdf2Sync',
    batch,
    'sync',
    pbkdf2Sync(kPassword, kSalt, kIterations, kLength, 'sha256'));
  if (syncFailure) {
    failures.push(syncFailure);
  }

  const settled = await Promise.allSettled(Array.from(
    { length: kJobs },
    () => derive(kPassword, kSalt)));
  for (let index = 0; index < settled.length; index++) {
    const result = settled[index];
    if (result.status === 'rejected') {
      failures.push(inspectError(api, batch, index, result.reason));
    } else {
      const failure = inspectResult(api, batch, index, result.value);
      if (failure) {
        failures.push(failure);
      }
    }
  }

  if (!kSalt.equals(kOriginalSalt)) {
    failures.push({
      actualSalt: kSalt.toString('hex'),
      api,
      batch,
      expectedSalt: kOriginalSalt.toString('hex'),
      error: 'salt mutated',
    });
  }

  if (failures.length !== 0) {
    console.error(`PBKDF2 issue 65696 failure metadata: ${
      JSON.stringify(metadata)}`);
    for (const failure of failures) {
      console.error(`PBKDF2 issue 65696 failure: ${JSON.stringify(failure)}`);
    }
    assert.fail(`${failures.length} PBKDF2 failure(s) in ${api} batch ${batch}`);
  }

  console.log(`${api} batch ${batch + 1}/${kBatches} passed; ` +
              `elapsedMs=${Date.now() - kStarted}`);
}

async function runApi(api, derive) {
  for (let batch = 0; batch < kBatches; batch++) {
    await runBatch(api, derive, batch);
  }
}

async function main() {
  await runApi('crypto.pbkdf2', deriveNodePbkdf2);
  await runApi('WebCrypto', deriveWebCrypto);
}

main().then(common.mustCall());
