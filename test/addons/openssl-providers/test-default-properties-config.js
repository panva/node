'use strict';

const common = require('../../common');
const fixtures = require('../../common/fixtures');
const providers = require('./providers.cjs');

const assert = require('node:assert');
const { fork } = require('node:child_process');
const { createHash, getHashes } = require('node:crypto');
const option = `--openssl-config=${fixtures.path(
  'openssl3-conf',
  'default_properties.cnf',
)}`;

if (!process.execArgv.includes(option)) {
  const cp = fork(__filename, { execArgv: [option] });
  cp.on('exit', common.mustCall((code, signal) => {
    assert.strictEqual(code, 0);
    assert.strictEqual(signal, null);
  }));
  return;
}

assert(providers.getCurrentProviders().includes('default'));
assert(providers.getCurrentProviders().includes('legacy'));
providers.testProviderPresent('default');

const hashes = getHashes();
for (const hash of ['md4', 'whirlpool']) {
  assert(!hashes.includes(hash));
  assert.throws(() => createHash(hash), { code: 'ERR_OSSL_EVP_UNSUPPORTED' });
}
