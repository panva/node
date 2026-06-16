// Flags: --permission --allow-fs-read=*
'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('node:assert');
const { createPrivateKey } = require('node:crypto');

assert.strictEqual(process.permission.has('crypto.store'), false);

const url = new URL('pkcs11:object=my-key;type=private');
assert.throws(
  () => createPrivateKey(url),
  (err) => {
    assert.strictEqual(err.code, 'ERR_ACCESS_DENIED');
    assert.strictEqual(err.permission, 'CryptoStore');
    assert.strictEqual(err.resource, url.href);
    return true;
  });
