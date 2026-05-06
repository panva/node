'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const { hasOpenSSL } = require('../common/crypto');

if (hasOpenSSL(3))
  common.skip('requires OpenSSL < 3');

assert.throws(
  () => crypto.createKmac(),
  { code: 'ERR_CRYPTO_KMAC_NOT_SUPPORTED' });
