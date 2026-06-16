// Flags: --permission --allow-crypto-store --allow-fs-read=*
'use strict';

require('../common');
const assert = require('node:assert');

assert.strictEqual(process.permission.has('crypto.store'), true);
process.permission.drop('crypto.store');
assert.strictEqual(process.permission.has('crypto.store'), false);
