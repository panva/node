'use strict';

const {
  assertCrypto,
} = require('internal/util');

assertCrypto();

module.exports = require('internal/crypto/hpke');
