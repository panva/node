'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3, 5))
  common.skip('requires OpenSSL >= 3.5');

const assert = require('assert');
const {
  randomBytes,
  sign,
  verify,
} = require('crypto');

const fixtures = require('../common/fixtures');

function getKeyFileName(type, suffix) {
  return `${type.replaceAll('-', '_')}_${suffix}.pem`;
}

for (const [asymmetricKeyType, sigLen] of [
  ['slh-dsa-sha2-128f', 17088],
  ['slh-dsa-sha2-128s', 7856],
  ['slh-dsa-sha2-192f', 35664],
  ['slh-dsa-sha2-192s', 16224],
  ['slh-dsa-sha2-256f', 49856],
  ['slh-dsa-sha2-256s', 29792],
  ['slh-dsa-shake-128f', 17088],
  ['slh-dsa-shake-128s', 7856],
  ['slh-dsa-shake-192f', 35664],
  ['slh-dsa-shake-192s', 16224],
  ['slh-dsa-shake-256f', 49856],
  ['slh-dsa-shake-256s', 29792],
]) {
  const keys = {
    public: fixtures.readKey(getKeyFileName(asymmetricKeyType, 'public'), 'ascii'),
    private: fixtures.readKey(getKeyFileName(asymmetricKeyType, 'private'), 'ascii'),
  };

  for (const data of [randomBytes(0), randomBytes(32)]) {
    // sync
    {
      const signature = sign(undefined, data, keys.private);
      assert.strictEqual(signature.byteLength, sigLen);
      assert.strictEqual(verify(undefined, randomBytes(32), keys.public, signature), false);
      assert.strictEqual(verify(undefined, data, keys.public, Buffer.alloc(sigLen)), false);
      assert.strictEqual(verify(undefined, data, keys.public, signature), true);
      assert.strictEqual(verify(undefined, data, keys.private, signature), true);
      assert.throws(() => sign('sha256', data, keys.private), { code: 'ERR_OSSL_INVALID_DIGEST' });
      assert.throws(
        () => verify('sha256', data, keys.public, Buffer.alloc(sigLen)),
        { code: 'ERR_OSSL_INVALID_DIGEST' });
    }

    // async
    {
      sign(undefined, data, keys.private, common.mustSucceed((signature) => {
        assert.strictEqual(signature.byteLength, sigLen);
        verify(undefined, data, keys.private, signature, common.mustSucceed((valid) => {
          assert.strictEqual(valid, true);
        }));
        verify(undefined, data, keys.private, Buffer.alloc(sigLen), common.mustSucceed((valid) => {
          assert.strictEqual(valid, false);
        }));
      }));

      sign('sha256', data, keys.private, common.expectsError(/invalid digest/));
      verify('sha256', data, keys.public, Buffer.alloc(sigLen), common.expectsError(/invalid digest/));
    }
  }
}
