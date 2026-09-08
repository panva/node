// Flags: --no-warnings
'use strict';

// ECDH retains the provider representation of its local key across
// computeSecret() calls. Every mutation of the key must drop it, otherwise
// derivation would keep using the superseded private scalar.

const common = require('../common');
if (!common.hasCrypto) common.skip('missing crypto');

const assert = require('assert');
const { createECDH } = require('crypto');

for (const curve of ['prime256v1', 'secp384r1', 'secp521r1']) {
  const local = createECDH(curve);
  const peer = createECDH(curve);
  local.generateKeys();
  peer.generateKeys();

  // The generated key is retained, so the first and the second derivation
  // take different paths through the cache.
  assert.deepStrictEqual(local.computeSecret(peer.getPublicKey()),
                         peer.computeSecret(local.getPublicKey()));
  assert.deepStrictEqual(local.computeSecret(peer.getPublicKey()),
                         peer.computeSecret(local.getPublicKey()));

  // setPrivateKey() replaces both the scalar and the derived public point.
  // A stale cache would derive from the previous scalar and disagree.
  local.setPrivateKey(Buffer.from([1]));
  assert.deepStrictEqual(local.computeSecret(peer.getPublicKey()),
                         peer.computeSecret(local.getPublicKey()));

  // setPublicKey() (deprecated, see DEP0031) makes the pair inconsistent,
  // and restoring it makes derivation work again.
  const publicKey = local.getPublicKey();
  local.setPublicKey(peer.getPublicKey());
  assert.throws(() => local.computeSecret(peer.getPublicKey()),
                { code: 'ERR_CRYPTO_INVALID_KEYPAIR' });
  local.setPublicKey(publicKey);
  assert.deepStrictEqual(local.computeSecret(peer.getPublicKey()),
                         peer.computeSecret(local.getPublicKey()));

  // Regenerating installs a fresh retained key.
  local.generateKeys();
  assert.deepStrictEqual(local.computeSecret(peer.getPublicKey()),
                         peer.computeSecret(local.getPublicKey()));
}
