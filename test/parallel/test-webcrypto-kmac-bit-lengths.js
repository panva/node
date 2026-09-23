'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const { getHashes } = require('crypto');
const { subtle } = globalThis.crypto;
if (!getHashes().includes('cshake128') || !getHashes().includes('cshake256'))
  common.skip('requires cSHAKE support');

// Generated using bit-string SP 800-185 framing over XKCP's CompactFIPS202.py,
// independently checked against the six published NIST KMAC sample vectors.
// https://github.com/XKCP/XKCP/blob/50b9d37b499db213826f1012d3c25ef17b114c14/Standalone/CompactFIPS202/Python/CompactFIPS202.py
// The prototype preserves high-aligned raw/JWK key tails and shifts them to
// Keccak's low bits. Outputs use Keccak packing with unused high bits clear.
const vectors = [
  ['KMAC128', 32, 9,
   '3a01'],
  ['KMAC128', 33, 1,
   '01'],
  ['KMAC128', 33, 255,
   'b0a0020f2808766d541273cf977d88c5deb0f492725fcae30712ca063da45764'],
  ['KMAC128', 39, 7,
   '09'],
  ['KMAC128', 128, 257,
   '5125718934394d6e7434908cad8212d1f5dc3c1425ae093dc86f4aabe44ece4301'],
  ['KMAC128', 129, 256,
   '0d4b34e94f16f6e8a94fb2ad84705e0d54c10a72b3fe60baa6173d13d5cc9e2f'],
  ['KMAC256', 32, 9,
   'b501'],
  ['KMAC256', 33, 1,
   '00'],
  ['KMAC256', 33, 255,
   'd47293342ebcf65892a356b4e3fea6a29c2186d361ef760f2fd272d5afd47d0e'],
  ['KMAC256', 39, 7,
   '16'],
  ['KMAC256', 128, 257,
   '163d00cb53233c815c168b9bb5231ba75d8cdd0e458b196e3419feb71ae4020f00'],
  ['KMAC256', 129, 256,
   '169825f32cc67284565265107502be966d9d2093eb739a3ac376ee711b505efe'],
  ['KMAC128', 1303, 9,
   '7301'],
  ['KMAC128', 1304, 9,
   'e100'],
  ['KMAC128', 1305, 9,
   'ce00'],
  ['KMAC256', 1047, 9,
   '5401'],
  ['KMAC256', 1048, 9,
   'e401'],
  ['KMAC256', 1049, 9,
   'b401'],
];

(async () => {
  for (const [name, length, outputLength, expected] of vectors) {
    const raw = Buffer.alloc(Math.ceil(length / 8));
    for (let i = 0; i < raw.length; i++)
      raw[i] = (0xa3 + 29 * i) & 0xff;
    if (length % 8 !== 0) {
      raw[raw.length - 1] |= 0x80;
      raw[raw.length - 1] &= 0xff << (8 - length % 8);
    }
    const key = await subtle.importKey(
      'raw-secret', raw, { name, length }, false, ['sign', 'verify']);
    const params = { name, outputLength, customization: Buffer.from('Bit KAT') };
    const data = Buffer.from('0001020304050607', 'hex');
    const signature = await subtle.sign(params, key, data);
    assert.strictEqual(Buffer.from(signature).toString('hex'), expected);
    assert(await subtle.verify(params, key, Buffer.from(expected, 'hex'), data));

    const invalid = Buffer.from(expected, 'hex');
    invalid[0] ^= 1;
    assert.strictEqual(await subtle.verify(params, key, invalid, data), false);
    if (outputLength % 8 !== 0) {
      const noncanonical = Buffer.from(expected, 'hex');
      noncanonical[noncanonical.length - 1] |= 0x80;
      assert.strictEqual(await subtle.verify(params, key, noncanonical, data), false);
    }
  }
})().then(common.mustCall());
