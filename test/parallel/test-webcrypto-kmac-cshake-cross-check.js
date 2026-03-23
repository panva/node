'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(4))
  common.skip('requires OpenSSL >= 4.0 for cSHAKE functionName support');

const assert = require('assert');
const { subtle } = globalThis.crypto;

const vectors = require('../fixtures/crypto/kmac')();

// NIST SP 800-185 encoding primitives used to construct KMAC input from
// its components so we can cross-check against cSHAKE with functionName="KMAC".
//
// KMAC128(K, X, L, S) =
//   cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(L),
//             L, "KMAC", S)
// KMAC256(K, X, L, S) =
//   cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L),
//             L, "KMAC", S)

// left_encode(x): big-endian encoding of x prefixed with the byte count.
function leftEncode(x) {
  if (x === 0) return Buffer.from([1, 0]);
  const bytes = [];
  let v = x;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([bytes.length, ...bytes]);
}

// right_encode(x): big-endian encoding of x suffixed with the byte count.
function rightEncode(x) {
  if (x === 0) return Buffer.from([0, 1]);
  const bytes = [];
  let v = x;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([...bytes, bytes.length]);
}

// encode_string(S) = left_encode(len(S) * 8) || S
function encodeString(s) {
  return Buffer.concat([leftEncode(s.length * 8), s]);
}

// bytepad(X, w) = left_encode(w) || X || 0*  (padded to multiple of w)
function bytepad(x, w) {
  const prefix = leftEncode(w);
  const z = Buffer.concat([prefix, x]);
  const padLen = w - (z.length % w);
  if (padLen === w) return z;
  return Buffer.concat([z, Buffer.alloc(padLen)]);
}

// Build the full cSHAKE input corresponding to KMAC(K, X, L, S):
//   bytepad(encode_string(K), rate) || X || right_encode(L)
function buildKmacCshakeInput(key, data, outputLengthBits, rate) {
  return Buffer.concat([
    bytepad(encodeString(key), rate),
    data,
    rightEncode(outputLengthBits),
  ]);
}

const encode = (str) => new TextEncoder().encode(str);

(async () => {
  for (const { algorithm, key, data, customization, outputLength, expected }
    of vectors) {
    const cshakeName = algorithm === 'KMAC128' ? 'cSHAKE128' : 'cSHAKE256';
    // cSHAKE128 rate = 168, cSHAKE256 rate = 136
    const rate = algorithm === 'KMAC128' ? 168 : 136;

    const cshakeInput = buildKmacCshakeInput(key, data, outputLength, rate);

    const cshakeParams = {
      name: cshakeName,
      outputLength,
      functionName: encode('KMAC'),
    };

    if (customization !== undefined) {
      cshakeParams.customization = customization;
    }

    const [kmacResult, cshakeResult] = await Promise.all([
      // Compute via KMAC sign
      (async () => {
        const kmacKey = await subtle.importKey(
          'raw-secret', key, { name: algorithm }, false, ['sign']);
        return subtle.sign(
          { name: algorithm, outputLength, customization }, kmacKey, data);
      })(),
      // Compute via cSHAKE with functionName="KMAC" and the manually
      // constructed input
      subtle.digest(cshakeParams, cshakeInput),
    ]);

    // Both must match the expected NIST vector
    assert.deepStrictEqual(
      Buffer.from(kmacResult),
      expected,
      `${algorithm} KMAC sign result mismatch`,
    );
    assert.deepStrictEqual(
      Buffer.from(cshakeResult),
      expected,
      `${algorithm} cSHAKE cross-check mismatch for vector with ` +
      `${customization ? `customization="${customization}"` : 'no customization'}`,
    );
  }
})().then(common.mustCall());
