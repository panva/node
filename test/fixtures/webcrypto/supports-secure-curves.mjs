import { createPrivateKey, createPublicKey } from 'node:crypto';

import { hasFIPS, hasOpenSSL } from '../../common/crypto.js'
import fixtures from '../../common/fixtures.js';

const supportsContext = hasOpenSSL(3, 2);

const { subtle } = globalThis.crypto;

const boringSSL = process.features.openssl_is_boringssl;
const supportsXCurves = !hasFIPS(3, 5);

const x25519PublicKey = createPublicKey(
  fixtures.readKey('x25519_public.pem'))
  .toCryptoKey('X25519', false, []);
let x448PrivateKey;
let x448PublicKey;
let Ed448;
if (!boringSSL) {
  x448PrivateKey = createPrivateKey(fixtures.readKey('x448_private.pem'))
    .toCryptoKey('X448', false, ['deriveBits', 'deriveKey']);
  x448PublicKey = createPublicKey(fixtures.readKey('x448_public.pem'))
    .toCryptoKey('X448', false, []);
  Ed448 = await subtle.generateKey('Ed448', false, ['sign', 'verify'])
}

export const vectors = {
  'sign': [
    [!boringSSL, 'Ed448'],
    [!boringSSL, { name: 'Ed448', context: Buffer.alloc(0) }],
    [!boringSSL && supportsContext, { name: 'Ed448', context: Buffer.alloc(32) }],
  ],
  'generateKey': [
    [!boringSSL && supportsXCurves, 'X448'],
    [!boringSSL, 'Ed448'],
  ],
  'deriveKey': [
    [!boringSSL && supportsXCurves,
     { name: 'X448', public: x448PublicKey },
     { name: 'AES-CBC', length: 128 }],
    [false,
     { name: 'X448', public: x448PublicKey },
     { name: 'HMAC', hash: 'SHA-256' }],
    [!boringSSL && supportsXCurves,
     { name: 'X448', public: x448PublicKey },
     { name: 'HMAC', hash: 'SHA-256', length: 448 }],
    [false,
     { name: 'X448', public: x448PublicKey },
     { name: 'HMAC', hash: 'SHA-256', length: 449 }],
    [!boringSSL && supportsXCurves,
     { name: 'X448', public: x448PublicKey },
     'HKDF'],
  ],
  'deriveBits': [
    [!boringSSL && supportsXCurves, { name: 'X448', public: x448PublicKey }],
    [!boringSSL && supportsXCurves, { name: 'X448', public: x448PublicKey }, 448],
    [false, { name: 'X448', public: x448PublicKey }, 449],
    [false, { name: 'X448', public: x25519PublicKey }],
    [false, { name: 'X448', public: x448PrivateKey }],
    [false, 'X448'],
  ],
  'importKey': [
    [!boringSSL, 'X448'],
    [!boringSSL, 'Ed448'],
  ],
  'exportKey': [
    [!boringSSL, 'Ed448'],
    [!boringSSL, 'X448'],
  ],
};
