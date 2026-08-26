// Flags: --expose-internals

'use strict';

const common = require('../common');

if (!common.hasCrypto) {
  common.skip('missing crypto');
}

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3) || process.features.openssl_is_boringssl) {
  common.skip('OpenSSL 3 EVP_MAC support is required');
}

const assert = require('node:assert');
const crypto = require('node:crypto');
const { encodingsMap } = require('internal/util');
const {
  createHmac,
  createMac,
  createSecretKey,
  getMacs,
  mac,
} = crypto;

const availableMacs = new Set(getMacs());

assert.strictEqual(typeof mac, 'function');

if (!availableMacs.has('hmac')) {
  common.printSkipMessage('HMAC is not available from the active providers');
} else {
  const algorithm = 'HMAC';
  const options = { digest: 'sha256' };
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const data = Buffer.from('The quick brown fox jumps over the lazy dog');
  const expected = createHmac('sha256', key).update(data).digest();
  const expectedEmpty = createHmac('sha256', key).digest();

  const result = mac(algorithm, key, data, options);
  assert(Buffer.isBuffer(result));
  assert.deepStrictEqual(result, expected);
  assert.deepStrictEqual(mac(algorithm, key, data, {
    ...options,
    outputEncoding: undefined,
  }), expected);
  assert.deepStrictEqual(mac(algorithm, key, '', options), expectedEmpty);
  assert.deepStrictEqual(
    mac(algorithm, key, Buffer.alloc(0), options),
    expectedEmpty,
  );
  assert.deepStrictEqual(
    mac(algorithm, Buffer.alloc(0), data, options),
    createHmac('sha256', Buffer.alloc(0)).update(data).digest(),
  );
  assert.deepStrictEqual(
    mac(algorithm, key, data.toString(), options),
    createMac(algorithm, key, options).update(data.toString()).final(),
  );

  for (const outputEncoding of Object.keys(encodingsMap)) {
    const encoded = mac(algorithm, key, data, {
      ...options,
      outputEncoding,
    });
    if (outputEncoding === 'buffer') {
      assert(Buffer.isBuffer(encoded));
      assert.deepStrictEqual(encoded, expected);
    } else {
      assert.strictEqual(encoded, expected.toString(outputEncoding));
    }
  }

  const nullPrototypeOptions = Object.assign({ __proto__: null }, options);
  assert.deepStrictEqual(
    mac(algorithm, key, data, nullPrototypeOptions),
    expected,
  );
  const inheritedUnknownOptions = Object.assign(
    { __proto__: { unknown: true } }, options);
  assert.deepStrictEqual(
    mac(algorithm, key, data, inheritedUnknownOptions),
    expected,
  );
  assert.deepStrictEqual(
    mac(algorithm, key, data, { ...options, unknown: true }),
    expected,
  );

  const optionReads = [];
  const getterOptions = { __proto__: null };
  const getterValues = {
    __proto__: null,
    digest: 'sha256',
    outputEncoding: 'hex',
  };
  for (const name of [
    'digest',
    'cipher',
    'iv',
    'customization',
    'salt',
    'outputLength',
    'outputEncoding',
  ]) {
    Object.defineProperty(getterOptions, name, {
      __proto__: null,
      get() {
        optionReads.push(name);
        return getterValues[name];
      },
    });
  }
  Object.defineProperty(getterOptions, 'unknown', {
    __proto__: null,
    get: common.mustNotCall(),
  });
  assert.strictEqual(
    mac(algorithm, key, data, getterOptions),
    expected.toString('hex'),
  );
  assert.deepStrictEqual(optionReads, [
    'digest',
    'cipher',
    'iv',
    'customization',
    'salt',
    'outputLength',
    'outputEncoding',
  ]);

  // BufferSource keys and data must honor view offsets and lengths.
  const keyStorage = Uint8Array.from([0xff, ...key, 0xff]);
  const keyView = new Uint8Array(keyStorage.buffer, 1, key.length);
  const keyDataView = new DataView(keyStorage.buffer, 1, key.length);
  const dataStorage = Uint8Array.from([0xff, ...data, 0xff]);
  const dataView = new DataView(dataStorage.buffer, 1, data.length);
  assert.deepStrictEqual(mac(algorithm, keyView, dataView, options), expected);
  assert.deepStrictEqual(
    mac(algorithm, keyDataView, dataView, options),
    expected,
  );

  const arrayBufferKey = key.buffer.slice(
    key.byteOffset,
    key.byteOffset + key.byteLength,
  );
  assert.deepStrictEqual(
    mac(algorithm, arrayBufferKey, dataView, options),
    expected,
  );
  assert.deepStrictEqual(
    mac(algorithm, createSecretKey(key), dataView, options),
    expected,
  );
}

// An output encoding string is shorthand for an options object. Poly1305 does
// not require any other options, making the shorthand independently testable.
if (!availableMacs.has('poly1305')) {
  common.printSkipMessage('Poly1305 is not available from the active providers');
} else {
  const key = Buffer.from(
    '85d6be7857556d337f4452fe42d506a8' +
    '0103808afb0db2fd4abff6af4149f51b',
    'hex',
  );
  const data = Buffer.from('Cryptographic Forum Research Group');
  const expected = createMac('poly1305', key).update(data).final();

  assert.strictEqual(mac('poly1305', key, data, 'hex'),
                     expected.toString('hex'));
  assert.strictEqual(mac('poly1305', key, data, { outputEncoding: 'hex' }),
                     expected.toString('hex'));
  const explicitBuffer = mac('poly1305', key, data, 'buffer');
  assert(Buffer.isBuffer(explicitBuffer));
  assert.deepStrictEqual(explicitBuffer, expected);
}

(async () => {
  const esmCrypto = await import('node:crypto');
  assert.strictEqual(esmCrypto.mac, mac);
})().then(common.mustCall());
