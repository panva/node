'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL3 } = require('../common/crypto');
if (!hasOpenSSL3)
  common.skip('this test requires OpenSSL 3.x');

const tmpdir = require('../common/tmpdir');
const assert = require('node:assert');
const fs = require('node:fs');
const {
  createPrivateKey,
  createPublicKey,
} = require('node:crypto');
const fixtures = require('../common/fixtures');

[
  'http://example.com/key',
  'https://example.com/key',
  'pkcs11://token/key',
  'pkcs11:object=x;type=private?module-name=test',
  'pkcs11:object=x;type=private?module-path=/tmp/provider.so',
  'pkcs11:object=x;type=private?pin-source=file:/tmp/pin',
  'pkcs11:object=x;type=private?pin-value=1234',
  'pkcs11:object=x;type=private?PIN-VALUE=1234',
  'pkcs11:object=x;type=private?%70%69%6e%2d%76%61%6c%75%65=1234',
  'pkcs11:object=x;type=private?pin-value%00=1234',
  'pkcs11:object=x;type=private;module-path=/tmp/provider.so',
  'pkcs11:object=x;type=private;pin-source=file:/tmp/pin',
  'pkcs11:object=x;type=private;pin-value=1234',
  'pkcs11:object=x;type=private;pin%2dvalue=1234',
  'pkcs11:object=x;type=private;pin-value%00=1234',
].forEach((href) => {
  assertStoreOpenFailed(() => createPrivateKey(new URL(href)));
});

function assertStoreOpenFailed(fn) {
  assert.throws(fn, (err) => {
    assert.notStrictEqual(err.code, 'ERR_INVALID_ARG_VALUE');
    assert.match(
      err.message,
      /Failed to open OpenSSL STORE|STORE routines::unsupported/);
    return true;
  });
}

function assertBuiltinStoreRejected(fn) {
  assert.throws(fn, {
    code: 'ERR_INVALID_ARG_VALUE',
    message: /OpenSSL STORE provider URL/,
  });
}

assertBuiltinStoreRejected(
  () => createPrivateKey(fixtures.fileURL('keys', 'rsa_private.pem')));

{
  const url = new URL('pkcs11:object=x;type=private');
  Object.defineProperties(url, {
    href: {
      __proto__: null,
      value: fixtures.fileURL('keys', 'rsa_private.pem').href,
    },
  });

  assertBuiltinStoreRejected(() => createPrivateKey(url));
}

{
  tmpdir.refresh();
  const filename = 'pkcs11:object=x;type=private';
  fs.writeFileSync(
    tmpdir.resolve(filename),
    fixtures.readKey('rsa_private.pem'));

  const cwd = process.cwd();
  try {
    process.chdir(tmpdir.path);
    assertStoreOpenFailed(() => createPrivateKey(new URL(filename)));
  } finally {
    process.chdir(cwd);
  }
}

[
  { href: 1 },
  { href: Symbol('pkcs11') },
].forEach((overrides) => {
  const url = new URL('pkcs11:object=x;type=private');
  const values = {
    __proto__: null,
    href: 'pkcs11:object=x;type=private',
    ...overrides,
  };
  Object.defineProperties(url, {
    href: { __proto__: null, value: values.href },
  });

  assert.throws(() => createPrivateKey(url), {
    code: 'ERR_INVALID_ARG_VALUE',
  });
});

assert.throws(
  () => createPublicKey(new URL('pkcs11:object=x;type=private')),
  {
    code: 'ERR_INVALID_ARG_TYPE',
  });

assert.throws(
  () => createPrivateKey({
    key: new URL('pkcs11:object=x;type=private'),
    format: 'pem',
  }),
  {
    code: 'ERR_INVALID_ARG_VALUE',
  });
