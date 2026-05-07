# HPKE

<!--introduced_in=REPLACEME-->

> Stability: 1.1 - Active development

<!-- source_link=lib/hpke.js -->

The `node:hpke` module provides an implementation of Hybrid Public Key
Encryption (HPKE) as specified by [RFC 9180][].

HPKE combines a key encapsulation mechanism (KEM), key derivation function
(KDF), and authenticated encryption with associated data (AEAD) algorithm into
a cipher suite. Both sender and recipient must use the same cipher suite.

The module is only available under the `node:` scheme or an alias as
[`crypto.hpke`][].

Only Base mode and PSK mode are supported. Auth and AuthPSK modes, sender IKM,
string suite parsing, GREASE, and sequence setters are not exposed.

All non-key byte inputs in this module must be one of {ArrayBuffer}, {Buffer},
{TypedArray}, or {DataView}. Strings are only accepted by key input objects in
the same places as other `node:crypto` key APIs, such as [`crypto.sign()`][] and
[`crypto.verify()`][].

## Determining if HPKE is available

It is possible for Node.js to be built without including support for the
`node:crypto` module. In such cases, attempting to call `require('node:hpke')`
will result in an error being thrown.

HPKE requires OpenSSL 3.2 or later. The [`hpke.constants`][] object is populated
from OpenSSL. Loading `node:hpke`, or accessing [`crypto.hpke`][], throws
[`ERR_CRYPTO_HPKE_NOT_SUPPORTED`][] when HPKE is not available in the OpenSSL
version used by Node.js.

When using CommonJS, the error thrown when `node:hpke` is not available can be
caught using try/catch:

```cjs
let hpke;
try {
  hpke = require('node:hpke');
} catch (err) {
  console.error('HPKE support is disabled!');
}
```

When using the lexical ESM `import` keyword, the error can only be
caught if a handler for `process.on('uncaughtException')` is registered
_before_ any attempt to load the module is made (using, for instance,
a preload module).

When using ESM, if there is a chance that the code may be run on a build of
Node.js where HPKE support is not available, consider using the [`import()`][]
function instead of the lexical `import` keyword:

```mjs
let hpke;
try {
  hpke = await import('node:hpke');
} catch (err) {
  console.error('HPKE support is disabled!');
}
```

## Examples

```cjs
const {
  generateKeyPairSync,
} = require('node:crypto');
const {
  constants,
  createRecipientContext,
  createSenderContext,
} = require('node:hpke');

const {
  AEAD_AES_128_GCM,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} = constants;

const suite = {
  kemId: KEM_DHKEM_X25519_HKDF_SHA256,
  kdfId: KDF_HKDF_SHA256,
  aeadId: AEAD_AES_128_GCM,
};
const {
  publicKey,
  privateKey,
} = generateKeyPairSync('x25519');
const info = Buffer.from('application context');
const sender = createSenderContext(suite, publicKey, {
  info,
});
const recipient = createRecipientContext(
  suite,
  privateKey,
  sender.encapsulatedKey,
  { info });
const aad1 = Buffer.from('message-id-1');
const ciphertext1 = sender.seal(Buffer.from('first message'), aad1);
const aad2 = Buffer.from('message-id-2');
const ciphertext2 = sender.seal(Buffer.from('second message'), aad2);

console.log(recipient.open(ciphertext1, aad1).toString());
// Prints: first message
console.log(recipient.open(ciphertext2, aad2).toString());
// Prints: second message
```

Using PSK mode:

```cjs
const {
  generateKeyPairSync,
} = require('node:crypto');
const {
  constants,
  createRecipientContext,
  createSenderContext,
} = require('node:hpke');

const suite = {
  kemId: constants.KEM_DHKEM_X25519_HKDF_SHA256,
  kdfId: constants.KDF_HKDF_SHA256,
  aeadId: constants.AEAD_AES_128_GCM,
};
const {
  publicKey,
  privateKey,
} = generateKeyPairSync('x25519');
const psk = Buffer.alloc(32, 1);
const pskId = Buffer.from('psk-id');
const sender = createSenderContext(suite, publicKey, {
  psk,
  pskId,
});
const recipient = createRecipientContext(
  suite,
  privateKey,
  sender.encapsulatedKey,
  {
    psk,
    pskId,
  });

console.log(recipient.open(sender.seal(Buffer.from('message'))).toString());
// Prints: message
```

Using one-shot encryption:

```cjs
const {
  generateKeyPairSync,
} = require('node:crypto');
const {
  constants,
  open,
  seal,
} = require('node:hpke');

const suite = {
  kemId: constants.KEM_DHKEM_X25519_HKDF_SHA256,
  kdfId: constants.KDF_HKDF_SHA256,
  aeadId: constants.AEAD_AES_128_GCM,
};
const {
  publicKey,
  privateKey,
} = generateKeyPairSync('x25519');
const options = {
  aad: Buffer.from('metadata'),
  info: Buffer.from('application context'),
};
const {
  encapsulatedKey,
  ciphertext,
} = seal(suite, publicKey, Buffer.from('single message'), options);
const plaintext = open(
  suite,
  privateKey,
  encapsulatedKey,
  ciphertext,
  options);

console.log(plaintext.toString());
// Prints: single message
```

Using export-only mode:

```cjs
const {
  generateKeyPairSync,
} = require('node:crypto');
const {
  constants,
  receiveExport,
  sendExport,
} = require('node:hpke');

const suite = {
  kemId: constants.KEM_DHKEM_X25519_HKDF_SHA256,
  kdfId: constants.KDF_HKDF_SHA256,
  aeadId: constants.AEAD_EXPORT_ONLY,
};
const {
  publicKey,
  privateKey,
} = generateKeyPairSync('x25519');
const label = Buffer.from('session key');
const {
  encapsulatedKey,
  exportedSecret: senderSecret,
} = sendExport(suite, publicKey, label, 32);
const recipientSecret = receiveExport(
  suite,
  privateKey,
  encapsulatedKey,
  label,
  32);

console.log(senderSecret.equals(recipientSecret));
// Prints: true
```

## Interface: `CipherSuite`

<!-- YAML
added: REPLACEME
-->

* `kemId` {number} Identifier for the HPKE KEM.
* `kdfId` {number} Identifier for the HPKE KDF.
* `aeadId` {number} Identifier for the HPKE AEAD.

The `CipherSuite` interface identifies the HPKE KEM, KDF, and AEAD used by an
HPKE context or one-shot operation. Use the KEM, KDF, and AEAD identifiers
exported by [`hpke.constants`][]. Both sender and recipient must use the same
`CipherSuite`.

## Class: `SenderContext`

<!-- YAML
added: REPLACEME
-->

The [`hpke.createSenderContext()`][] method is used to create `SenderContext`
instances. `SenderContext` objects are not to be created directly using the
`new` keyword.

A `SenderContext` is stateful. Each successful [`senderContext.seal()`][] call
advances the context's internal sequence number.

### `senderContext.encapsulatedKey`

<!-- YAML
added: REPLACEME
-->

* {Buffer}

The encapsulated public key that must be sent to the recipient. A new {Buffer}
copy is returned on each access.

### `senderContext.seal(plaintext[, aad])`

<!-- YAML
added: REPLACEME
-->

* `plaintext` {ArrayBuffer|Buffer|TypedArray|DataView}
* `aad` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {Buffer}

Encrypts `plaintext` and authenticates `aad`. Each successful call advances the
context's internal sequence number. `plaintext` must be at least 1 byte.

For export-only suites, this method throws [`ERR_CRYPTO_INVALID_STATE`][].

### `senderContext.export(label, length)`

<!-- YAML
added: REPLACEME
-->

* `label` {ArrayBuffer|Buffer|TypedArray|DataView}
* `length` {number} A non-negative integer not greater than
  [`buffer.constants.MAX_LENGTH`][].
* Returns: {KeyObject}

Exports a secret of `length` bytes from the HPKE context and returns it as a
secret {KeyObject}. `label` is the HPKE exporter context and should be chosen
to domain-separate the secret's intended use. `label` must not be longer than
[`hpke.constants.MAX_PARAMETER_LENGTH`][]. OpenSSL enforces its HPKE exporter
limits for `length`.

## Class: `RecipientContext`

<!-- YAML
added: REPLACEME
-->

The [`hpke.createRecipientContext()`][] method is used to create
`RecipientContext` instances. `RecipientContext` objects are not to be created
directly using the `new` keyword.

A `RecipientContext` is stateful. Each successful [`recipientContext.open()`][]
call advances the context's internal sequence number.

### `recipientContext.open(ciphertext[, aad])`

<!-- YAML
added: REPLACEME
-->

* `ciphertext` {ArrayBuffer|Buffer|TypedArray|DataView}
* `aad` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {Buffer}

Decrypts `ciphertext` and authenticates `aad`. Ciphertexts must be opened in
the same order they were produced by the matching sender context; recipient
contexts do not support re-sequencing.

For export-only suites, this method throws [`ERR_CRYPTO_INVALID_STATE`][].

### `recipientContext.export(label, length)`

<!-- YAML
added: REPLACEME
-->

* `label` {ArrayBuffer|Buffer|TypedArray|DataView}
* `length` {number} A non-negative integer not greater than
  [`buffer.constants.MAX_LENGTH`][].
* Returns: {KeyObject}

Exports a secret of `length` bytes from the HPKE context and returns it as a
secret {KeyObject}. `label` is the HPKE exporter context and should be chosen
to domain-separate the secret's intended use. `label` must not be longer than
[`hpke.constants.MAX_PARAMETER_LENGTH`][]. The same `label` and `length`
produce the same secret as the sender context when both contexts were
initialized with matching inputs.

## `node:hpke` module methods and properties

### `hpke.seal(suite, publicKey, plaintext[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `publicKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient public key.
* `plaintext` {ArrayBuffer|Buffer|TypedArray|DataView}
* `options` {Object}
  * `aad` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {Object}
  * `encapsulatedKey` {Buffer}
  * `ciphertext` {Buffer}

Creates a sender context with [`hpke.createSenderContext()`][], seals
`plaintext`, and returns the encapsulated public key and ciphertext. Use this
one-shot API when only one message is sent to a recipient.

If `publicKey` is not a [`KeyObject`][], this function behaves as if
`publicKey` had been passed to [`crypto.createPublicKey()`][].

### `hpke.open(suite, privateKey, encapsulatedKey, ciphertext[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `privateKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient private key.
* `encapsulatedKey` {ArrayBuffer|Buffer|TypedArray|DataView}
* `ciphertext` {ArrayBuffer|Buffer|TypedArray|DataView}
* `options` {Object}
  * `aad` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {Buffer}

Creates a recipient context with [`hpke.createRecipientContext()`][] and opens
`ciphertext`. Use this one-shot API when only one message is received from a
sender.

If `privateKey` is not a [`KeyObject`][], this function behaves as if
`privateKey` had been passed to [`crypto.createPrivateKey()`][].

### `hpke.sendExport(suite, publicKey, label, length[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `publicKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient public key.
* `label` {ArrayBuffer|Buffer|TypedArray|DataView}
* `length` {number} A non-negative integer not greater than
  [`buffer.constants.MAX_LENGTH`][].
* `options` {Object}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {Object}
  * `encapsulatedKey` {Buffer}
  * `exportedSecret` {KeyObject}

Creates a sender context with [`hpke.createSenderContext()`][], exports a
secret of `length` bytes, and returns the encapsulated public key and exported
secret. Use this one-shot API when only one exported secret is needed.

If `publicKey` is not a [`KeyObject`][], this function behaves as if
`publicKey` had been passed to [`crypto.createPublicKey()`][].

### `hpke.receiveExport(suite, privateKey, encapsulatedKey, label, length[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `privateKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient private key.
* `encapsulatedKey` {ArrayBuffer|Buffer|TypedArray|DataView}
* `label` {ArrayBuffer|Buffer|TypedArray|DataView}
* `length` {number} A non-negative integer not greater than
  [`buffer.constants.MAX_LENGTH`][].
* `options` {Object}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {KeyObject}

Creates a recipient context with [`hpke.createRecipientContext()`][] and
exports a secret of `length` bytes. Use this one-shot API when only one
exported secret is needed.

If `privateKey` is not a [`KeyObject`][], this function behaves as if
`privateKey` had been passed to [`crypto.createPrivateKey()`][].

### `hpke.createSenderContext(suite, publicKey[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `publicKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient public key.
* `options` {Object}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {SenderContext}

Creates an HPKE sender context. If neither `psk` nor `pskId` is provided, Base
mode is used. If both are provided, PSK mode is used. Providing exactly one of
`psk` or `pskId` throws.

Use a sender context to seal multiple ordered messages to the same recipient,
amortizing the cost of HPKE setup.

If `publicKey` is not a [`KeyObject`][], this function behaves as if
`publicKey` had been passed to [`crypto.createPublicKey()`][].

Node.js enforces the HPKE parameter limits exposed in [`hpke.constants`][] for
`info`, `psk`, and `pskId`. `pskId` must not contain null bytes.

### `hpke.createRecipientContext(suite, privateKey, encapsulatedKey[, options])`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `privateKey` {Object|string|ArrayBuffer|Buffer|TypedArray|DataView|KeyObject}
  The recipient private key.
* `encapsulatedKey` {ArrayBuffer|Buffer|TypedArray|DataView}
* `options` {Object}
  * `info` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `psk` {ArrayBuffer|Buffer|TypedArray|DataView}
  * `pskId` {ArrayBuffer|Buffer|TypedArray|DataView}
* Returns: {RecipientContext}

Creates an HPKE recipient context. OpenSSL validates that `encapsulatedKey` is
valid for the selected suite. The `info`, `psk`, and `pskId` rules are the same
as for [`hpke.createSenderContext()`][].

Use a recipient context to open multiple ordered messages from the same sender.

If `privateKey` is not a [`KeyObject`][], this function behaves as if
`privateKey` had been passed to [`crypto.createPrivateKey()`][].

### `hpke.isSuiteSupported(suite)`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* Returns: {boolean}

Returns `true` if the HPKE suite is supported by the current OpenSSL build.

### `hpke.getPublicEncapSize(suite)`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* Returns: {number}

Returns the encapsulated public key size for `suite`, or `0` if OpenSSL does
not support `suite`.

### `hpke.getCiphertextSize(suite, plaintextLength)`

<!-- YAML
added: REPLACEME
-->

* `suite` {CipherSuite}
* `plaintextLength` {number} A non-negative integer not greater than
  [`buffer.constants.MAX_LENGTH`][].
* Returns: {number}

Returns the ciphertext size for `suite` and `plaintextLength`, or `0` if
OpenSSL cannot compute the size.

### `hpke.constants`

<!-- YAML
added: REPLACEME
-->

* {Object}

An object containing HPKE constants. See [HPKE Constants][].

## HPKE Constants

The following constants are exported by [`hpke.constants`][].

### KEM identifiers

These constants are identifiers for an HPKE KEM.

<table>
  <tr>
    <th>Constant</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>KEM_DHKEM_P256_HKDF_SHA256</code></td>
    <td>Identifier for the HPKE KEM DHKEM using P-256 and
    HKDF-SHA256.</td>
  </tr>
  <tr>
    <td><code>KEM_DHKEM_P384_HKDF_SHA384</code></td>
    <td>Identifier for the HPKE KEM DHKEM using P-384 and
    HKDF-SHA384.</td>
  </tr>
  <tr>
    <td><code>KEM_DHKEM_P521_HKDF_SHA512</code></td>
    <td>Identifier for the HPKE KEM DHKEM using P-521 and
    HKDF-SHA512.</td>
  </tr>
  <tr>
    <td><code>KEM_DHKEM_X25519_HKDF_SHA256</code></td>
    <td>Identifier for the HPKE KEM DHKEM using X25519 and
    HKDF-SHA256.</td>
  </tr>
  <tr>
    <td><code>KEM_DHKEM_X448_HKDF_SHA512</code></td>
    <td>Identifier for the HPKE KEM DHKEM using X448 and
    HKDF-SHA512.</td>
  </tr>
</table>

### KDF identifiers

These constants are identifiers for an HPKE KDF.

<table>
  <tr>
    <th>Constant</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>KDF_HKDF_SHA256</code></td>
    <td>Identifier for the HPKE KDF HKDF-SHA256.</td>
  </tr>
  <tr>
    <td><code>KDF_HKDF_SHA384</code></td>
    <td>Identifier for the HPKE KDF HKDF-SHA384.</td>
  </tr>
  <tr>
    <td><code>KDF_HKDF_SHA512</code></td>
    <td>Identifier for the HPKE KDF HKDF-SHA512.</td>
  </tr>
</table>

### AEAD identifiers

These constants are identifiers for an HPKE AEAD.

<table>
  <tr>
    <th>Constant</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>AEAD_AES_128_GCM</code></td>
    <td>Identifier for the HPKE AEAD AES-128-GCM.</td>
  </tr>
  <tr>
    <td><code>AEAD_AES_256_GCM</code></td>
    <td>Identifier for the HPKE AEAD AES-256-GCM.</td>
  </tr>
  <tr>
    <td><code>AEAD_ChaCha20Poly1305</code></td>
    <td>Identifier for the HPKE AEAD ChaCha20-Poly1305.</td>
  </tr>
  <tr>
    <td><code>AEAD_EXPORT_ONLY</code></td>
    <td>Identifier for the HPKE export-only AEAD, for contexts that only allow
    secret export.</td>
  </tr>
</table>

### Parameter limits

These constants describe OpenSSL HPKE parameter limits.

<table>
  <tr>
    <th>Constant</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>MAX_PARAMETER_LENGTH</code></td>
    <td>Maximum length, in bytes, for OpenSSL HPKE parameter inputs such as
    labels and PSKs.</td>
  </tr>
  <tr>
    <td><code>MIN_PSK_LENGTH</code></td>
    <td>Minimum PSK length, in bytes.</td>
  </tr>
  <tr>
    <td><code>MAX_INFO_LENGTH</code></td>
    <td>Maximum length, in bytes, for the HPKE <code>info</code>
    parameter.</td>
  </tr>
</table>

[HPKE Constants]: #hpke-constants
[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180
[`ERR_CRYPTO_HPKE_NOT_SUPPORTED`]: errors.md#err_crypto_hpke_not_supported
[`ERR_CRYPTO_INVALID_STATE`]: errors.md#err_crypto_invalid_state
[`KeyObject`]: crypto.md#class-keyobject
[`buffer.constants.MAX_LENGTH`]: buffer.md#bufferconstantsmax_length
[`crypto.createPrivateKey()`]: crypto.md#cryptocreateprivatekeykey
[`crypto.createPublicKey()`]: crypto.md#cryptocreatepublickeykey
[`crypto.hpke`]: crypto.md#cryptohpke
[`crypto.sign()`]: crypto.md#cryptosignalgorithm-data-key-callback
[`crypto.verify()`]: crypto.md#cryptoverifyalgorithm-data-key-signature-callback
[`hpke.constants.MAX_PARAMETER_LENGTH`]: #parameter-limits
[`hpke.constants`]: #hpkeconstants
[`hpke.createRecipientContext()`]: #hpkecreaterecipientcontextsuite-privatekey-encapsulatedkey-options
[`hpke.createSenderContext()`]: #hpkecreatesendercontextsuite-publickey-options
[`import()`]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/import
[`recipientContext.open()`]: #recipientcontextopenciphertext-aad
[`senderContext.seal()`]: #sendercontextsealplaintext-aad
