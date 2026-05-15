'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const { hasOpenSSL } = require('../common/crypto');

if (!hasOpenSSL(3, 5))
  common.skip('requires OpenSSL >= 3.5');

const assert = require('assert');
const { once } = require('events');
const { KeyObject } = require('crypto');
const { MessageChannel } = require('worker_threads');
const { subtle } = globalThis.crypto;
const { SubtleCrypto } = globalThis;

const algorithm = { name: 'MLKEM768-X25519' };

const vector = {
  seed: [
    '0000000000000000000000000000000000000000000000000000000000000000',
  ].join(''),
  publicKey: [
    '3d209f716752f6408e7f89bceef97ac388530045377927644ef046c0a7cae978',
    'c8841a0133aac4f1e1a7027277f671219cf58b85d29c8fec08edd432e787a3cf',
    '9936fe0026a113cb9efb1d7214049527bfe2141ea170b0294a59403ab0ce1676',
    '0a8baa95b823cbb8aacdcc17ef32775223c791e3740163941f9bb3f63346bef1',
    'c050c31f932c62719429aff14c2bd438ab135bed692d56c77c04cbbffd6335b5',
    '78318b513771e84b14ea821262141ca006ccb8bf2500aa1008970f216fe7f1ae',
    '34125aa290492c069a189222adc322f97649c762c7d3128ad3bb2667971d0744',
    '014bc3b67445cbcd0b3e7ea69fb1cb9f9c331f97487920187292926d04a25a26',
    '50abbd44982bb0c3c6301fe6a61330d24d8a3c7021dc3e3392c79a139b37613b',
    'ba67a2984298507b84a4d61eef18acfb979af2d39caa4c0db4513815359d76fc',
    '378c63a7f4f3053b17168d0221cf0c2eec5514ba235f81d04d67c3b5c5180949',
    '17671c26a7c046457533cc32844581277a03eb065c4529a779a9a5878f2aac3f',
    '81db9ed3d8c9345697058cbb99d379bca16d8fdb61d129960390524791b9d3e5',
    '01b900bd1e5002e095be06c23f1fb212f5801f24b6b28c0c5493d246d02aa29f',
    'a3acfbe15ac4e212eb0b6f69ebbea259a2703aa4c308224bdb741c65c7a5d4bf',
    'f788279507bbfe513d7aa5694e7b3cdf62ab36432742d4a0ca9b3570ba742fa8',
    '03b46989c8526ea586cc4fc32866143b79601725fa545fd280b404530318bbc3',
    '371194710b6d74beaa629eb18a36a953b75915ae96999ba5c88cdc56a46861c5',
    '0032c9b630bcc1445a30878979bc55a2c0955bf399b231203b90c651b6afe0e2',
    '42b5a543250b142f7291ed753d816098f7913302a8ce91641716623d4fc2ac67',
    '72aa5f3674042b7c4a18a2186289a4ac4e200774596ca03e6798c7506b984999',
    'db6ac142586bae0799f1e776f9f5247dc574d8556ddf9bbbc4ca3643263457f7',
    '4248010d62d4311268360aecb4902b450bf2050ecb8ba7a92820d233f5a14ed3',
    '1225a1d17ca6f19e825894cfb1807d922cbd60761134be419144bcf72006366a',
    '4460137ad9136c113f05eb54c409520edc72e4150cc3a24b0f819eec11bbd19c',
    'a9645b0810a60b4a8a9e9c3955396a1653955b047bcf4f98433c27236c570d75',
    'f809e44aaf2dc33665826351872c293350ab324518c8c0c80b521c80c81a56bd',
    'c968a5650315a830c8bb17532c62ccc23b1d46412c256b224fd4674491803501',
    'd0143125c7577239689965b6989ca561793c0f85c62a9e13487da17662a7188c',
    '70b1040a67ed4c3f85e74e3691822fb96314d6134fe6a626b3cbe1461d62a7b5',
    '73b2cc75579ffa22967e36ceb2a1aa0b71875a22751d706b72ca9ecd0c8100ad',
    '0aa58009a5c83fffe91759e6baa0a9345af99fe3b69509dbc84032868844ab3f',
    '65bb1df8beadf36442e48e339c967023a525411544c789a2f04dacd06ffef783',
    '02210450b931f6b4c32aab34a3f5260b810f4c9a946fc22d3baabaa80ba8d995',
    '5d6dc35e8609b4256b482cdc9d8977c1a47a354e7c527fdb1672e166917b95cd',
    '6351820261daab361f8a2dcbb240c55abd6a8105e5291b427b566d731e6b7047',
    '189cff20d8b120e0b3e72472d1b0086812200fd3698e23f06e4f4e08bbb54cc2',
    'f63601b7f85accfeea2d17964c66b5194b0f08e18519faaee194e3c102823062',
  ].join(''),
  ciphertext: [
    'd81018a94f8078e02105beaa814e003390befa4589bb614f77397af42d8e8150',
    '796f2c88a4efca81b8cf93c0ae3716c54ec1b045e3875f38c2dd12d7f717bd7f',
    'b701a9fecda5ed8b764c9a35d4a5c1d8930f6071f653eebb2d1afa77debb8302',
    'd16f17e0f5f3920a71a4d49beafa0e1c7e443f8abca64a65a9e81a97e7357bf9',
    '02573363c0e1a12e5228036828e3f759121fada92441fe334e85d79347e470d2',
    'fed945541d832c54baaa3cb7526c3853954db4f73547cc7c27fd38398bfa7704',
    '952cb841e38b270e4db7435f0ee22f57d7ad3270bd0c88e71b4b864cf2277c65',
    'daa10a6dad4c7abecd95cc4ebec39c08404b522e4ecc1545713f76bebd3b5a0f',
    '2feb3461936065dbd13f6a1f61e1b142a2af2e5a482ba2c50cf0317049c0b3bf',
    'd6d5e9240eba9111d2030fdea17e33b6524020d30b0c4f8069285f3a6ca267d2',
    '87d01e827d8422bf5426e11688bfc73756af1841b1c87e126cb50c914b5b2b86',
    '73488ad3b074cad77a3840eb12dd688f313ee1e9ff8c479a678f276356fc9d65',
    'e1d5b4c1e9855b4175db144f7767c12061769190fe6b5e51563b91f94d131a2b',
    '796bd2980ed0dab4ae7a7110e920007a757158a5eb8662cbf89ddffe9d819682',
    '1313cdc00108853fc4746b111d5b56da638d8ed2973918960f5dfe93ead3ae52',
    '1e957cec3c8d843e8fce234c70ad055177f235439d6098bdd771b1cfcfadaab4',
    'f50a7378185c62409f383c8ff658c2a2af66498cfd81e962766ac6b774e88424',
    'fb4f331837d0a28502708477caf8780a156d723f68fca791e1cd2397bfc2b24c',
    '77c765d9b2af36f732d52107517efd8157b283b440a613f756c364ca108971a8',
    '878199a93f260baec3e850033cc032c2e53f823576affb4d3b116e2d16049152',
    'c35aaa263ab376f0ad5ede6a749607a283e3016e62191c0e8fde33e718cd9895',
    '91c9a205d608d99fcb8a7471603d716cb01b56328d7d880aec2851f4e6d8b501',
    '6c25647e9026ebb441543e8012dbfcf078d4012b8c39184dd64f3821b4774ae4',
    'e36365f8baf2bd1f6667c017a1e65ff8a1554458fb3f367c02721752bfa56fc7',
    'fd566ae95ffb208f919ef12f4cf8a2fdd141a8df559bddb7b8d1f04ee6d4cf78',
    '05d142989caf216dfae985faaab9974f6d9f8aa1129084db8db912b1655f595f',
    'fbaa66491ab4655fd734cfd4bb0c0289d4bcc8fc5e9943b351cb147c8db059a2',
    '4004d1c3e3bb4c14a881e5101acb736c65c5d579acb67ee85a560277b43338fe',
    '79d34b772c5da001da3b5a3383dd81319a0b4542e6d7e46eed5314cc70eb231d',
    'e27b6e760db598ba19995cf69be0e4458e35f3f274aca2455d43fe3344e183c6',
    'dc47c857dbe9907b41e41006d91b25adcafc098fe66f7554be8dad493c4f4b1d',
    'bf7a51464139db474afab5572f92a2232b59be56a72c0505149dae5cde1e6028',
    '77037de7802b5f6fa47a4c9a3e52d6ca15339920254e9ffb53c7b834cc0288ed',
    '9905a1841e9390ea94a8898bd4c6b6d6027e4d43c7867242515bbeefe12340fc',
    '6b3d57762f8badb69433f9c6d060f85f5e5c6b6803a816d141c075f63541ad10',
  ].join(''),
  sharedSecret: [
    'e5ba94031ea6efd69c09c254f6d9783136ba6037e2d4c43bcccf19d6f3f4343a',
  ].join(''),
};

const seed = Buffer.from(vector.seed, 'hex');
const publicKey = Buffer.from(vector.publicKey, 'hex');
const ciphertext = Buffer.from(vector.ciphertext, 'hex');
const sharedSecret = Buffer.from(vector.sharedSecret, 'hex');

assert.strictEqual(seed.byteLength, 32);
assert.strictEqual(publicKey.byteLength, 1216);
assert.strictEqual(ciphertext.byteLength, 1120);
assert.strictEqual(sharedSecret.byteLength, 32);

async function roundTripViaMessageChannel(key) {
  const { port1, port2 } = new MessageChannel();
  port1.postMessage(key);
  const [received] = await once(port2, 'message');
  port1.close();
  port2.close();
  return received;
}

async function testGeneratedRoundTrip() {
  const { privateKey, publicKey } = await subtle.generateKey(
    algorithm,
    true,
    ['encapsulateKey', 'encapsulateBits', 'decapsulateKey', 'decapsulateBits']);

  assert.strictEqual(publicKey.type, 'public');
  assert.strictEqual(privateKey.type, 'private');
  assert.strictEqual(publicKey.algorithm.name, algorithm.name);
  assert.strictEqual(privateKey.algorithm.name, algorithm.name);
  assert.deepStrictEqual(publicKey.usages, ['encapsulateKey', 'encapsulateBits']);
  assert.deepStrictEqual(privateKey.usages, ['decapsulateKey', 'decapsulateBits']);

  const encapsulated = await subtle.encapsulateBits(algorithm, publicKey);
  assert.strictEqual(encapsulated.sharedKey.byteLength, 32);
  assert.strictEqual(encapsulated.ciphertext.byteLength, 1120);

  const decapsulated = await subtle.decapsulateBits(
    algorithm,
    privateKey,
    encapsulated.ciphertext);
  assert(Buffer.from(decapsulated).equals(Buffer.from(encapsulated.sharedKey)));

  const encapsulatedKey = await subtle.encapsulateKey(
    algorithm,
    publicKey,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign']);
  const decapsulatedKey = await subtle.decapsulateKey(
    algorithm,
    privateKey,
    encapsulatedKey.ciphertext,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign']);
  assert(KeyObject.from(encapsulatedKey.sharedKey)
    .export()
    .equals(KeyObject.from(decapsulatedKey).export()));
}

async function testVectorRoundTrip() {
  const privateKey = await subtle.importKey(
    'raw-seed',
    seed,
    algorithm,
    true,
    ['decapsulateBits']);
  const publicKeyFromPrivate = await subtle.getPublicKey(
    privateKey,
    ['encapsulateBits']);
  assert(Buffer.from(await subtle.exportKey('raw-public', publicKeyFromPrivate))
    .equals(publicKey));

  const jwk = await subtle.exportKey('jwk', privateKey);
  assert.strictEqual(jwk.kty, 'AKP');
  assert.strictEqual(jwk.alg, algorithm.name);
  assert(Buffer.from(jwk.pub, 'base64url').equals(publicKey));
  assert(Buffer.from(jwk.priv, 'base64url').equals(seed));

  const jwkPrivateKey = await subtle.importKey(
    'jwk',
    jwk,
    algorithm,
    true,
    ['decapsulateBits']);
  const vectorSharedSecret = await subtle.decapsulateBits(
    algorithm,
    jwkPrivateKey,
    ciphertext);
  assert(Buffer.from(vectorSharedSecret).equals(sharedSecret));

  const publicKeyOnly = await subtle.importKey(
    'raw-public',
    publicKey,
    algorithm,
    true,
    ['encapsulateBits']);
  const clonedPrivateKey = structuredClone(privateKey);
  const clonedPublicKey = structuredClone(publicKeyOnly);
  const portPrivateKey = await roundTripViaMessageChannel(privateKey);
  const portPublicKey = await roundTripViaMessageChannel(publicKeyOnly);
  assert.deepStrictEqual(clonedPrivateKey, privateKey);
  assert.deepStrictEqual(clonedPublicKey, publicKeyOnly);
  assert.deepStrictEqual(portPrivateKey, privateKey);
  assert.deepStrictEqual(portPublicKey, publicKeyOnly);
  assert(Buffer.from(await subtle.exportKey('raw-seed', clonedPrivateKey))
    .equals(seed));
  assert(Buffer.from(await subtle.exportKey('raw-seed', portPrivateKey))
    .equals(seed));
  assert(Buffer.from((await subtle.exportKey('jwk', clonedPrivateKey)).priv, 'base64url')
    .equals(seed));
  assert(Buffer.from((await subtle.exportKey('jwk', portPrivateKey)).priv, 'base64url')
    .equals(seed));

  const clonedPublicKeyFromPrivate = await subtle.getPublicKey(
    clonedPrivateKey,
    ['encapsulateBits']);
  assert(Buffer.from(await subtle.exportKey('raw-public', clonedPublicKeyFromPrivate))
    .equals(publicKey));

  const clonedVectorSharedSecret = await subtle.decapsulateBits(
    algorithm,
    clonedPrivateKey,
    ciphertext);
  assert(Buffer.from(clonedVectorSharedSecret).equals(sharedSecret));
  const portVectorSharedSecret = await subtle.decapsulateBits(
    algorithm,
    portPrivateKey,
    ciphertext);
  assert(Buffer.from(portVectorSharedSecret).equals(sharedSecret));

  const differentX25519Public = Buffer.from(publicKey);
  differentX25519Public[differentX25519Public.length - 1] ^= 1;
  const differentSecondaryPublicKey = await subtle.importKey(
    'raw-public',
    differentX25519Public,
    algorithm,
    true,
    ['encapsulateBits']);
  assert.notDeepStrictEqual(publicKeyOnly, differentSecondaryPublicKey);

  const encapsulated = await subtle.encapsulateBits(algorithm, publicKeyOnly);
  const decapsulated = await subtle.decapsulateBits(
    algorithm,
    privateKey,
    encapsulated.ciphertext);
  assert(Buffer.from(decapsulated).equals(Buffer.from(encapsulated.sharedKey)));
  const clonedDecapsulated = await subtle.decapsulateBits(
    algorithm,
    clonedPrivateKey,
    encapsulated.ciphertext);
  assert(Buffer.from(clonedDecapsulated).equals(Buffer.from(encapsulated.sharedKey)));

  const clonedEncapsulated = await subtle.encapsulateBits(algorithm, clonedPublicKey);
  const originalDecapsulated = await subtle.decapsulateBits(
    algorithm,
    privateKey,
    clonedEncapsulated.ciphertext);
  assert(Buffer.from(originalDecapsulated).equals(Buffer.from(clonedEncapsulated.sharedKey)));

  const portEncapsulated = await subtle.encapsulateBits(algorithm, portPublicKey);
  const portDecapsulated = await subtle.decapsulateBits(
    algorithm,
    privateKey,
    portEncapsulated.ciphertext);
  assert(Buffer.from(portDecapsulated).equals(Buffer.from(portEncapsulated.sharedKey)));
}

async function testFailures() {
  const privateKey = await subtle.importKey(
    'raw-seed',
    seed,
    algorithm,
    true,
    ['decapsulateBits']);
  const publicKeyOnly = await subtle.getPublicKey(privateKey, ['encapsulateBits']);
  const jwk = await subtle.exportKey('jwk', privateKey);

  await assert.rejects(
    subtle.importKey('raw-public', Buffer.alloc(1215), algorithm, true, ['encapsulateBits']),
    { name: 'DataError' });
  await assert.rejects(
    subtle.importKey('raw-seed', Buffer.alloc(31), algorithm, true, ['decapsulateBits']),
    { name: 'DataError' });
  await assert.rejects(
    subtle.importKey('raw-public', publicKey, algorithm, true, ['decapsulateBits']),
    { name: 'SyntaxError' });
  await assert.rejects(
    subtle.importKey('raw-seed', seed, algorithm, true, ['encapsulateBits']),
    { name: 'SyntaxError' });
  await assert.rejects(
    subtle.importKey('raw', publicKey, algorithm, true, ['encapsulateBits']),
    { name: 'NotSupportedError' });
  await assert.rejects(
    subtle.importKey('raw-private', seed, algorithm, true, ['decapsulateBits']),
    { name: 'NotSupportedError' });
  await assert.rejects(
    subtle.exportKey('spki', publicKeyOnly),
    { name: 'NotSupportedError' });
  await assert.rejects(
    subtle.exportKey('pkcs8', privateKey),
    { name: 'NotSupportedError' });
  await assert.rejects(
    subtle.decapsulateBits(algorithm, privateKey, Buffer.alloc(1119)),
    { name: 'OperationError' });
  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, alg: 'ML-KEM-768' },
      algorithm,
      true,
      ['decapsulateBits']),
    { name: 'DataError' });

  const badPublicKey = Buffer.from(publicKey);
  badPublicKey[0] ^= 1;
  await assert.rejects(
    subtle.importKey(
      'jwk',
      { ...jwk, pub: badPublicKey.toString('base64url') },
      algorithm,
      true,
      ['decapsulateBits']),
    { name: 'DataError' });
}

function testSupports() {
  assert(SubtleCrypto.supports('generateKey', algorithm));
  assert(SubtleCrypto.supports('importKey', algorithm));
  assert(SubtleCrypto.supports('exportKey', algorithm));
  assert(SubtleCrypto.supports('getPublicKey', algorithm));
  assert(SubtleCrypto.supports('encapsulateBits', algorithm));
  assert(SubtleCrypto.supports('decapsulateBits', algorithm));
  assert(SubtleCrypto.supports('encapsulateKey', algorithm, 'HKDF'));
  assert(SubtleCrypto.supports('decapsulateKey', algorithm, 'HKDF'));
  assert(!SubtleCrypto.supports('sign', algorithm));
}

(async () => {
  testSupports();
  await testGeneratedRoundTrip();
  await testVectorRoundTrip();
  await testFailures();
})().then(common.mustCall());
