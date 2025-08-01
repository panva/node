import { hasOpenSSL } from '../../common/crypto.js'

const pqc = hasOpenSSL(3, 5);

export const vectors = {
  'encapsulateBits': [
    [false, ''],
    [false, 'ML-KEM-512'],
    [false, 'ML-KEM-768'],
    [false, 'ML-KEM-1024'],
  ],
  'encapsulateKey': [],
  'decapsulateBits': [
    [false, ''],
    [false, 'ML-KEM-512'],
    [false, 'ML-KEM-768'],
    [false, 'ML-KEM-1024'],
  ],
  'decapsulateKey': [],
  'sign': [
    [pqc, 'ML-DSA-44'],
    [pqc, 'ML-DSA-65'],
    [pqc, 'ML-DSA-87'],
  ],
  'generateKey': [
    [pqc, 'ML-DSA-44'],
    [pqc, 'ML-DSA-65'],
    [pqc, 'ML-DSA-87'],
  ],
  'importKey': [
    [pqc, 'ML-DSA-44'],
    [pqc, 'ML-DSA-65'],
    [pqc, 'ML-DSA-87'],
  ],
  'exportKey': [
    [pqc, 'ML-DSA-44'],
    [pqc, 'ML-DSA-65'],
    [pqc, 'ML-DSA-87'],
  ],
};
