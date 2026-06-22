// META: title=WebCryptoAPI: generateKey() failures for Hybrid KEM
// META: timeout=long
// META: script=../util/helpers.js
// META: script=failures.js
run_test(["MLKEM768-P256", "MLKEM768-X25519", "MLKEM1024-P384"]);
