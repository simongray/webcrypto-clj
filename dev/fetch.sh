#!/bin/sh
# Download the test vectors of Wycheproof and NIST's GCM vectors, at the
# versions that the tests follow, into dev-resources/.
set -eu

wycheproof=7a325932231bd7a724c791c8b0d65ea4d6d2f435
gcm=https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
gcm_sha256=f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023

cd "$(dirname "$0")/.."
mkdir -p dev-resources/wycheproof dev-resources/nist

for f in aes_gcm_test.json \
         hmac_sha1_test.json hmac_sha256_test.json hmac_sha384_test.json hmac_sha512_test.json \
         hkdf_sha1_test.json hkdf_sha256_test.json hkdf_sha384_test.json hkdf_sha512_test.json \
         pbkdf2_hmacsha1_test.json pbkdf2_hmacsha256_test.json \
         pbkdf2_hmacsha384_test.json pbkdf2_hmacsha512_test.json \
         ecdsa_secp256r1_sha256_p1363_test.json ecdsa_secp384r1_sha384_p1363_test.json \
         ecdsa_secp521r1_sha512_p1363_test.json \
         ecdh_secp256r1_webcrypto_test.json ecdh_secp384r1_webcrypto_test.json \
         ecdh_secp521r1_webcrypto_test.json \
         rsa_signature_2048_sha256_test.json rsa_pkcs1_2048_sig_gen_test.json \
         rsa_pss_2048_sha256_mgf1_32_test.json rsa_pss_misc_test.json \
         ed25519_test.json; do
  curl -sSfL -o "dev-resources/wycheproof/$f" \
    "https://raw.githubusercontent.com/C2SP/wycheproof/$wycheproof/testvectors_v1/$f"
done

# NIST doesn't version the file, so its checksum pins it
curl -sSfL -o dev-resources/nist/gcmtestvectors.zip "$gcm"
echo "$gcm_sha256  dev-resources/nist/gcmtestvectors.zip" | shasum -a 256 -c -
unzip -o -q dev-resources/nist/gcmtestvectors.zip \
  gcmEncryptExtIV128.rsp gcmEncryptExtIV256.rsp gcmDecrypt128.rsp gcmDecrypt256.rsp \
  -d dev-resources/nist
rm dev-resources/nist/gcmtestvectors.zip
