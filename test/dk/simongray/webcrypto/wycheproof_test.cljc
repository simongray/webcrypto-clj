(ns dk.simongray.webcrypto.wycheproof-test
  "The library against the test vectors of Wycheproof, from the files that
  dev/fetch.sh puts in dev-resources/wycheproof.

  A vector that the library refuses on purpose (an AES key of 192 bits, an
  IV outside 12 to 128 bytes, a PBKDF2 password that isn't UTF-8) must be
  refused with not-supported-error. The vectors that WebCrypto can't take
  are skipped: PBKDF2 with 16,777,216 iterations, which takes too long,
  SHA-224, and RSA-PSS whose MGF1 has another hash than the signature."
  (:require [clojure.test :refer [deftest is]]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.asymmetric-test :as asymmetric-test]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]
            [dk.simongray.webcrypto.test-support :as support :refer [all fails-with run then]]))

(defn groups
  "The test groups of the Wycheproof file `name` as maps with keyword keys,
  whose :tests are such maps too."
  [name]
  (for [group (get (support/json (str "wycheproof/" name)) "testGroups")]
    (-> (update-keys group keyword)
        (update :tests (partial map #(update-keys % keyword))))))

(defn cases
  "Each test of the Wycheproof file `name` with the members of its group."
  [name]
  (for [group (groups name)
        test  (:tests group)]
    (merge (dissoc group :tests) test)))

(defn hex
  "The bytes of the hex `s`."
  [s]
  (bytes/from-hex s))

(def hashes
  "The hash of each file of Wycheproof, by its name in the file's name."
  {"sha1" :sha-1 "sha256" :sha-256 "sha384" :sha-384 "sha512" :sha-512})

(defn- truncated
  "The first `bits` bits of the bytes `b`."
  [b bits]
  (bytes/slice b 0 (quot bits 8)))

(deftest hmac
  (doseq [[h hash-name] hashes
          {:keys [tcId key msg tag tagSize result]} (cases (str "hmac_" h "_test.json"))]
    (is (= (= "valid" result)
           (= tag (bytes/hex (truncated (hash/hmac hash-name (hex key) (hex msg)) tagSize))))
        (str "HMAC by " h ", test " tcId))))

(deftest hmac-verify
  (run #(all (for [[h hash-name]                            hashes
                   {:keys [tcId key msg tag tagSize result]} (cases (str "hmac_" h "_test.json"))
                   :when (= tagSize (* 8 (bytes/length (hash/digest hash-name (bytes/of [])))))]
               (then (webcrypto/import-key :raw (hex key) {:name :hmac :hash hash-name} false [:verify])
                     (fn [k]
                       (then (webcrypto/verify :hmac k (hex tag) (hex msg))
                             (fn [verified]
                               (is (= (= "valid" result) verified)
                                   (str "HMAC by " h ", test " tcId))))))))))

(deftest hkdf
  (run #(all (for [[h hash-name]                               hashes
                   {:keys [tcId ikm salt info size okm result]} (cases (str "hkdf_" h "_test.json"))
                   :let [why    (str "HKDF by " h ", test " tcId)
                         params {:name :hkdf :hash hash-name :salt (hex salt) :info (hex info)}]]
               (if (= "valid" result)
                 (do (is (= okm (bytes/hex (hash/hkdf hash-name (hex ikm) (hex salt) (hex info) size)))
                         why)
                     (then (webcrypto/import-key :raw (hex ikm) :hkdf false [:derive-bits])
                           (fn [k]
                             (then (webcrypto/derive-bits params k (* 8 size))
                                   (fn [bits] (is (= okm (bytes/hex bits)) why))))))
                 (all [(fails-with :operation-error why
                                   (fn [] (hash/hkdf hash-name (hex ikm) (hex salt) (hex info) size)))
                       (fails-with :operation-error why
                                   (fn []
                                     (then (webcrypto/import-key :raw (hex ikm) :hkdf false [:derive-bits])
                                           (fn [k] (webcrypto/derive-bits params k (* 8 size))))))]))))))

(deftest pbkdf2
  (run #(all (for [[h hash-name] hashes
                   {:keys [tcId password salt iterationCount dkLen dk flags]}
                   (cases (str "pbkdf2_hmac" h "_test.json"))
                   :when (not (some #{"LargeIterationCount"} flags))
                   :let [why    (str "PBKDF2 by " h ", test " tcId)
                         params {:name :pbkdf2 :hash hash-name :salt (hex salt) :iterations iterationCount}
                         import (fn [] (webcrypto/import-key :raw (hex password) :pbkdf2 false [:derive-bits]))]]
               (if (some #{"NonUtf8"} flags)
                 (fails-with :not-supported-error why import)
                 (then (import)
                       (fn [k]
                         (then (webcrypto/derive-bits params k (* 8 dkLen))
                               (fn [bits] (is (= dk (bytes/hex bits)) why))))))))))

(defn- gcm-params
  "The AES-GCM parameters of a test of Wycheproof."
  [{:keys [iv aad tagSize]}]
  {:name :aes-gcm :iv (hex iv) :additional-data (hex aad) :tag-length tagSize})

(defn- check-gcm
  "Check the AES-GCM test `t` of Wycheproof with the `key`, which encrypts
  and decrypts."
  [key {:keys [tcId msg ct tag result ivSize] :as t}]
  (let [why    (str "AES-GCM, test " tcId)
        params (gcm-params t)]
    (cond
      (zero? ivSize)
      (fails-with :operation-error why #(webcrypto/encrypt params key (hex msg)))

      (not (<= 96 ivSize 1024))
      (fails-with :not-supported-error why #(webcrypto/encrypt params key (hex msg)))

      (= "valid" result)
      (then (all [(webcrypto/encrypt params key (hex msg))
                  (webcrypto/decrypt params key (hex (str ct tag)))])
            (fn [[sealed opened]]
              (is (= (str ct tag) (bytes/hex sealed)) why)
              (is (= msg (bytes/hex opened)) why)))

      :else
      (fails-with :operation-error why #(webcrypto/decrypt params key (hex (str ct tag)))))))

(deftest aes-gcm
  (run #(all (for [{:keys [tcId key keySize] :as t} (cases "aes_gcm_test.json")
                   :let [import (fn [] (webcrypto/import-key :raw (hex key) :aes-gcm false [:encrypt :decrypt]))]]
               (if (= 192 keySize)
                 (fails-with :not-supported-error (str "AES-GCM, test " tcId) import)
                 (then (import) (fn [k] (check-gcm k t))))))))

(def sha-names
  "The hash of each name of a hash in Wycheproof that the library has."
  {"SHA-1" :sha-1 "SHA-256" :sha-256 "SHA-384" :sha-384 "SHA-512" :sha-512})

(defn- check-signatures
  "Check that the public `key` verifies the valid signatures of the
  Wycheproof `tests` by the `algorithm` and no others. An acceptable
  signature can go either way."
  [key algorithm why tests]
  (all (for [{:keys [tcId msg sig result]} tests
             :when (not= "acceptable" result)]
         (then (webcrypto/verify algorithm key (hex sig) (hex msg))
               (fn [verified]
                 (is (= (= "valid" result) verified) (str why ", test " tcId)))))))

(def ecdsa-files
  "The Wycheproof file of ECDSA of each curve and its hash."
  {:p-256 ["ecdsa_secp256r1_sha256_p1363_test.json" :sha-256]
   :p-384 ["ecdsa_secp384r1_sha384_p1363_test.json" :sha-384]
   :p-521 ["ecdsa_secp521r1_sha512_p1363_test.json" :sha-512]})

(deftest ecdsa
  (run #(all (for [[curve [file hash]]          ecdsa-files
                   {:keys [publicKeyDer tests]} (groups file)
                   :let [algorithm {:name :ecdsa :named-curve curve}]]
               (then (webcrypto/import-key :spki (hex publicKeyDer) algorithm false [:verify])
                     (fn [k]
                       (check-signatures k {:name :ecdsa :hash hash} (str "ECDSA on " (name curve))
                                         tests)))))))

(def ecdh-files
  "The Wycheproof file of ECDH of each curve, with keys as JWKs."
  {:p-256 "ecdh_secp256r1_webcrypto_test.json"
   :p-384 "ecdh_secp384r1_webcrypto_test.json"
   :p-521 "ecdh_secp521r1_webcrypto_test.json"})

(defn- shared-secret
  "The secret that ECDH by the `algorithm` derives from the JWKs `public`
  and `private`, maps with string keys."
  [algorithm public private]
  (then (all [(webcrypto/import-key :jwk (update-keys public keyword) algorithm false [])
              (webcrypto/import-key :jwk (update-keys private keyword) algorithm false [:derive-bits])])
        (fn [[public-key private-key]]
          (webcrypto/derive-bits {:name :ecdh :public public-key} private-key nil))))

;; The invalid tests have public keys that aren't on the curve
(deftest ecdh
  (run #(all (for [[curve file]                             ecdh-files
                   {:keys [tcId public private shared result]} (cases file)
                   :let [algorithm {:name :ecdh :named-curve curve}
                         why       (str "ECDH on " (name curve) ", test " tcId)]]
               (if (= "valid" result)
                 (then (shared-secret algorithm public private)
                       (fn [secret] (is (= shared (bytes/hex secret)) why)))
                 (fails-with :data-error why (fn [] (shared-secret algorithm public private))))))))

(deftest rsassa-pkcs1-v1_5
  (run #(all (for [{:keys [publicKeyDer sha tests]} (groups "rsa_signature_2048_sha256_test.json")
                   :let [algorithm {:name :rsassa-pkcs1-v1_5 :hash (sha-names sha)}]]
               (then (webcrypto/import-key :spki (hex publicKeyDer) algorithm false [:verify])
                     (fn [k] (check-signatures k :rsassa-pkcs1-v1_5 "RSASSA-PKCS1-v1_5" tests)))))
       #(all (for [{:keys [privateKeyPkcs8 sha tests]} (groups "rsa_pkcs1_2048_sig_gen_test.json")
                   :when (sha-names sha)
                   :let [algorithm {:name :rsassa-pkcs1-v1_5 :hash (sha-names sha)}]]
               (then (webcrypto/import-key :pkcs8 (hex privateKeyPkcs8) algorithm false [:sign])
                     (fn [k]
                       (all (for [{:keys [tcId msg sig]} tests]
                              (then (webcrypto/sign :rsassa-pkcs1-v1_5 k (hex msg))
                                    (fn [signature]
                                      (is (= sig (bytes/hex signature))
                                          (str "RSASSA-PKCS1-v1_5 signing, test " tcId))))))))))))

(deftest rsa-pss
  (run #(all (for [{:keys [publicKeyDer sha mgfSha sLen tests]}
                   (mapcat groups ["rsa_pss_2048_sha256_mgf1_32_test.json" "rsa_pss_misc_test.json"])
                   :when (and (= sha mgfSha) (sha-names sha))
                   :let [algorithm {:name :rsa-pss :hash (sha-names sha)}]]
               (then (webcrypto/import-key :spki (hex publicKeyDer) algorithm false [:verify])
                     (fn [k]
                       (check-signatures k {:name :rsa-pss :salt-length sLen}
                                         (str "RSA-PSS with " sha " and a salt of " sLen)
                                         tests)))))))

(deftest ed25519
  (run #(all (for [{:keys [publicKeyDer tests]} (groups "ed25519_test.json")
                   :when asymmetric-test/ed25519?]
               (then (webcrypto/import-key :spki (hex publicKeyDer) :ed25519 false [:verify])
                     (fn [k] (check-signatures k :ed25519 "Ed25519" tests)))))))
