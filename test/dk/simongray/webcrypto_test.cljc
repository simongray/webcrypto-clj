(ns dk.simongray.webcrypto-test
  "The Web Cryptography API on both platforms: digests, HMAC, AES-GCM, HKDF
  and PBKDF2 by the test vectors of their standards, keys as raw bytes and
  as JWK, and the errors that each platform throws alike."
  (:require [clojure.test :refer [deftest is]]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]
            [dk.simongray.webcrypto.hash-test :as hash-test]
            [dk.simongray.webcrypto.test-support :refer [all fails-with outcome run then]]))

(deftest digests
  (run #(all (for [[h examples]       hash-test/fips-180
                   [message expected] examples]
               (then (webcrypto/digest h (bytes/encode message))
                     (fn [d] (is (= expected (bytes/hex d)) (str h))))))))

(defn hmac-key
  "A promise of the HMAC key of the hex `k` by the `hash`, which signs and
  verifies."
  [k hash]
  (webcrypto/import-key :raw (bytes/from-hex k) {:name :hmac :hash hash} true [:sign :verify]))

(defn check-hmac
  "Check that the HMAC `key` signs the bytes `data` by the `hash` as RFC
  4231 `expected`, and verifies the HMAC alone."
  [key hash data expected]
  (let [mac (hash/hmac hash (bytes/from-hex (:key expected)) data)]
    (then (all [(webcrypto/sign :hmac key data)
                (webcrypto/verify :hmac key mac data)
                (webcrypto/verify :hmac key (bytes/concat (bytes/slice mac 1) (bytes/of [0])) data)
                (webcrypto/verify :hmac key (bytes/slice mac 0 16) data)])
          (fn [[signature right wrong truncated]]
            (is (= (expected hash) (subs (bytes/hex signature) 0 (count (expected hash)))))
            (is (true? right))
            (is (false? wrong))
            (is (false? truncated) "a truncated HMAC doesn't verify")))))

;; RFC 4231, section 4
(deftest hmac
  (run #(all (for [c hash-test/rfc-4231
                   h [:sha-256 :sha-384 :sha-512]]
               (then (hmac-key (:key c) h)
                     (fn [k] (check-hmac k h (bytes/from-hex (:data c)) c)))))
       #(then (webcrypto/generate-key {:name :hmac :hash :sha-512} false [:sign])
              (fn [k]
                (is (= {:type         :secret
                        :extractable? false
                        :algorithm    {:name :hmac :hash :sha-512 :length 1024}
                        :usages       #{:sign}}
                       (webcrypto/key-info k))
                    "a key of HMAC has the hash's block size by default")))))

;; The test cases 3 and 4 of the GCM's specification by McGrew and Viega,
;; which NIST published with SP 800-38D
(def gcm-cases
  "The key, IV, additional data, plaintext and ciphertext with its tag, in
  hex."
  (let [plaintext (str "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        sealed    (str "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                       "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")]
    [{:key        "feffe9928665731c6d6a8f9467308308"
      :iv         "cafebabefacedbaddecaf888"
      :aad        nil
      :plaintext  plaintext
      :ciphertext (str sealed "473f5985" "4d5c2af327cd64a62cf35abd2ba6fab4")}
     {:key        "feffe9928665731c6d6a8f9467308308"
      :iv         "cafebabefacedbaddecaf888"
      :aad        "feedfacedeadbeeffeedfacedeadbeefabaddad2"
      :plaintext  (subs plaintext 0 120)
      :ciphertext (str sealed "5bc94fbc3221a5db94fae95ae7121a47")}]))

(defn gcm-params
  "The AES-GCM parameters of the hex `iv` and `aad`."
  [iv aad]
  (cond-> {:name :aes-gcm :iv (bytes/from-hex iv)}
    aad (assoc :additional-data (bytes/from-hex aad))))

(defn aes-key
  "A promise of the AES-GCM key of the hex `k` with the `usages`."
  [k usages]
  (webcrypto/import-key :raw (bytes/from-hex k) :aes-gcm false usages))

(deftest aes-gcm
  (run #(all (for [{:keys [key iv aad plaintext ciphertext]} gcm-cases
                   :let [params (gcm-params iv aad)]]
               (then (aes-key key [:encrypt :decrypt])
                     (fn [k]
                       (then (all [(webcrypto/encrypt params k (bytes/from-hex plaintext))
                                   (webcrypto/decrypt params k (bytes/from-hex ciphertext))])
                             (fn [[sealed opened]]
                               (is (= ciphertext (bytes/hex sealed)))
                               (is (= plaintext (bytes/hex opened)))))))))
       #(then (webcrypto/generate-key {:name :aes-gcm :length 128} false [:encrypt :decrypt])
              (fn [k]
                (let [params {:name :aes-gcm :iv (webcrypto/random-bytes 12) :tag-length 96}]
                  (then (webcrypto/encrypt params k (bytes/encode "a secret"))
                        (fn [sealed]
                          (is (= (+ 8 12) (bytes/length sealed)) "a tag of 96 bits")
                          (then (webcrypto/decrypt params k sealed)
                                (fn [opened] (is (= "a secret" (bytes/decode opened))))))))))))

(defn flipped
  "A copy of the bytes `b` with a bit of the byte at `i` flipped."
  [b i]
  (let [c (bytes/slice b 0)]
    (aset c i (#?(:clj unchecked-byte :cljs identity) (bit-xor 1 (bit-and (aget c i) 0xff))))
    c))

(deftest changed-ciphertexts
  (let [{:keys [key iv aad ciphertext]} (second gcm-cases)
        sealed                          (bytes/from-hex ciphertext)
        changes                         [["a changed ciphertext" (gcm-params iv aad) (flipped sealed 0)]
                                         ["a changed tag" (gcm-params iv aad) (flipped sealed 75)]
                                         ["other additional data" (gcm-params iv nil) sealed]
                                         ["another IV" (gcm-params (str "00" (subs iv 2)) aad) sealed]
                                         ["a ciphertext shorter than a tag" (gcm-params iv aad) (bytes/of [1 2 3])]]]
    (run #(then (aes-key key [:decrypt])
                (fn [k]
                  (all (for [[why params data] changes]
                         (fails-with :operation-error why (fn [] (webcrypto/decrypt params k data))))))))))

;; RFC 5869, Appendix A, where WebCrypto needs the zeros of case 7's salt
(deftest hkdf
  (run #(all (for [[i {:keys [hash length ikm salt info okm]}] (map-indexed vector hash-test/rfc-5869)
                   :let [params {:name :hkdf
                                 :hash hash
                                 :salt (or (some-> salt bytes/from-hex) (bytes/of (repeat 20 0)))
                                 :info (bytes/from-hex info)}]]
               (then (webcrypto/import-key :raw (bytes/from-hex ikm) :hkdf false [:derive-bits])
                     (fn [k]
                       (then (webcrypto/derive-bits params k (* 8 length))
                             (fn [bits] (is (= okm (bytes/hex bits)) (str "case " (inc i)))))))))))

;; RFC 6070 for SHA-1, and RFC 7914, section 11, for SHA-256
(def pbkdf2-cases
  "The hash, password, salt, iterations, length in bytes and derived key of
  each test vector of PBKDF2, but for the 16,777,216 iterations of RFC 6070,
  which take too long."
  [[:sha-1 "password" "salt" 1 20 "0c60c80f961f0e71f3a9b524af6012062fe037a6"]
   [:sha-1 "password" "salt" 2 20 "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"]
   [:sha-1 "password" "salt" 4096 20 "4b007901b765489abead49d926f721d065a429c1"]
   [:sha-1 "passwordPASSWORDpassword" "saltSALTsaltSALTsaltSALTsaltSALTsalt" 4096 25
    "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"]
   [:sha-1 "pass\u0000word" "sa\u0000lt" 4096 16 "56fa6aa75548099dcc37d7f03425e0c3"]
   [:sha-256 "passwd" "salt" 1 64
    (str "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
         "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")]
   [:sha-256 "Password" "NaCl" 80000 64
    (str "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
         "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d")]])

(defn password-key
  "A promise of the PBKDF2 key of the text `password`, which derives bits
  and keys."
  [password]
  (webcrypto/import-key :raw (bytes/encode password) :pbkdf2 false [:derive-bits :derive-key]))

(deftest pbkdf2
  (run #(all (for [[hash password salt iterations length dk] pbkdf2-cases
                   :let [params {:name :pbkdf2 :hash hash :salt (bytes/encode salt) :iterations iterations}]]
               (then (password-key password)
                     (fn [k]
                       (then (webcrypto/derive-bits params k (* 8 length))
                             (fn [bits]
                               (is (= dk (bytes/hex bits)) (str iterations " of " hash))))))))
       #(-> (password-key "p")
            (then (fn [k]
                    (webcrypto/derive-bits {:name :pbkdf2 :hash :sha-256 :salt (bytes/encode "salt") :iterations 1}
                                           k 0)))
            (then (fn [bits] (is (= 0 (bytes/length bits)) "no bits are no bytes"))))))

(def like-minded-params
  "The parameters of PBKDF2 of an envelope of like-minded, with fewer
  iterations."
  {:name :pbkdf2 :hash :sha-256 :salt (bytes/of (range 16)) :iterations 1000})

(deftest derived-keys
  (run #(-> (password-key "hunter2")
            (then (fn [password]
                    (webcrypto/derive-key like-minded-params password {:name :aes-gcm :length 256}
                                          false [:encrypt :decrypt])))
            (then (fn [k]
                    (is (= {:type         :secret
                            :extractable? false
                            :algorithm    {:name :aes-gcm :length 256}
                            :usages       #{:encrypt :decrypt}}
                           (webcrypto/key-info k)))
                    (webcrypto/encrypt {:name :aes-gcm :iv (bytes/of (range 12))} k
                                       (bytes/encode "a secret"))))
            ;; what WebCrypto in Node seals too
            (then (fn [sealed]
                    (is (= "ae7f75f1ccda8837a6561e70b8cb5e0e509390fdf132c7fa" (bytes/hex sealed))))))
       #(then (password-key "hunter2")
              (fn [password]
                (then (webcrypto/derive-key like-minded-params password {:name :hmac :hash :sha-256}
                                            true [:sign])
                      (fn [k]
                        (is (= 512 (:length (:algorithm (webcrypto/key-info k))))
                            "an HMAC key of a block by default")))))))

(deftest jwk
  (run #(-> (webcrypto/import-key :raw (bytes/of (range 32)) :aes-gcm true [:decrypt :encrypt])
            (then (fn [k] (webcrypto/export-key :jwk k)))
            (then (fn [jwk]
                    (is (= {:kty     "oct"
                            :k       "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
                            :alg     "A256GCM"
                            :key_ops ["encrypt" "decrypt"]
                            :ext     true}
                           jwk)
                        "key_ops in the order of WebCrypto's KeyUsage")
                    (webcrypto/import-key :jwk jwk :aes-gcm true [:encrypt])))
            (then (fn [k] (webcrypto/export-key :raw k)))
            (then (fn [b] (is (= (bytes/hex (bytes/of (range 32))) (bytes/hex b))))))
       #(then (hmac-key "4a656665" :sha-256)
              (fn [k]
                (then (webcrypto/export-key :jwk k)
                      (fn [jwk]
                        (is (= {:kty "oct" :k "SmVmZQ" :alg "HS256" :key_ops ["sign" "verify"] :ext true}
                               jwk))))))))

(def aes-jwk
  "The JWK of an AES-GCM key of 128 bits."
  {:kty "oct" :k "AAECAwQFBgcICQoLDA0ODw" :alg "A128GCM"})

(def jwk-refusals
  "The JWKs that the import of an AES-GCM key for :encrypt refuses with
  data-error, and why."
  [["another kty" (assoc aes-jwk :kty "RSA")]
   ["another alg" (assoc aes-jwk :alg "A256GCM")]
   ["a k that isn't base64url" (assoc aes-jwk :k "AA+/")]
   ["no k" (dissoc aes-jwk :k)]
   ["a use for signatures" (assoc aes-jwk :use "sig")]
   ["key_ops without the usage" (assoc aes-jwk :key_ops ["decrypt"])]
   ["key_ops with a usage twice" (assoc aes-jwk :key_ops ["encrypt" "encrypt"])]])

(deftest jwk-refusals-test
  (run #(all (for [[why jwk] jwk-refusals]
               (fails-with :data-error why
                           (fn [] (webcrypto/import-key :jwk jwk :aes-gcm false [:encrypt])))))
       #(fails-with :data-error "an ext of false for an extractable key"
                    (fn [] (webcrypto/import-key :jwk (assoc aes-jwk :ext false) :aes-gcm true [:encrypt])))
       #(fails-with :data-error "an HMAC key of another hash"
                    (fn [] (webcrypto/import-key :jwk {:kty "oct" :k "SmVmZQ" :alg "HS256"}
                                                 {:name :hmac :hash :sha-1} false [:sign])))
       #(fails-with :type-error "a JWK that isn't a map"
                    (fn [] (webcrypto/import-key :jwk "{}" :aes-gcm false [:encrypt])))))

(defn with-key
  "A function that calls `f` with the key that `key-fn` returns a promise
  of, for the refusals."
  [key-fn f]
  (fn [] (then (key-fn) f)))

(def data
  "Some bytes."
  (bytes/encode "data"))

(def iv
  "An IV of 12 bytes."
  (bytes/of (range 12)))

(def aes-128
  "A function that returns a promise of an AES key of 128 bits, which only
  encrypts."
  #(aes-key "000102030405060708090a0b0c0d0e0f" [:encrypt]))

(def pbkdf2-params
  "The parameters of PBKDF2, but for a salt and iterations."
  {:name :pbkdf2 :hash :sha-256})

;; The refusals of the library, which every platform throws alike
(def refusals
  "The kind of error, why it's thrown, and a function that throws it (or
  returns a promise that rejects with it)."
  [[:not-supported-error "an AES key of 192 bits"
    #(webcrypto/generate-key {:name :aes-gcm :length 192} false [:encrypt])]
   [:not-supported-error "an AES key of 192 bits"
    #(webcrypto/import-key :raw (bytes/of (range 24)) :aes-gcm false [:encrypt])]
   [:not-supported-error "the JWK of an AES key of 192 bits"
    #(webcrypto/import-key :jwk {:kty "oct" :k (bytes/base64url (bytes/of (range 24)))} :aes-gcm false [:encrypt])]
   [:operation-error "an AES key of 100 bits"
    #(webcrypto/generate-key {:name :aes-gcm :length 100} false [:encrypt])]
   [:data-error "an AES key of 160 bits"
    #(webcrypto/import-key :raw (bytes/of (range 20)) :aes-gcm false [:encrypt])]
   [:not-supported-error "a tag of 64 bits"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm :iv iv :tag-length 64} % data))]
   [:operation-error "a tag of 100 bits"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm :iv iv :tag-length 100} % data))]
   [:operation-error "an empty IV"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm :iv (bytes/of [])} % data))]
   [:type-error "no IV"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm} % data))]
   [:type-error "a tag length that isn't an octet"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm :iv iv :tag-length 300} % data))]
   [:type-error "data that isn't bytes"
    (with-key aes-128 #(webcrypto/encrypt {:name :aes-gcm :iv iv} % "data"))]
   [:invalid-access-error "a key without the usage"
    (with-key aes-128 #(webcrypto/decrypt {:name :aes-gcm :iv iv} % data))]
   [:invalid-access-error "a key of another algorithm"
    (with-key aes-128 #(webcrypto/sign :hmac % data))]
   [:invalid-access-error "a key that isn't extractable"
    (with-key aes-128 #(webcrypto/export-key :raw %))]
   [:syntax-error "a usage that an AES-GCM key can't have"
    #(aes-key "000102030405060708090a0b0c0d0e0f" [:sign])]
   [:syntax-error "a secret key without a usage"
    #(aes-key "000102030405060708090a0b0c0d0e0f" [])]
   [:type-error "a usage that WebCrypto doesn't have"
    #(aes-key "000102030405060708090a0b0c0d0e0f" [:encipher])]
   [:type-error "a format that WebCrypto doesn't have"
    #(webcrypto/import-key :hex (bytes/of [1]) :aes-gcm false [:encrypt])]
   [:not-supported-error "an algorithm that the library doesn't have"
    #(webcrypto/digest :sha-3 data)]
   [:not-supported-error "an algorithm of another operation"
    #(webcrypto/digest :hmac data)]
   [:type-error "an algorithm that isn't a keyword"
    #(webcrypto/digest "SHA-256" data)]
   [:not-supported-error "an HMAC key of 7 bits"
    #(webcrypto/generate-key {:name :hmac :hash :sha-256 :length 7} false [:sign])]
   [:operation-error "an HMAC key of 0 bits"
    #(webcrypto/generate-key {:name :hmac :hash :sha-256 :length 0} false [:sign])]
   [:type-error "an HMAC key without a hash"
    #(webcrypto/generate-key {:name :hmac} false [:sign])]
   [:data-error "an empty HMAC key"
    #(webcrypto/import-key :raw (bytes/of []) {:name :hmac :hash :sha-256} false [:sign])]
   [:data-error "an HMAC key shorter than its length"
    #(webcrypto/import-key :raw (bytes/of [1]) {:name :hmac :hash :sha-256 :length 16} false [:sign])]
   [:not-supported-error "a PBKDF2 password that isn't UTF-8"
    #(webcrypto/import-key :raw (bytes/of [0xff 0xfe]) :pbkdf2 false [:derive-bits])]
   [:syntax-error "an extractable PBKDF2 key"
    #(webcrypto/import-key :raw data :pbkdf2 true [:derive-bits])]
   [:not-supported-error "a PBKDF2 key as a JWK"
    #(webcrypto/import-key :jwk {:kty "oct"} :pbkdf2 false [:derive-bits])]
   [:not-supported-error "PBKDF2 with an empty salt"
    (with-key #(password-key "p")
      #(webcrypto/derive-bits (assoc pbkdf2-params :salt (bytes/of []) :iterations 1) % 256))]
   [:operation-error "PBKDF2 without iterations"
    (with-key #(password-key "p")
      #(webcrypto/derive-bits (assoc pbkdf2-params :salt data :iterations 0) % 256))]
   [:not-supported-error "PBKDF2 with more iterations than the JDK's int"
    (with-key #(password-key "p")
      #(webcrypto/derive-bits (assoc pbkdf2-params :salt data :iterations 0x80000000) % 256))]
   [:operation-error "a length of part of a byte"
    (with-key #(password-key "p")
      #(webcrypto/derive-bits (assoc pbkdf2-params :salt data :iterations 1) % 12))]
   [:operation-error "no length"
    (with-key #(password-key "p")
      #(webcrypto/derive-bits (assoc pbkdf2-params :salt data :iterations 1) % nil))]
   [:not-supported-error "the export of a PBKDF2 key"
    (with-key #(password-key "p") #(webcrypto/export-key :raw %))]
   [:operation-error "a derived key of HKDF, which has no length"
    (with-key #(password-key "p")
      #(webcrypto/derive-key (assoc pbkdf2-params :salt data :iterations 1) % :hkdf false [:derive-bits]))]
   [:operation-error "an HKDF longer than 255 blocks"
    (with-key #(webcrypto/import-key :raw data :hkdf false [:derive-bits])
      #(webcrypto/derive-bits {:name :hkdf :hash :sha-1 :salt data :info data} % (* 8 20 256)))]
   [:type-error "a negative number of random bytes"
    #(webcrypto/random-bytes -1)]
   [:quota-exceeded-error "more random bytes than a Java array holds, which the JVM truncated"
    #(webcrypto/random-bytes 0x100000010)]
   [:type-error "a key that isn't a key"
    #(webcrypto/sign :hmac (bytes/of [1]) data)]])

(deftest the-same-errors-everywhere
  (run #(all (for [[kind why f] refusals]
               (fails-with kind why f)))))

(deftest chaining
  (run #(webcrypto/then 1 (fn [x] (is (= 1 x)) x))
       #(webcrypto/then (webcrypto/digest :sha-256 data)
                        (fn [d] (is (= (bytes/hex (hash/digest :sha-256 data)) (bytes/hex d)))))
       #(-> (password-key "hunter2")
            (webcrypto/then (fn [password]
                              (webcrypto/derive-key like-minded-params password
                                                    {:name :aes-gcm :length 256} false [:encrypt])))
            (webcrypto/then (fn [k] (is (webcrypto/key? k)))))))

(deftest random-bytes
  (let [b (webcrypto/random-bytes 100000)]
    (is (= 100000 (bytes/length b)) "more than one call of getRandomValues")
    (is (not (bytes/same? (bytes/slice b 0 32) (webcrypto/random-bytes 32))))))

(deftest key-info
  (run #(then (outcome (fn [] (webcrypto/key-info "a key")))
              (fn [{:keys [error]}]
                (is (= ::webcrypto/type-error error))))
       #(then (webcrypto/import-key :raw (bytes/of [1 2 3]) :hkdf false [:derive-key :derive-bits])
              (fn [k]
                (is (webcrypto/key? k))
                (is (not (webcrypto/key? (bytes/of [1 2 3]))))
                (is (= {:type         :secret
                        :extractable? false
                        :algorithm    {:name :hkdf}
                        :usages       #{:derive-key :derive-bits}}
                       (webcrypto/key-info k)))))))
