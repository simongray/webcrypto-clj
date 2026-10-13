(ns dk.simongray.webcrypto.hash-test
  "The synchronous hashes, HMACs and HKDF by the test vectors of their
  standards: the examples of FIPS 180-4, RFC 2202 and RFC 4231 for HMAC,
  and Appendix A of RFC 5869 for HKDF."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]))

(defn repeated
  "The hex of the byte `x` (as two hex digits) `n` times."
  [x n]
  (apply str (repeat n x)))

;; The examples of FIPS 180-4 at https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values,
;; and the message of a million a's that FIPS 180-2 had in its appendices
(def fips-180
  "The digest of each example message by each hash."
  (let [two-blocks  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        four-blocks (str "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        a-million   (apply str (repeat 1000000 "a"))]
    {:sha-1   {"abc"      "a9993e364706816aba3e25717850c26c9cd0d89d"
               two-blocks "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
               a-million  "34aa973cd4c4daa4f61eeb2bdbad27316534016f"}
     :sha-256 {"abc"      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
               two-blocks "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
               a-million  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}
     :sha-384 {"abc"       (str "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                                "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
               four-blocks (str "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                                "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
               a-million   (str "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
                                "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")}
     :sha-512 {"abc"       (str "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
               four-blocks (str "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
               a-million   (str "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                                "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")}}))

(deftest the-examples-of-fips-180
  (doseq [[h examples] fips-180
          [message expected] examples]
    (is (= expected (bytes/hex (hash/digest h (bytes/encode message))))
        (str h " of " (subs message 0 (min 10 (count message)))))))

;; RFC 2202, section 3
(def rfc-2202
  "The test cases of HMAC-SHA-1: the key, the data and the HMAC, in hex."
  [[(repeated "0b" 20) (bytes/hex (bytes/encode "Hi There"))
    "b617318655057264e28bc0b6fb378c8ef146be00"]
   [(bytes/hex (bytes/encode "Jefe")) (bytes/hex (bytes/encode "what do ya want for nothing?"))
    "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"]
   [(repeated "aa" 20) (repeated "dd" 50)
    "125d7342b9ac11cd91a39af48aa17b4f63f175d3"]
   ["0102030405060708090a0b0c0d0e0f10111213141516171819" (repeated "cd" 50)
    "4c9007f4026250c6bc8414f9bf50c86c2d7235da"]
   [(repeated "0c" 20) (bytes/hex (bytes/encode "Test With Truncation"))
    "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"]
   [(repeated "aa" 80) (bytes/hex (bytes/encode "Test Using Larger Than Block-Size Key - Hash Key First"))
    "aa4ae5e15272d00e95705637ce8a3b55ed402112"]
   [(repeated "aa" 80) (bytes/hex (bytes/encode (str "Test Using Larger Than Block-Size Key "
                                                     "and Larger Than One Block-Size Data")))
    "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"]])

;; RFC 4231, section 4, where case 5 truncates its HMACs to 128 bits
(def rfc-4231
  "The test cases of HMAC-SHA-2, without SHA-224."
  [{:key     (repeated "0b" 20)
    :data    (bytes/hex (bytes/encode "Hi There"))
    :sha-256 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    :sha-384 (str "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6"
                  "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
    :sha-512 (str "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                  "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")}
   {:key     (bytes/hex (bytes/encode "Jefe"))
    :data    (bytes/hex (bytes/encode "what do ya want for nothing?"))
    :sha-256 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    :sha-384 (str "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47"
                  "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")
    :sha-512 (str "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                  "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")}
   {:key     (repeated "aa" 20)
    :data    (repeated "dd" 50)
    :sha-256 "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    :sha-384 (str "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9feb"
                  "e83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27")
    :sha-512 (str "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                  "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")}
   {:key     "0102030405060708090a0b0c0d0e0f10111213141516171819"
    :data    (repeated "cd" 50)
    :sha-256 "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    :sha-384 (str "3e8a69b7783c25851933ab6290af6ca77a9981480850009c"
                  "c5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb")
    :sha-512 (str "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                  "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")}
   {:key     (repeated "0c" 20)
    :data    (bytes/hex (bytes/encode "Test With Truncation"))
    :sha-256 "a3b6167473100ee06e0c796c2955552b"
    :sha-384 "3abf34c3503b2a23a46efc619baef897"
    :sha-512 "415fad6271580a531d4179bc891d87a6"}
   {:key     (repeated "aa" 131)
    :data    (bytes/hex (bytes/encode "Test Using Larger Than Block-Size Key - Hash Key First"))
    :sha-256 "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    :sha-384 (str "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f"
                  "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952")
    :sha-512 (str "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                  "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")}
   {:key     (repeated "aa" 131)
    :data    (bytes/hex (bytes/encode (str "This is a test using a larger than block-size key "
                                           "and a larger than block-size data. The key needs to "
                                           "be hashed before being used by the HMAC algorithm.")))
    :sha-256 "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    :sha-384 (str "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9a"
                  "dccebb82461e99c5a678cc31e799176d3860e6110c46523e")
    :sha-512 (str "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
                  "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")}])

(deftest the-cases-of-rfc-2202
  (doseq [[i [k data expected]] (map-indexed vector rfc-2202)]
    (is (= expected (bytes/hex (hash/hmac :sha-1 (bytes/from-hex k) (bytes/from-hex data))))
        (str "case " (inc i)))))

(deftest the-cases-of-rfc-4231
  (doseq [[i {:keys [key data] :as c}] (map-indexed vector rfc-4231)
          h                            [:sha-256 :sha-384 :sha-512]
          :let [expected (c h)]]
    (is (= expected (subs (bytes/hex (hash/hmac h (bytes/from-hex key) (bytes/from-hex data)))
                          0 (count expected)))
        (str "case " (inc i) " by " h))))

;; RFC 5869, Appendix A
(def rfc-5869
  "The test cases of HKDF, in hex. Case 7 gives no salt."
  [{:hash :sha-256 :length 42
    :ikm  (repeated "0b" 22)
    :salt "000102030405060708090a0b0c"
    :info "f0f1f2f3f4f5f6f7f8f9"
    :prk  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    :okm  (str "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
               "34007208d5b887185865")}
   {:hash :sha-256 :length 82
    :ikm  (bytes/hex (bytes/of (range 0x00 0x50)))
    :salt (bytes/hex (bytes/of (range 0x60 0xb0)))
    :info (bytes/hex (bytes/of (range 0xb0 0x100)))
    :prk  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    :okm  (str "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
               "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
               "cc30c58179ec3e87c14c01d5c1f3434f1d87")}
   {:hash :sha-256 :length 42
    :ikm  (repeated "0b" 22)
    :salt ""
    :info ""
    :prk  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    :okm  (str "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
               "9d201395faa4b61a96c8")}
   {:hash :sha-1 :length 42
    :ikm  (repeated "0b" 11)
    :salt "000102030405060708090a0b0c"
    :info "f0f1f2f3f4f5f6f7f8f9"
    :prk  "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"
    :okm  (str "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2"
               "c22e422478d305f3f896")}
   {:hash :sha-1 :length 82
    :ikm  (bytes/hex (bytes/of (range 0x00 0x50)))
    :salt (bytes/hex (bytes/of (range 0x60 0xb0)))
    :info (bytes/hex (bytes/of (range 0xb0 0x100)))
    :prk  "8adae09a2a307059478d309b26c4115a224cfaf6"
    :okm  (str "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe"
               "8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e"
               "927336d0441f4c4300e2cff0d0900b52d3b4")}
   {:hash :sha-1 :length 42
    :ikm  (repeated "0b" 22)
    :salt ""
    :info ""
    :prk  "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"
    :okm  (str "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0"
               "ea00033de03984d34918")}
   {:hash :sha-1 :length 42
    :ikm  (repeated "0c" 22)
    :salt nil
    :info ""
    :prk  "2adccada18779e7c2077ad2eb19d3f3e731385dd"
    :okm  (str "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5"
               "673a081d70cce7acfc48")}])

(deftest the-cases-of-rfc-5869
  (doseq [[i {:keys [hash length ikm salt info prk okm]}] (map-indexed vector rfc-5869)
          :let [[ikm salt info] (map #(some-> % bytes/from-hex) [ikm salt info])]]
    (testing (str "case " (inc i))
      (is (= prk (bytes/hex (hash/hkdf-extract hash salt ikm))))
      (is (= okm (bytes/hex (hash/hkdf-expand hash (bytes/from-hex prk) info length))))
      (is (= okm (bytes/hex (hash/hkdf hash ikm salt info length)))))))

(defn error-type
  "The :type of the error that calling `f` throws, or nil."
  [f]
  (try
    (f)
    nil
    (catch #?(:clj Exception :cljs :default) e
      (:type (ex-data e)))))

(deftest errors
  (let [b (bytes/encode "abc")]
    (is (= :dk.simongray.webcrypto/not-supported-error
           (error-type #(hash/digest :sha-3 b))))
    (is (= :dk.simongray.webcrypto/not-supported-error
           (error-type #(hash/hmac :md5 b b))))
    (is (= :dk.simongray.webcrypto/type-error
           (error-type #(hash/digest :sha-256 "abc")))
        "text isn't bytes")
    (is (= :dk.simongray.webcrypto/type-error
           (error-type (fn []
                         #_{:clj-kondo/ignore [:type-mismatch]}
                         (hash/hmac :sha-256 nil b)))))
    (testing "HKDF derives 255 blocks of the hash at most"
      (is (= (* 255 32) (bytes/length (hash/hkdf :sha-256 b nil nil (* 255 32)))))
      (is (= :dk.simongray.webcrypto/operation-error
             (error-type #(hash/hkdf :sha-256 b nil nil (inc (* 255 32))))))
      (is (= 0 (bytes/length (hash/hkdf :sha-1 b nil nil 0)))))
    (testing "an empty key, which RFC 2104 allows"
      (is (= "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
             (bytes/hex (hash/hmac :sha-256 (bytes/of []) (bytes/of []))))))))

(deftest large-data
  (let [b (bytes/encode (str/join (repeat 100000 "0123456789")))]
    (is (= 32 (bytes/length (hash/digest :sha-256 b))))
    (is (= 64 (bytes/length (hash/hmac :sha-512 b b))))))
