(ns dk.simongray.webcrypto.asymmetric-test
  "Signatures and key agreement on both platforms: ECDSA, RSASSA-PKCS1-v1_5,
  RSA-PSS, Ed25519 and ECDH by the examples of their RFCs, keys in each
  format, keys that one platform made and the other uses, and the errors
  that each platform throws alike.

  The JDK has no Ed25519 before Java 15, so there the tests only check
  that the library refuses it."
  (:require [clojure.test :refer [deftest is]]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto-test :as webcrypto-test]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.fixtures :as fixtures]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.impl.ec :as ec]
            #?(:clj [dk.simongray.webcrypto.impl.ed25519 :as ed25519])
            [dk.simongray.webcrypto.pem :as pem]
            [dk.simongray.webcrypto.test-support :refer [all fails-with run then]]))

(def ed25519?
  "Whether the platform has Ed25519."
  #?(:clj @ed25519/available? :cljs true))

(defn algorithm-name
  "The name of the `algorithm`, a keyword or a map."
  [algorithm]
  (if (map? algorithm) (:name algorithm) algorithm))

(defn available?
  "Whether the platform has the `algorithm`."
  [algorithm]
  (or ed25519? (not= :ed25519 (algorithm-name algorithm))))

(defn deterministic?
  "Whether the `algorithm` signs the same data the same way each time."
  [algorithm]
  (contains? #{:rsassa-pkcs1-v1_5 :ed25519} (algorithm-name algorithm)))

(defn hex
  "The bytes of the hex `s`."
  [s]
  (bytes/from-hex s))

(def message
  "Some bytes to sign."
  (bytes/encode "a message"))

;; RFC 8032, section 7.1
(deftest rfc-8032
  (run #(all (for [{:keys [secret public signature] :as v} fixtures/rfc-8032
                   :when ed25519?
                   :let [jwk {:kty "OKP"
                              :crv "Ed25519"
                              :x   (bytes/base64url (hex public))
                              :d   (bytes/base64url (hex secret))}
                         data (hex (:message v))]]
               (-> (all [(webcrypto/import-key :jwk jwk :ed25519 false [:sign])
                         (webcrypto/import-key :raw (hex public) :ed25519 false [:verify])])
                   (then (fn [[private-key public-key]]
                           (all [(webcrypto/sign :ed25519 private-key data)
                                 (webcrypto/verify :ed25519 public-key (hex signature) data)])))
                   (then (fn [[signed verified]]
                           (is (= signature (bytes/hex signed)) (:name v))
                           (is (true? verified) (:name v)))))))))

(deftest ed25519-before-java-15
  (run #(when-not ed25519?
          (fails-with :not-supported-error "Ed25519 before Java 15"
                      (fn [] (webcrypto/generate-key :ed25519 false [:sign :verify]))))))

(defn pem-key
  "The key in the PEM text `s` for the `algorithm`, which is extractable
  and has the `usages`."
  [s algorithm usages]
  (let [{:keys [format data]} (pem/key-data s)]
    (webcrypto/import-key format data algorithm true usages)))

(defn public-members
  "The members of the `jwk` that its public key has too."
  [jwk]
  (select-keys jwk [:kty :crv :alg :x :y :n :e]))

;; RFC 9421, section 4.3 and Appendix B.2
(deftest rfc-9421
  (run #(all (for [{:keys [public private algorithm signing base signature] :as example}
                   fixtures/rfc-9421-signatures
                   :when (available? algorithm)
                   :let [why  (str "RFC 9421, " (:name example))
                         data (bytes/encode base)]]
               (-> (all [(pem-key (fixtures/rfc-9421 public) algorithm [:verify])
                         (pem-key (fixtures/rfc-9421 private) algorithm [:sign])])
                   (then (fn [[public-key private-key]]
                           (all [public-key
                                 (webcrypto/verify signing public-key (bytes/from-base64 signature) data)
                                 (webcrypto/sign signing private-key data)
                                 (webcrypto/export-key :jwk public-key)
                                 (webcrypto/export-key :jwk private-key)])))
                   (then (fn [[public-key verified signed public-jwk private-jwk]]
                           (is (true? verified) why)
                           (is (= (public-members public-jwk) (public-members private-jwk))
                               (str why ", the private key's public key"))
                           (if (deterministic? signing)
                             (is (= signature (bytes/base64 signed)) why)
                             (then (webcrypto/verify signing public-key signed data)
                                   (fn [verified] (is (true? verified) why)))))))))))

(def exponent
  "The public exponent 65537."
  (bytes/of [1 0 1]))

(def signers
  "The algorithms of generate-key and of sign of a key pair of each kind
  that signs."
  [[{:name :ecdsa :named-curve :p-256} {:name :ecdsa :hash :sha-256}]
   [{:name :ecdsa :named-curve :p-384} {:name :ecdsa :hash :sha-384}]
   [{:name :ecdsa :named-curve :p-521} {:name :ecdsa :hash :sha-512}]
   [{:name :rsassa-pkcs1-v1_5 :modulus-length 2048 :public-exponent exponent :hash :sha-256}
    :rsassa-pkcs1-v1_5]
   [{:name :rsa-pss :modulus-length 1024 :public-exponent exponent :hash :sha-384}
    {:name :rsa-pss :salt-length 48}]
   [:ed25519 :ed25519]])

(defn key-algorithm
  "The algorithm in the key-info of a key of the `algorithm` of
  generate-key, with a public exponent in hex."
  [algorithm]
  (if (map? algorithm)
    (cond-> algorithm
      (:public-exponent algorithm) (update :public-exponent bytes/hex))
    {:name algorithm}))

(defn info
  "The key-info of the `key`, with a public exponent in hex."
  [key]
  (update (webcrypto/key-info key) :algorithm key-algorithm))

(deftest generated-key-pairs
  (run #(all (for [[algorithm signing] signers
                   :when (available? algorithm)
                   :let [why (str (algorithm-name algorithm))]]
               (-> (webcrypto/generate-key algorithm false [:verify :sign])
                   (then (fn [{:keys [public-key private-key]}]
                           (is (= {:type         :public
                                   :extractable? true
                                   :algorithm    (key-algorithm algorithm)
                                   :usages       #{:verify}}
                                  (info public-key))
                               why)
                           (is (= {:type         :private
                                   :extractable? false
                                   :algorithm    (key-algorithm algorithm)
                                   :usages       #{:sign}}
                                  (info private-key))
                               why)
                           (then (webcrypto/sign signing private-key message)
                                 (fn [signature]
                                   (all [(webcrypto/verify signing public-key signature message)
                                         (webcrypto/verify signing public-key signature (bytes/encode "another"))
                                         (webcrypto/verify signing public-key
                                                           (webcrypto-test/flipped signature 0) message)
                                         (webcrypto/verify signing public-key
                                                           (bytes/slice signature 1) message)])))))
                   (then (fn [[right other changed truncated]]
                           (is (true? right) why)
                           (is (false? other) (str why ", other data"))
                           (is (false? changed) (str why ", a changed signature"))
                           (is (false? truncated) (str why ", a truncated signature")))))))))

(defn usages-of
  "The usages of the private key and of the public key of the algorithm
  named `alg-name`."
  [alg-name]
  (if (= :ecdh alg-name)
    [[:derive-bits] []]
    [[:sign] [:verify]]))

(defn import-algorithm
  "The algorithm of import-key for a key of the `algorithm` of
  generate-key."
  [algorithm]
  (if (map? algorithm)
    (select-keys algorithm [:name :named-curve :hash])
    algorithm))

(defn exported
  "The `key` in the `format`, with bytes as hex."
  [format key]
  (then (webcrypto/export-key format key)
        #(if (bytes/bytes? %) (bytes/hex %) %)))

(defn check-format
  "Check that the `key` imports again as it exports in the `format`, for
  the `algorithm` with the `usages`, and exports the same."
  [key algorithm format usages]
  (-> (webcrypto/export-key format key)
      (then #(webcrypto/import-key format % algorithm true usages))
      (then #(all [(exported format key) (exported format %)]))
      (then (fn [[before after]]
              (is (= before after) (str (algorithm-name algorithm) " as " format))))))

(deftest key-formats
  (run #(all (for [algorithm (conj (mapv first signers) {:name :ecdh :named-curve :p-384})
                   :when (available? algorithm)
                   :let [alg-name                       (algorithm-name algorithm)
                         [private-usages public-usages] (usages-of alg-name)
                         imported                       (import-algorithm algorithm)]]
               (then (webcrypto/generate-key algorithm true (concat private-usages public-usages))
                     (fn [{:keys [public-key private-key]}]
                       (all (cond-> [(check-format public-key imported :spki public-usages)
                                     (check-format public-key imported :jwk public-usages)
                                     (check-format private-key imported :pkcs8 private-usages)
                                     (check-format private-key imported :jwk private-usages)]
                              (contains? #{:ecdsa :ecdh :ed25519} alg-name)
                              (conj (check-format public-key imported :raw public-usages))))))))))

(defn key-ops
  "The key_ops of a JWK with the `usages`."
  [usages]
  (mapv algorithms/usage-names usages))

(deftest made-elsewhere
  (run #(all (for [{:keys [made-on algorithm signing jwk spki pkcs8 signature] :as made}
                   fixtures/made-elsewhere
                   :when (available? algorithm)
                   :let [why                            (str (algorithm-name algorithm) " made on "
                                                             (name made-on))
                         [private-usages public-usages] (usages-of (algorithm-name algorithm))
                         data                           (some-> (:message made) bytes/encode)]]
               (-> (all [(webcrypto/import-key :jwk jwk algorithm true private-usages)
                         (webcrypto/import-key :pkcs8 (hex pkcs8) algorithm true private-usages)
                         (webcrypto/import-key :spki (hex spki) algorithm true public-usages)])
                   (then (fn [[from-jwk from-pkcs8 public-key]]
                           (all [(exported :pkcs8 from-jwk)
                                 (exported :jwk from-pkcs8)
                                 (exported :spki public-key)
                                 (when signature
                                   (webcrypto/verify signing public-key (hex signature) data))
                                 (when (and signature (deterministic? signing))
                                   (then (webcrypto/sign signing from-pkcs8 data) bytes/hex))])))
                   (then (fn [[pkcs8-again jwk-again spki-again verified signed]]
                           (is (= pkcs8 pkcs8-again) why)
                           (is (= (assoc jwk :key_ops (key-ops private-usages) :ext true) jwk-again) why)
                           (is (= spki spki-again) why)
                           (when signature
                             (is (true? verified) why))
                           (when signed
                             (is (= signature signed) why)))))))))

(defn ecdh
  "The parameters of ECDH with the `public-key`."
  [public-key]
  {:name :ecdh :public public-key})

(deftest ecdh-key-agreement
  (run #(all (for [[curve size] {:p-256 32 :p-384 48 :p-521 66}
                   :let [algorithm {:name :ecdh :named-curve curve}
                         why       (str "ECDH on " (name curve))]]
               (-> (all [(webcrypto/generate-key algorithm false [:derive-bits :derive-key])
                         (webcrypto/generate-key algorithm false [:derive-bits])])
                   (then (fn [[alice bob]]
                           (is (= #{} (:usages (webcrypto/key-info (:public-key alice)))) why)
                           (all [(webcrypto/derive-bits (ecdh (:public-key bob)) (:private-key alice) nil)
                                 (webcrypto/derive-bits (ecdh (:public-key alice)) (:private-key bob) nil)
                                 (webcrypto/derive-bits (ecdh (:public-key bob)) (:private-key alice) 12)
                                 (then (webcrypto/derive-key (ecdh (:public-key bob)) (:private-key alice)
                                                             {:name :aes-gcm :length 128} true [:encrypt])
                                       (partial exported :raw))])))
                   (then (fn [[secret same twelve aes-key]]
                           (is (= size (bytes/length secret)) why)
                           (is (= (bytes/hex secret) (bytes/hex same)) why)
                           (is (= [(bytes/at secret 0) (bit-and (bytes/at secret 1) 0xf0)]
                                  [(bytes/at twelve 0) (bytes/at twelve 1)])
                               (str why ", 12 bits and 4 zeros"))
                           (is (= 2 (bytes/length twelve)) (str why ", 12 bits in 2 bytes"))
                           (is (= (subs (bytes/hex secret) 0 32) aes-key)
                               (str why ", an AES key of its first 128 bits")))))))))

(defn made-on
  "The key pair of the algorithm named `alg-name` that was made on the
  `platform`, :jvm or :node."
  [platform alg-name]
  (some #(when (and (= platform (:made-on %)) (= alg-name (algorithm-name (:algorithm %)))) %)
        fixtures/made-elsewhere))

(defn imported-ecdh
  "The private and the public key of the ECDH key pair `made` elsewhere."
  [{:keys [algorithm jwk spki]}]
  (all [(webcrypto/import-key :jwk jwk algorithm false [:derive-bits])
        (webcrypto/import-key :spki (hex spki) algorithm false [])]))

(deftest ecdh-made-elsewhere
  (run #(-> (all [(imported-ecdh (made-on :jvm :ecdh)) (imported-ecdh (made-on :node :ecdh))])
            (then (fn [[[jvm-private jvm-public] [node-private node-public]]]
                    (all [(webcrypto/derive-bits (ecdh node-public) jvm-private nil)
                          (webcrypto/derive-bits (ecdh jvm-public) node-private nil)])))
            (then (fn [[jvm-secret node-secret]]
                    (is (= (bytes/hex jvm-secret) (bytes/hex node-secret))))))))

(def p-256
  "The algorithm of an ECDSA key on P-256."
  {:name :ecdsa :named-curve :p-256})

(defn ecdsa-pair
  "A new ECDSA key pair on P-256, which is extractable."
  []
  (webcrypto/generate-key p-256 true [:sign :verify]))

(defn ecdh-pair
  "A new ECDH key pair on the `curve`."
  [curve]
  (webcrypto/generate-key {:name :ecdh :named-curve curve} false [:derive-bits]))

(def node-ecdsa
  "The ECDSA key pair on P-256 that WebCrypto made in Node."
  (made-on :node :ecdsa))

(def node-rsa
  "The RSASSA-PKCS1-v1_5 key pair that WebCrypto made in Node."
  (made-on :node :rsassa-pkcs1-v1_5))

(def point
  "The public key of node-ecdsa as raw bytes."
  (bytes/slice (hex (:spki node-ecdsa)) 26))

(def rsa-numbers
  "The modulus :n and the public exponent :e of node-rsa, as bytes."
  (der/rsa-public-key (:public-key (der/spki (hex (:spki node-rsa))))))

(defn rsa-spki
  "The SPKI of the RSA public key of the modulus `n` and the exponent `e`,
  as bytes, under rsaEncryption with the DER `parameters`, NULL by default."
  ([n e]
   (rsa-spki n e (der/null)))
  ([n e parameters]
   (der/write-spki (der/oids :rsa-encryption) parameters (der/write-rsa-public-key n e))))

(def even-modulus
  "The modulus of node-rsa with its lowest bit cleared."
  (let [{:keys [n]} rsa-numbers
        last-byte   (dec (bytes/length n))]
    (bytes/concat (bytes/slice n 0 last-byte) (bytes/of [(bit-and (bytes/at n last-byte) 0xfe)]))))

(defn ec-spki-with-oid
  "The SPKI of node-ecdsa's point under the algorithm of the bytes `oid`,
  the content of an object identifier."
  [oid]
  (der/sequence-of (der/sequence-of (der/tlv :oid oid) (der/oid (der/oids :secp256r1)))
                   (der/bit-string point)))

(def mismatched-pkcs8
  "The PKCS#8 of node-ecdsa's private key with the public key of another
  key pair."
  (let [{:keys [d]} (der/ec-private-key (:private-key (der/private-key-info (hex (:pkcs8 node-ecdsa)))))
        other       (bytes/slice (hex (:spki (made-on :jvm :ecdh))) 26)]
    (der/write-private-key-info (der/oids :ec-public-key) (der/oid (der/oids :secp256r1))
                                (der/write-ec-private-key d other))))

(def identity-point
  "The encoding of the identity on Ed25519, a point of order 1."
  (bytes/concat (bytes/of [1]) (bytes/of (repeat 31 0))))

(defn rsa-pss-key
  "The private RSA-PSS key of 2048 bits that the library made on the JVM."
  []
  (let [{:keys [jwk algorithm]} (made-on :jvm :rsa-pss)]
    (webcrypto/import-key :jwk jwk algorithm false [:sign])))

(defn rsa-params
  "The parameters of generate-key for an RSA-PSS key pair of
  `modulus-length` bits with the public exponent `e`."
  [modulus-length e]
  {:name :rsa-pss :modulus-length modulus-length :public-exponent e :hash :sha-256})

(def with-key
  "A function that calls a function with the key that a key function
  returns (a promise of)."
  webcrypto-test/with-key)

;; The refusals of the library, which every platform throws alike
(def refusals
  "The kind of error, why it's thrown, and a function that throws it (or
  returns a promise that rejects with it)."
  [[:not-supported-error "a curve that the library doesn't have"
    #(webcrypto/generate-key {:name :ecdsa :named-curve :p-192} false [:sign])]
   [:type-error "a curve that isn't a keyword"
    #(webcrypto/generate-key {:name :ecdsa :named-curve "P-256"} false [:sign])]
   [:type-error "ECDSA without a hash"
    (with-key ecdsa-pair #(webcrypto/sign :ecdsa (:private-key %) message))]
   [:syntax-error "an ECDSA key that encrypts"
    #(webcrypto/generate-key p-256 false [:sign :encrypt])]
   [:syntax-error "a key pair whose private key has no usage"
    #(webcrypto/generate-key p-256 false [:verify])]
   [:syntax-error "a public key that signs"
    #(webcrypto/import-key :spki (hex (:spki node-ecdsa)) p-256 false [:sign])]
   [:invalid-access-error "a signature with a public key"
    (with-key ecdsa-pair #(webcrypto/sign {:name :ecdsa :hash :sha-256} (:public-key %) message))]
   [:invalid-access-error "a signature by another algorithm"
    (with-key ecdsa-pair #(webcrypto/sign {:name :rsa-pss :salt-length 32} (:private-key %) message))]
   [:invalid-access-error "the PKCS#8 of a public key"
    (with-key ecdsa-pair #(webcrypto/export-key :pkcs8 (:public-key %)))]
   [:invalid-access-error "the raw bytes of a private key"
    (with-key ecdsa-pair #(webcrypto/export-key :raw (:private-key %)))]
   [:invalid-access-error "a private key that isn't extractable"
    (with-key #(webcrypto/generate-key p-256 false [:sign :verify])
      #(webcrypto/export-key :pkcs8 (:private-key %)))]
   [:data-error "the SPKI of a key on another curve"
    #(webcrypto/import-key :spki (hex (:spki node-ecdsa)) {:name :ecdsa :named-curve :p-384}
                           false [:verify])]
   [:data-error "a point that isn't on its curve"
    #(webcrypto/import-key :raw (webcrypto-test/flipped point 64) p-256 false [:verify])]
   [:data-error "an SPKI as PKCS#8"
    #(webcrypto/import-key :pkcs8 (hex (:spki node-ecdsa)) p-256 false [:sign])]
   [:data-error "an SPKI whose length has more bytes than it needs, which isn't DER"
    #(webcrypto/import-key :spki (hex (str "308159" (subs (:spki node-ecdsa) 4))) p-256 false [:verify])]
   [:data-error "an SPKI with a byte after it"
    #(webcrypto/import-key :spki (bytes/concat (hex (:spki node-ecdsa)) (bytes/of [0])) p-256
                           false [:verify])]
   [:data-error "an RSA key as an EC key"
    #(webcrypto/import-key :spki (hex (:spki node-rsa)) p-256 false [:verify])]
   [:data-error "an EC key as an RSA key"
    #(webcrypto/import-key :spki (hex (:spki node-ecdsa)) {:name :rsa-pss :hash :sha-256}
                           false [:verify])]
   [:data-error "an EC JWK whose public key isn't its private key's"
    #(webcrypto/import-key :jwk (merge (:jwk node-ecdsa) (select-keys (:jwk (made-on :jvm :ecdh)) [:x :y]))
                           p-256 false [:sign])]
   [:data-error "the JWK of an RSA key of another hash"
    #(webcrypto/import-key :jwk (:jwk node-rsa) {:name :rsassa-pkcs1-v1_5 :hash :sha-384}
                           false [:sign])]
   [:not-supported-error "the JWK of an RSA key of more than two primes"
    #(webcrypto/import-key :jwk (assoc (:jwk node-rsa) :oth []) (:algorithm node-rsa) false [:sign])]
   [:not-supported-error "an RSA key as raw bytes"
    #(webcrypto/import-key :raw (hex (:spki node-rsa)) (:algorithm node-rsa) false [:verify])]
   [:not-supported-error "the raw bytes of an RSA key"
    (with-key #(webcrypto/import-key :spki (hex (:spki node-rsa)) (:algorithm node-rsa) true [:verify])
      #(webcrypto/export-key :raw %))]
   [:not-supported-error "an RSA modulus that isn't a multiple of 128 bits"
    #(webcrypto/generate-key (rsa-params 1000 exponent) false [:sign])]
   [:not-supported-error "an RSA modulus longer than 8,192 bits"
    #(webcrypto/generate-key (rsa-params 8320 exponent) false [:sign])]
   [:not-supported-error "the public exponent 17"
    #(webcrypto/generate-key (rsa-params 1024 (bytes/of [17])) false [:sign])]
   [:operation-error "the public exponent 1"
    #(webcrypto/generate-key (rsa-params 1024 (bytes/of [1])) false [:sign])]
   [:type-error "a public exponent that isn't bytes"
    #(webcrypto/generate-key (rsa-params 1024 65537) false [:sign])]
   [:type-error "RSA-PSS without a salt length"
    (with-key rsa-pss-key #(webcrypto/sign :rsa-pss % message))]
   [:operation-error "a salt too long for the key"
    (with-key rsa-pss-key #(webcrypto/sign {:name :rsa-pss :salt-length 300} % message))]
   [:type-error "ECDH without a public key"
    (with-key #(ecdh-pair :p-256) #(webcrypto/derive-bits {:name :ecdh} (:private-key %) nil))]
   [:type-error "an ECDH public key that isn't a key"
    (with-key #(ecdh-pair :p-256) #(webcrypto/derive-bits (ecdh "key") (:private-key %) nil))]
   [:invalid-access-error "ECDH with a private key as the public key"
    (with-key #(ecdh-pair :p-256) #(webcrypto/derive-bits (ecdh (:private-key %)) (:private-key %) nil))]
   [:invalid-access-error "ECDH with keys on two curves"
    (with-key #(all [(ecdh-pair :p-256) (ecdh-pair :p-384)])
      (fn [[a b]] (webcrypto/derive-bits (ecdh (:public-key b)) (:private-key a) nil)))]
   [:invalid-access-error "ECDH with the public key of ECDSA"
    (with-key #(all [(ecdh-pair :p-256) (ecdsa-pair)])
      (fn [[a b]] (webcrypto/derive-bits (ecdh (:public-key b)) (:private-key a) nil)))]
   [:operation-error "more bits than ECDH derives"
    (with-key #(ecdh-pair :p-256) #(webcrypto/derive-bits (ecdh (:public-key %)) (:private-key %) 264))]
   [:data-error "an EC PKCS#8 whose public key isn't its private key's"
    #(webcrypto/import-key :pkcs8 mismatched-pkcs8 p-256 false [:sign])]
   [:data-error "an RSA public exponent of 1, which the JDK threw an exception of its own for"
    #(webcrypto/import-key :spki (rsa-spki (:n rsa-numbers) (bytes/of [1])) (:algorithm node-rsa) false [:verify])]
   [:data-error "an even RSA public exponent, which Chrome refuses"
    #(webcrypto/import-key :spki (rsa-spki (:n rsa-numbers) (bytes/of [1 0 0])) (:algorithm node-rsa) false [:verify])]
   [:not-supported-error "an RSA public exponent of 34 bits, which Chrome refuses"
    #(webcrypto/import-key :spki (rsa-spki (:n rsa-numbers) (bytes/of [2 0 0 0 1])) (:algorithm node-rsa) false
                           [:verify])]
   [:data-error "an even RSA modulus, which Chrome refuses"
    #(webcrypto/import-key :spki (rsa-spki even-modulus (:e rsa-numbers)) (:algorithm node-rsa) false [:verify])]
   [:data-error "rsaEncryption without its NULL parameters, which Chrome refuses"
    #(webcrypto/import-key :spki (rsa-spki (:n rsa-numbers) (:e rsa-numbers) nil) (:algorithm node-rsa) false
                           [:verify])]
   [:data-error "an RSA private key whose numbers disagree, which Chrome refuses and Node takes"
    #(webcrypto/import-key :jwk (assoc (:jwk node-rsa) :dp (:dq (:jwk node-rsa))) (:algorithm node-rsa) false [:sign])]
   [:data-error "an RSA private key with a prime of 1, which the JDK divided by zero for"
    #(webcrypto/import-key :jwk (assoc (:jwk node-rsa) :p "AQ" :q (:n (:jwk node-rsa))) (:algorithm node-rsa) false
                           [:sign])]
   [:data-error "DER nested deeper than any key, which overflowed the stack"
    #(webcrypto/import-key :spki (reduce (fn [inner _] (der/sequence-of inner)) (der/null) (range 50)) p-256 false
                           [:verify])]
   [:data-error "an object identifier with an arc that isn't in its fewest bytes"
    #(webcrypto/import-key :spki (ec-spki-with-oid (hex "2a808648ce3d0201")) p-256 false [:verify])]
   [:data-error "an object identifier with an arc too long for a number"
    #(webcrypto/import-key :spki (ec-spki-with-oid (hex "2bffffffffffffffffff01")) p-256 false [:verify])]])

(def ed25519-refusals
  "The refusals of Ed25519, where the platform has it."
  (let [node-jwk (:jwk (made-on :node :ed25519))]
    [[:data-error "an Ed25519 key of 31 bytes"
      #(webcrypto/import-key :raw (bytes/of (range 31)) :ed25519 false [:verify])]
     [:data-error "an Ed25519 JWK whose public key isn't its private key's"
      #(webcrypto/import-key :jwk (assoc node-jwk :x (:x (:jwk (made-on :jvm :ed25519))))
                             :ed25519 false [:sign])]
     [:data-error "a JWK of Ed448"
      #(webcrypto/import-key :jwk (assoc node-jwk :crv "Ed448") :ed25519 false [:sign])]
     [:syntax-error "an Ed25519 key that derives bits"
      #(webcrypto/generate-key :ed25519 false [:sign :derive-bits])]
     [:data-error "an Ed25519 key of small order, which verifies forgeries everywhere"
      #(webcrypto/import-key :raw identity-point :ed25519 false [:verify])]
     [:data-error "an Ed25519 key of small order with the sign bit"
      #(webcrypto/import-key :raw (hex "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
                             :ed25519 false [:verify])]
     [:data-error "the SPKI of an Ed25519 key of small order"
      #(webcrypto/import-key :spki (der/write-spki (der/oids :ed25519) nil identity-point) :ed25519 false [:verify])]]))

(deftest the-same-errors-everywhere
  (run #(all (for [[kind why f] (concat refusals (when ed25519? ed25519-refusals))]
               (fails-with kind why f)))))

;; Signatures that a platform verified, or threw an exception of its own for
(deftest forged-signatures
  (run #(-> (all [(ecdsa-pair)
                  (webcrypto/import-key :spki (hex (:spki (made-on :jvm :rsa-pss))) {:name :rsa-pss :hash :sha-256}
                                        false [:verify])])
            (then (fn [[{:keys [public-key]} rsa-pss-key]]
                    (all [(webcrypto/verify {:name :ecdsa :hash :sha-256} public-key (bytes/of (repeat 64 0)) message)
                          (webcrypto/verify {:name :ecdsa :hash :sha-256} public-key
                                            (bytes/concat (hex (:order (ec/curves :p-256))) (bytes/of (repeat 31 0))
                                                          (bytes/of [1]))
                                            message)
                          (webcrypto/verify {:name :rsa-pss :salt-length 0xFFFFFFFF} rsa-pss-key (bytes/of (range 256))
                                            message)])))
            (then (fn [[zeros r-of-order huge-salt]]
                    (is (false? zeros) "r and s of 0, which JDK 15 to 18 verified (CVE-2022-21449)")
                    (is (false? r-of-order) "r of the curve's order")
                    (is (false? huge-salt) "a salt longer than the JDK's int"))))
       #(when ed25519?
          (-> (webcrypto/generate-key :ed25519 false [:sign :verify])
              (then (fn [{:keys [public-key private-key]}]
                      (then (webcrypto/sign :ed25519 private-key message)
                            (fn [signature]
                              (webcrypto/verify :ed25519 public-key
                                                (bytes/concat identity-point (bytes/slice signature 32))
                                                message)))))
              (then (fn [verified] (is (false? verified) "an R of small order")))))))

(defn without-point
  "The PKCS#8 bytes `pkcs8` of an EC key without the public key in its
  ECPrivateKey."
  [pkcs8]
  (let [{:keys [algorithm parameters private-key]} (der/private-key-info pkcs8)]
    (der/write-private-key-info algorithm (der/oid (der/read-oid parameters))
                                (der/sequence-of (der/small-integer 1)
                                                 (der/octet-string (:d (der/ec-private-key private-key)))))))

;; RFC 5915, section 3: the public key is optional, e.g. in the PKCS#8 of
;; the JDK, so the import computes it
(deftest points-of-private-keys
  (run #(all (for [{:keys [made-on algorithm jwk pkcs8]} fixtures/made-elsewhere
                   :when (:named-curve algorithm)
                   :let [why                (str (algorithm-name algorithm) " made on " (name made-on))
                         [private-usages _] (usages-of (algorithm-name algorithm))]]
               (-> (webcrypto/import-key :pkcs8 (without-point (hex pkcs8)) algorithm true private-usages)
                   (then (partial exported :jwk))
                   (then (fn [computed] (is (= (select-keys jwk [:x :y]) (select-keys computed [:x :y])) why))))))))

;; SEC 1, section 2.3.3, where 02 or 03 says whether y is even or odd
(deftest compressed-points
  (let [compressed (bytes/concat (bytes/of [(if (odd? (bytes/at point 64)) 3 2)])
                                 (bytes/slice point 1 33))]
    (run #(-> (webcrypto/import-key :raw compressed p-256 true [:verify])
              (then (partial exported :raw))
              (then (fn [raw] (is (= (bytes/hex point) raw) "exports uncompressed")))))))
