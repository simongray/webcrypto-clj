(ns ^:no-doc dk.simongray.webcrypto.impl.rsa
  "RSASSA-PKCS1-v1_5 and RSA-PSS, as WebCrypto has them in sections 20 and
  21, on both platforms. Each function returns its result on the JVM and a
  promise of it in ClojureScript.

  The formats of a key come from its numbers, so that each platform exports
  the same bytes. The library refuses what one platform refuses: Chrome
  makes moduli of a multiple of 128 bits up to 8,192 and the public
  exponents 3 and 65537 alone, and takes public exponents of up to 33 bits
  and private keys whose numbers agree, and the JDK takes moduli from 512
  to 16,384 bits."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.jwk :as jwk]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?(:cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.math BigInteger]
                   [java.security GeneralSecurityException KeyFactory KeyPair KeyPairGenerator
                    PrivateKey PublicKey Signature]
                   [java.security.interfaces RSAPrivateCrtKey RSAPublicKey]
                   [java.security.spec MGF1ParameterSpec PSSParameterSpec RSAKeyGenParameterSpec
                    RSAPrivateCrtKeySpec RSAPublicKeySpec])))

;; JWA, section 3.1 and 3.5, and WebCrypto, sections 20.9.4 and 21.4.4
(def jwa
  "The JWA algorithm of a key of each algorithm by its hash."
  {:rsassa-pkcs1-v1_5 {:sha-1 "RS1" :sha-256 "RS256" :sha-384 "RS384" :sha-512 "RS512"}
   :rsa-pss           {:sha-1 "PS1" :sha-256 "PS256" :sha-384 "PS384" :sha-512 "PS512"}})

(defn- stripped
  "The bytes `b` of an unsigned integer without leading zeros, or a single
  zero for zero (WebCrypto, section 16)."
  [b]
  (let [zeros (count (take-while #(zero? (bytes/at b %)) (range (bytes/length b))))]
    (if (= zeros (bytes/length b))
      (bytes/of [0])
      (bytes/slice b zeros))))

(defn- bit-length
  "The number of bits of the unsigned integer of the bytes `b`."
  [b]
  (let [b (stripped b)]
    (+ (* 8 (dec (bytes/length b)))
       (count (take-while pos? (iterate #(bit-shift-right % 1) (bytes/at b 0)))))))

;; WebCrypto, section 20.5
(defn- check-key-gen
  "Throw unless the `modulus-length` and the `public-exponent`, bytes, can
  make a key pair on every platform."
  [modulus-length public-exponent]
  (let [e (bytes/hex (stripped public-exponent))]
    (errors/check (and (>= modulus-length 4)
                       (not= "00" e) (not= "01" e) (not= "02" e)
                       (odd? (bytes/at public-exponent (dec (bytes/length public-exponent))))
                       (< (bit-length public-exponent) modulus-length))
                  :operation-error "The modulus length or the public exponent can't make an RSA key")
    (errors/check (and (zero? (mod modulus-length 128)) (<= 512 modulus-length 8192))
                  :not-supported-error
                  "The library makes RSA keys of a multiple of 128 bits from 512 to 8,192, as Chrome does")
    (errors/check (contains? #{"03" "010001"} e) :not-supported-error
                  "The library makes RSA keys with the public exponents 3 and 65537 alone, as Chrome does")))

(defn- odd-bytes?
  "Whether the unsigned integer of the bytes `b`, which aren't empty, is
  odd."
  [b]
  (odd? (bytes/at b (dec (bytes/length b)))))

;; RFC 8017, section 3.1
(defn- check-public
  "Throw unless the modulus `n` and the public exponent `e`, bytes, are a
  public key that every platform takes, as Chrome checks them."
  [n e]
  (let [e (stripped e)]
    (errors/check (<= 512 (bit-length n) 16384) :not-supported-error
                  "The library takes RSA keys of 512 to 16,384 bits, as the JDK does")
    (errors/check (odd-bytes? n) :data-error "An RSA modulus is odd")
    (errors/check (and (odd-bytes? e) (not= "01" (bytes/hex e))) :data-error
                  "An RSA public exponent is odd and greater than 1")
    (errors/check (<= (bit-length e) 33) :not-supported-error
                  "The library takes RSA public exponents of up to 33 bits, as Chrome does")))

#?(:clj
   (defn- algorithm-of
     "The KeyAlgorithm of a key of the algorithm named `name` by the `hash`,
     whose modulus is `n` and public exponent `e`, as bytes."
     [name hash n e]
     {:name name :modulus-length (bit-length n) :public-exponent (stripped e) :hash hash}))

(defn- big
  "The unsigned integer of the bytes `b`: a BigInteger on the JVM and a
  BigInt in JavaScript."
  [b]
  #?(:clj  (BigInteger. 1 ^bytes b)
     :cljs (js/BigInt (str "0x0" (bytes/hex b)))))

;; ClojureScript's arithmetic takes numbers, so JavaScript's operators do
;; it for BigInts
(defn- times
  "The product of the integers `a` and `b`."
  [a b]
  #?(:clj (.multiply ^BigInteger a b) :cljs (js* "(~{} * ~{})" a b)))

(defn- minus
  "The integer `a` minus `b`."
  [a b]
  #?(:clj (.subtract ^BigInteger a b) :cljs (js* "(~{} - ~{})" a b)))

(defn- modulo
  "The non-negative integer `a` modulo the positive `b`."
  [a b]
  #?(:clj (.mod ^BigInteger a b) :cljs (js* "(~{} % ~{})" a b)))

(defn- quotient
  "The non-negative integer `a` divided by the positive `b`, rounded down."
  [a b]
  #?(:clj (.divide ^BigInteger a b) :cljs (js* "(~{} / ~{})" a b)))

(defn- same-integer?
  "Whether the integers `a` and `b` are the same."
  [a b]
  #?(:clj (= a b) :cljs (js* "(~{} === ~{})" a b)))

(defn- gcd
  "The greatest common divisor of the non-negative integers `a` and `b`."
  [a b]
  #?(:clj  (.gcd ^BigInteger a b)
     :cljs (if (same-integer? b (big (bytes/of [0]))) a (recur b (modulo a b)))))

;; RFC 8017, section 3.2, the relations of the numbers of a private key
(defn- consistent?
  "Whether the numbers of the map `m`, as bytes, are those of one RSA
  private key. Chrome and the JDK refuse a key whose numbers disagree, and
  Node takes it."
  [m]
  (let [{:keys [n e d p q dp dq qi]} (update-vals m big)
        zero (big (bytes/of [0]))
        one  (big (bytes/of [1]))
        p-1  (minus p one)
        q-1  (minus q one)]
    ;; a prime of 1 would divide by zero below, and one of 0 fails n = pq
    (and (not (same-integer? zero p-1))
         (not (same-integer? zero q-1))
         (same-integer? n (times p q))
         (same-integer? dp (modulo d p-1))
         (same-integer? dq (modulo d q-1))
         (same-integer? one (modulo (times qi q) p))
         (same-integer? one (modulo (times e d)
                                    (quotient (times p-1 q-1) (gcd p-1 q-1)))))))

#?(:clj
   (defn- unsigned-bytes
     "The unsigned integer `n` as bytes without leading zeros."
     [^BigInteger n]
     (stripped (.toByteArray n))))

#?(:clj
   (defn- public-key-of
     "The PublicKey of the modulus `n` and the public exponent `e`, as
     bytes."
     [n e]
     (.generatePublic (KeyFactory/getInstance "RSA") (RSAPublicKeySpec. (big n) (big e)))))

#?(:clj
   (defn- key-pair-of
     "The KeyPair of the numbers of the map `m`, as bytes."
     [m]
     (let [{:keys [n e d p q dp dq qi]} (update-vals m big)]
       (KeyPair. (public-key-of (:n m) (:e m))
                 (.generatePrivate (KeyFactory/getInstance "RSA")
                                   (RSAPrivateCrtKeySpec. n e d p q dp dq qi))))))

;; WebCrypto, sections 20.9.3 and 21.4.3
(defn generate-key
  "A new key pair of the normalized algorithm `alg`, of RSASSA-PKCS1-v1_5 or
  RSA-PSS, whose private key is `extractable` and has its share of the
  `usages`."
  [{:keys [name modulus-length public-exponent] :as alg} extractable usages]
  (keys/check-usages name usages)
  (check-key-gen modulus-length public-exponent)
  #?(:clj  (let [kp (.generateKeyPair (doto (KeyPairGenerator/getInstance "RSA")
                                        (.initialize (RSAKeyGenParameterSpec. (int modulus-length)
                                                                              (big public-exponent)))))]
             (keys/key-pair (algorithm-of name (:hash alg)
                                          (unsigned-bytes (.getModulus ^RSAPublicKey (.getPublic kp)))
                                          public-exponent)
                            extractable usages kp))
     :cljs (subtle/generate-key alg extractable usages)))

;; RFC 3279, section 2.3.1, whose NULL parameters Chrome needs
(defn- check-algorithm
  "Throw data-error unless the `algorithm` of a key is rsaEncryption and
  its `parameters` are NULL."
  [algorithm parameters]
  (errors/check (= (der/oids :rsa-encryption) algorithm) :data-error
                "The key isn't an RSA key of rsaEncryption")
  (errors/check (and (= (der/tags :null) (:tag parameters))
                     (zero? (bytes/length (:content parameters))))
                :data-error "The parameters of rsaEncryption are NULL"))

(defn- check-jwk
  "Throw unless the `jwk` is a JWK of a key of the normalized algorithm
  `alg` that can have the `usages` and be `extractable`, and return its
  numbers as bytes in a map."
  [{:keys [name hash]} jwk extractable usages]
  (let [private? (contains? jwk :d)]
    (keys/check-allowed name (if private? #{:sign} #{:verify}) usages)
    (errors/check (= "RSA" (:kty jwk)) :data-error "The JWK of an RSA key has the kty RSA")
    (jwk/check-uses jwk "sig" extractable usages)
    (errors/check (contains? #{nil (get-in jwa [name hash])} (:alg jwk)) :data-error
                  (str "The JWK's alg isn't " (get-in jwa [name hash])))
    (errors/check (not (contains? jwk :oth)) :not-supported-error
                  "The library only takes RSA keys of two primes")
    (into {} (for [k (if private? der/rsa-private-fields [:n :e])]
               [k (jwk/member-bytes jwk k)]))))

;; WebCrypto, sections 20.9.4 and 21.4.4
(defn import-key
  "The key of the key `data` in the `format` for the normalized algorithm
  `alg`, of RSASSA-PKCS1-v1_5 or RSA-PSS, which is `extractable` and has
  the `usages`."
  [format data {:keys [name] :as alg} extractable usages]
  (let [numbers (case format
                  :spki  (do (keys/check-allowed name #{:verify} usages)
                             (let [{:keys [algorithm parameters public-key]} (der/spki data)]
                               (check-algorithm algorithm parameters)
                               (der/rsa-public-key public-key)))
                  :pkcs8 (do (keys/check-allowed name #{:sign} usages)
                             (let [{:keys [algorithm parameters private-key]} (der/private-key-info data)]
                               (check-algorithm algorithm parameters)
                               (der/rsa-private-key private-key)))
                  :jwk   (check-jwk alg data extractable usages)
                  (throw (errors/error :not-supported-error
                                       (str "The library can't import an RSA key as " format))))]
    (check-public (:n numbers) (:e numbers))
    (when (:d numbers)
      (errors/check (consistent? numbers) :data-error "The numbers aren't one RSA key's"))
    #?(:clj  (let [algorithm (algorithm-of name (:hash alg) (:n numbers) (:e numbers))]
               (try
                 (if (:d numbers)
                   (keys/make :private algorithm extractable usages (key-pair-of numbers))
                   (keys/make :public algorithm extractable usages
                              (public-key-of (:n numbers) (:e numbers))))
                 (catch GeneralSecurityException e
                   (throw (errors/error :data-error "The JDK refuses the RSA key" e)))))
       :cljs (subtle/import-key format data alg extractable usages))))

(defn- numbers
  "The numbers of the `key` as bytes in a map, its :n and :e and, when it's
  private, the rest of RFC 8017's numbers."
  [key]
  #?(:clj  (let [^RSAPublicKey public (keys/public-key key)]
             (merge {:n (unsigned-bytes (.getModulus public))
                     :e (unsigned-bytes (.getPublicExponent public))}
                    (when (= :private (:type (keys/info key)))
                      (let [^RSAPrivateCrtKey private (keys/private-key key)]
                        (update-vals {:d  (.getPrivateExponent private)
                                      :p  (.getPrimeP private)
                                      :q  (.getPrimeQ private)
                                      :dp (.getPrimeExponentP private)
                                      :dq (.getPrimeExponentQ private)
                                      :qi (.getCrtCoefficient private)}
                                     unsigned-bytes)))))
     :cljs (async/then (subtle/export-jwk key)
                       (fn [jwk]
                         (into {} (for [k der/rsa-private-fields
                                        :when (contains? jwk k)]
                                    [k (bytes/from-base64url (get jwk k))]))))))

;; WebCrypto, sections 20.9.5 and 21.4.5
(defn export-key
  "The `key` in the `format`: bytes for :spki and :pkcs8, and a map for
  :jwk."
  [format key]
  (let [{:keys [algorithm usages extractable?]} (keys/info key)]
    (errors/check (contains? #{:spki :pkcs8 :jwk} format) :not-supported-error
                  (str "The library can't export an RSA key as " format))
    (case format
      :spki  (keys/check-type key :public)
      :pkcs8 (keys/check-type key :private)
      nil)
    (async/then (numbers key)
                (fn [{:keys [n e] :as m}]
                  (case format
                    :spki  (der/write-spki (der/oids :rsa-encryption) (der/null)
                                          (der/write-rsa-public-key n e))
                    :pkcs8 (der/write-private-key-info (der/oids :rsa-encryption) (der/null)
                                                       (der/write-rsa-private-key m))
                    :jwk   (jwk/with-uses (into {:kty "RSA"
                                                 :alg (get-in jwa [(:name algorithm) (:hash algorithm)])}
                                                (for [[k v] m] [k (bytes/base64url v)]))
                                          usages extractable?))))))

#?(:clj
   (defn- jca-signature
     "A Signature of the JCA for the `key` of the normalized algorithm
     `alg`."
     [alg key]
     (let [hash (:hash (:algorithm (keys/info key)))]
       (if (= :rsa-pss (:name alg))
         (doto (Signature/getInstance "RSASSA-PSS")
           (.setParameter (PSSParameterSpec. (algorithms/names hash) "MGF1"
                                             (MGF1ParameterSpec. (algorithms/names hash))
                                             (int (:salt-length alg)) 1)))
         (Signature/getInstance (str (.replace ^String (algorithms/names hash) "-" "") "withRSA"))))))

;; RFC 8017, section 9.1.1, where a salt that leaves no room in the
;; encoded message is an error
(defn- salt-fits?
  "Whether the salt of the normalized algorithm `alg` fits a signature
  with the `key`, as it always does for RSASSA-PKCS1-v1_5."
  [alg key]
  (let [{:keys [modulus-length hash]} (:algorithm (keys/info key))]
    (or (not= :rsa-pss (:name alg))
        (<= (:salt-length alg)
            (- (quot (+ modulus-length 6) 8) (:size (algorithms/hashes hash)) 2)))))

;; WebCrypto, sections 20.9.1 and 21.4.1
(defn sign
  "The signature of the bytes `data` with the private `key` by the
  normalized algorithm `alg`."
  [alg key data]
  (keys/check-type key :private)
  (errors/check (salt-fits? alg key) :operation-error "The salt is too long for the key")
  #?(:clj  (try
             (let [^Signature s (jca-signature alg key)]
               (.initSign s ^PrivateKey (keys/private-key key))
               (.update s ^bytes data)
               (.sign s))
             (catch GeneralSecurityException e
               (throw (errors/error :operation-error (str "The key can't sign: " (.getMessage e)) e))))
     :cljs (subtle/sign alg key data)))

;; WebCrypto, sections 20.9.2 and 21.4.2
(defn verify
  "Whether `signature` is the signature of the bytes `data` with the public
  `key` by the normalized algorithm `alg`."
  [alg key signature data]
  (keys/check-type key :public)
  (and (salt-fits? alg key)
       #?(:clj  (try
                  (let [^Signature s (jca-signature alg key)]
                    (.initVerify s ^PublicKey (keys/public-key key))
                    (.update s ^bytes data)
                    (.verify s ^bytes signature))
                  (catch GeneralSecurityException _
                    false))
          :cljs (subtle/verify alg key signature data))))
