(ns dk.simongray.webcrypto
  "The Web Cryptography API of the W3C, the same on the JVM, in Node and in
  browsers. It uses the JCA on the JVM and WebCrypto in JavaScript.

  The methods of SubtleCrypto are here under their names in kebab case,
  e.g. import-key, and take their arguments in the same order. Each returns
  its result on the JVM (and a promise of it in ClojureScript). To chain
  them the same way on both platforms, use then.

  - An algorithm is a keyword, its WebCrypto name in lower case (e.g.
    :sha-256), or a map of its :name and its parameters, named as the
    members of its dictionary in kebab case (e.g. :tag-length).
  - A usage of a key is a keyword, e.g. :encrypt or :derive-bits, and a
    format is :raw, :spki, :pkcs8 or :jwk.
  - Bytes are a byte array on the JVM and a Uint8Array in JavaScript.
  - A JWK is a map of its JSON members as keywords, e.g. :kty and :key_ops.
  - A key is WebCrypto's CryptoKey in ClojureScript and a type of the
    library's own on the JVM. Use key-info for its attributes. A key pair
    is a map of its :public-key and its :private-key.

  The algorithms are these:

  - SHA-1 and SHA-2 for digest
  - HMAC, ECDSA, RSASSA-PKCS1-v1_5, RSA-PSS and Ed25519 for sign and verify
  - AES-GCM for encrypt and decrypt
  - HKDF, PBKDF2 and ECDH for derive-bits and derive-key

  ECDSA and ECDH take the curves P-256, P-384 and P-521. Ed25519 needs
  Java 15 or later on the JVM. For hashes, HMACs and HKDF without promises,
  see the hash namespace, and for keys in PEM, the pem namespace.

  An error is an ex-info whose :type is one of these keywords, named after
  the exceptions of WebCrypto, section 14.4:

  - ::not-supported-error, for an algorithm, a format or a parameter that
    the library doesn't support
  - ::syntax-error, for usages that a key can't have, or none
  - ::invalid-access-error, for a key of another algorithm or type, without
    the usage, or one that can't be exported
  - ::data-error, for key data that isn't what the algorithm takes
  - ::operation-error, for an operation that fails, e.g. a decryption of a
    changed ciphertext, or a parameter out of its range
  - ::type-error, for an argument of the wrong type or a missing parameter"
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.aes-gcm :as aes-gcm]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.ec :as ec]
            [dk.simongray.webcrypto.impl.ed25519 :as ed25519]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.hmac :as hmac]
            [dk.simongray.webcrypto.impl.kdf :as kdf]
            [dk.simongray.webcrypto.impl.keys :as keys]
            [dk.simongray.webcrypto.impl.random :as random]
            [dk.simongray.webcrypto.impl.rsa :as rsa]
            #?(:clj  [dk.simongray.webcrypto.hash :as hash]
               :cljs [dk.simongray.webcrypto.impl.subtle :as subtle])))

;; WebCrypto, section 10.1.1
(defn random-bytes
  "An array of `n` random bytes from the platform's secure source of
  randomness, as getRandomValues fills one, but with a limit of
  2,147,483,647 bytes rather than its 65,536, as a Java array has."
  [n]
  (errors/check (nat-int? n) :type-error "The number of random bytes is a natural number")
  (errors/check (<= n 0x7FFFFFFF) :quota-exceeded-error
                "The library makes at most 2,147,483,647 random bytes at a time")
  (random/random-bytes n))

(defn then
  "The result of calling `f` on `x`: at once on the JVM, and in
  ClojureScript a promise of it, once `x` resolves if it's a promise. It
  chains the results of the other functions here the same way on both
  platforms.

      (-> (import-key :raw (bytes/encode \"hunter2\") :pbkdf2 false [:derive-key])
          (then #(derive-key params % {:name :aes-gcm :length 256} false [:encrypt])))"
  [x f]
  (async/then x f))

(defn key?
  "Whether `x` is a key."
  [x]
  (keys/crypto-key? x))

;; WebCrypto, section 13.4
(defn key-info
  "The attributes of the `key` as a map:

  - :type, :secret, :public or :private
  - :extractable?, whether export-key can export it
  - :algorithm, its algorithm, e.g. {:name :hmac :hash :sha-256 :length 512}
    or {:name :ecdsa :named-curve :p-256}
  - :usages, the set of its usages"
  [key]
  (errors/check (key? key) :type-error "The key isn't a key")
  (keys/info key))

(defn ^:no-doc check-format
  "Throw type-error unless `format` is a format of WebCrypto."
  [format]
  (errors/check (contains? #{:raw :spki :pkcs8 :jwk} format) :type-error
                "A format is :raw, :spki, :pkcs8 or :jwk"))

(defn ^:no-doc unsupported
  "The error for the algorithm `alg` in the operation `op`, which the
  library can't do."
  [alg op]
  (errors/error :not-supported-error
                (str "The library has no " (:name alg) " for " (name op))))

;; WebCrypto, section 14.3.5
(defn digest
  "The digest of the bytes `data` by the `algorithm`: :sha-1, :sha-256,
  :sha-384 or :sha-512. In JavaScript this is WebCrypto's own digest, which
  is faster on large data than hash/digest."
  [algorithm data]
  (async/promised
   (fn []
     (errors/check-bytes data "data")
     (let [alg (algorithms/normalize :digest algorithm)]
       #?(:clj  (hash/digest (:name alg) data)
          :cljs (subtle/digest alg data))))))

;; WebCrypto, section 14.3.3
(defn sign
  "The signature of the bytes `data` with the `key` by the `algorithm`,
  e.g. :hmac, :ed25519 or {:name :ecdsa :hash :sha-256}. An ECDSA
  signature is r and s side by side, as in JOSE."
  [algorithm key data]
  (async/promised
   (fn []
     (errors/check-bytes data "data")
     (let [alg (algorithms/normalize :sign algorithm)]
       (keys/check key alg :sign)
       (case (:name alg)
         :hmac                         (hmac/sign key data)
         :ecdsa                        (ec/sign alg key data)
         (:rsassa-pkcs1-v1_5 :rsa-pss) (rsa/sign alg key data)
         :ed25519                      (ed25519/sign key data)
         (throw (unsupported alg :sign)))))))

;; WebCrypto, section 14.3.4
(defn verify
  "Whether `signature` is the signature of the bytes `data` with the `key`
  by the `algorithm`, e.g. :hmac."
  [algorithm key signature data]
  (async/promised
   (fn []
     (errors/check-bytes signature "signature")
     (errors/check-bytes data "data")
     (let [alg (algorithms/normalize :verify algorithm)]
       (keys/check key alg :verify)
       (case (:name alg)
         :hmac                         (hmac/verify key signature data)
         :ecdsa                        (ec/verify alg key signature data)
         (:rsassa-pkcs1-v1_5 :rsa-pss) (rsa/verify alg key signature data)
         :ed25519                      (ed25519/verify key signature data)
         (throw (unsupported alg :verify)))))))

;; WebCrypto, section 14.3.1
(defn encrypt
  "The bytes `data` encrypted with the `key` by the `algorithm`, e.g.
  {:name :aes-gcm :iv iv}. With AES-GCM the tag follows the ciphertext."
  [algorithm key data]
  (async/promised
   (fn []
     (errors/check-bytes data "data")
     (let [alg (algorithms/normalize :encrypt algorithm)]
       (keys/check key alg :encrypt)
       (case (:name alg)
         :aes-gcm (aes-gcm/encrypt alg key data)
         (throw (unsupported alg :encrypt)))))))

;; WebCrypto, section 14.3.2
(defn decrypt
  "The plaintext of the bytes `data` that the `key` encrypted by the
  `algorithm`, e.g. {:name :aes-gcm :iv iv}. A ciphertext that was changed,
  or that another key or IV encrypted, throws operation-error."
  [algorithm key data]
  (async/promised
   (fn []
     (errors/check-bytes data "data")
     (let [alg (algorithms/normalize :decrypt algorithm)]
       (keys/check key alg :decrypt)
       (case (:name alg)
         :aes-gcm (aes-gcm/decrypt alg key data)
         (throw (unsupported alg :decrypt)))))))

;; WebCrypto, section 14.3.6
(defn generate-key
  "A new key of the `algorithm`, e.g. {:name :aes-gcm :length 256}, which
  is `extractable` (or not) and has the `usages`, e.g. [:encrypt
  :decrypt]. For an asymmetric algorithm it's a key pair, whose public key
  is always extractable:

      (generate-key {:name :ecdsa :named-curve :p-256} false [:sign :verify])
      ;; => {:public-key … :private-key …}"
  [algorithm extractable usages]
  (async/promised
   (fn []
     (let [usages (keys/usages usages)
           alg    (algorithms/normalize :generate-key algorithm)]
       (async/then (case (:name alg)
                     :hmac                         (hmac/generate-key alg extractable usages)
                     :aes-gcm                      (aes-gcm/generate-key alg extractable usages)
                     (:ecdsa :ecdh)                (ec/generate-key alg extractable usages)
                     (:rsassa-pkcs1-v1_5 :rsa-pss) (rsa/generate-key alg extractable usages)
                     :ed25519                      (ed25519/generate-key extractable usages)
                     (throw (unsupported alg :generate-key)))
                   (fn [key]
                     (keys/check-present-usages key)
                     key))))))

(defn ^:no-doc import-key*
  "The key of the key `data` in the `format` for the normalized algorithm
  `alg`, which is `extractable` and has the `usages`."
  [format data alg extractable usages]
  (case (:name alg)
    :hmac                         (hmac/import-key format data alg extractable usages)
    :aes-gcm                      (aes-gcm/import-key format data extractable usages)
    :hkdf                         (kdf/import-hkdf-key format data extractable usages)
    :pbkdf2                       (kdf/import-pbkdf2-key format data extractable usages)
    (:ecdsa :ecdh)                (ec/import-key format data alg extractable usages)
    (:rsassa-pkcs1-v1_5 :rsa-pss) (rsa/import-key format data alg extractable usages)
    :ed25519                      (ed25519/import-key format data extractable usages)
    (throw (unsupported alg :import-key))))

;; WebCrypto, section 14.3.9
(defn import-key
  "The key of the key `data` in the `format`, for the `algorithm`, which is
  `extractable` (or not) and has the `usages`.

  The data is bytes for :raw, :spki and :pkcs8, and a map for :jwk, e.g. a
  password for PBKDF2:

      (import-key :raw (bytes/encode \"hunter2\") :pbkdf2 false [:derive-key])

  To import a key in PEM, read it with the pem namespace first."
  [format data algorithm extractable usages]
  (async/promised
   (fn []
     (check-format format)
     (let [usages (keys/usages usages)
           alg    (algorithms/normalize :import-key algorithm)]
       (if (= :jwk format)
         (errors/check (map? data) :type-error "A JWK is a map")
         (errors/check-bytes data "key data"))
       (async/then (import-key* format data alg extractable usages)
                   (fn [key]
                     (keys/check-present-usages key)
                     key))))))

;; WebCrypto, section 14.3.10
(defn export-key
  "The `key` in the `format`: bytes for :raw, :spki and :pkcs8, and a map
  for :jwk. Only a key that was made extractable exports, a public key as
  :spki (or :raw for ECDSA, ECDH and Ed25519) and a private key as :pkcs8."
  [format key]
  (async/promised
   (fn []
     (check-format format)
     (errors/check (key? key) :type-error "The key isn't a key")
     (let [{:keys [algorithm extractable?]} (keys/info key)]
       (errors/check (contains? algorithms/exportable (:name algorithm))
                     :not-supported-error
                     (str "The library can't export a key of " (:name algorithm)))
       (errors/check extractable? :invalid-access-error "The key isn't extractable")
       (case (:name algorithm)
         :hmac                         (hmac/export-key format key)
         :aes-gcm                      (aes-gcm/export-key format key)
         (:ecdsa :ecdh)                (ec/export-key format key)
         (:rsassa-pkcs1-v1_5 :rsa-pss) (rsa/export-key format key)
         :ed25519                      (ed25519/export-key format key))))))

(defn- check-length
  "Throw type-error unless `length`, a number of bits, is nil or an
  unsigned long of WebIDL."
  [length]
  (errors/check (or (nil? length) (and (nat-int? length) (<= length 0xFFFFFFFF)))
                :type-error "A length is a number of bits, or nil"))

(defn ^:no-doc derive-bits*
  "The `length` bits that the `key` derives by the normalized algorithm
  `alg`."
  [alg key length]
  (case (:name alg)
    :hkdf   (kdf/hkdf-bits alg key length)
    :pbkdf2 (kdf/pbkdf2-bits alg key length)
    :ecdh   (ec/derive-bits alg key length)
    (throw (unsupported alg :derive-bits))))

;; WebCrypto, section 14.3.8
(defn derive-bits
  "The `length` bits, as bytes, that the `algorithm` derives from the base
  key `key`, e.g. {:name :hkdf :hash :sha-256 :salt salt :info info}. The
  length is a whole number of bytes, in bits, except for ECDH, which takes
  any length and also nil, for all its bits:

      (derive-bits {:name :ecdh :public their-public-key} my-private-key nil)"
  [algorithm key length]
  (async/promised
   (fn []
     (check-length length)
     (let [alg (algorithms/normalize :derive-bits algorithm)]
       (keys/check key alg :derive-bits)
       (derive-bits* alg key length)))))

#?(:cljs
   (defn- check-derivation
     "Throw unless the normalized algorithm `alg` can derive `length` bits
     from the `key`."
     [alg key length]
     (case (:name alg)
       :hkdf   (kdf/check-hkdf alg length)
       :pbkdf2 (kdf/check-pbkdf2 alg length)
       :ecdh   (ec/check-ecdh alg key length))))

(defn- key-length
  "The length in bits of a key of the normalized algorithm `alg`, or nil
  for an algorithm whose keys have no length."
  [alg]
  (case (:name alg)
    :hmac    (hmac/key-length alg)
    :aes-gcm (aes-gcm/key-length alg)
    nil))

;; WebCrypto, section 14.3.7
(defn derive-key
  "A new key of the `derived-key-type`, e.g. {:name :aes-gcm :length 256},
  that the `algorithm` derives from the base key `key`, which is
  `extractable` (or not) and has the `usages`.

      (derive-key {:name :pbkdf2 :hash :sha-256 :salt salt :iterations 600000}
                  password
                  {:name :aes-gcm :length 256}
                  false
                  [:encrypt :decrypt])"
  [algorithm key derived-key-type extractable usages]
  (async/promised
   (fn []
     (let [usages  (keys/usages usages)
           alg     (algorithms/normalize :derive-bits algorithm)
           derived (algorithms/normalize :import-key derived-key-type)
           length  (key-length (algorithms/normalize :get-key-length derived-key-type))]
       (keys/check key alg :derive-key)
       (-> #?(:clj  (async/then (derive-bits* alg key length)
                                #(import-key* :raw % derived extractable usages))
              ;; WebCrypto's own deriveKey, since its deriveBits would need
              ;; the usage :derive-bits
              :cljs (do (check-derivation alg key length)
                        (keys/check-usages (:name derived) usages)
                        (subtle/derive-key alg key (assoc derived :length length)
                                           extractable usages)))
           (async/then (fn [derived-key]
                         (keys/check-present-usages derived-key)
                         derived-key)))))))

(comment
  (def k (generate-key {:name :aes-gcm :length 256} true [:encrypt :decrypt]))
  (key-info k)
  (def iv (random-bytes 12))
  (bytes/decode (decrypt {:name :aes-gcm :iv iv} k
                         (encrypt {:name :aes-gcm :iv iv} k (bytes/encode "a secret"))))
  (export-key :jwk k)
  (def pair (generate-key {:name :ecdsa :named-curve :p-256} true [:sign :verify]))
  (export-key :jwk (:private-key pair))
  #_.)
