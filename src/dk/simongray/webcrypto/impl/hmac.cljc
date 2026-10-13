(ns ^:no-doc dk.simongray.webcrypto.impl.hmac
  "HMAC, as WebCrypto has it in section 31, on both platforms. Each
  function returns its result on the JVM and a promise of it in
  ClojureScript."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.jwk :as jwk]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?@(:clj  [[dk.simongray.webcrypto.hash :as hash]
                       [dk.simongray.webcrypto.impl.random :as random]]
                :cljs [[dk.simongray.webcrypto.impl.subtle :as subtle]])))

(def jwk-algorithms
  "The JWA algorithm of an HMAC key by each hash."
  {:sha-1   "HS1"
   :sha-256 "HS256"
   :sha-384 "HS384"
   :sha-512 "HS512"})

;; WebCrypto, section 31.6.1
(defn sign
  "The HMAC of the bytes `data` with the `key`."
  [key data]
  #?(:clj  (hash/hmac (:hash (:algorithm (keys/info key))) (keys/handle key) data)
     :cljs (subtle/sign {:name :hmac} key data)))

;; WebCrypto, section 31.6.2
(defn verify
  "Whether `signature` is the HMAC of the bytes `data` with the `key`,
  compared in constant time."
  [key signature data]
  #?(:clj  (bytes/same? (sign key data) signature)
     :cljs (subtle/verify {:name :hmac} key signature data)))

(defn block-length
  "The length in bits of a block of the `hash`, which is the length of an
  HMAC key by default."
  [hash]
  (* 8 (:block-size (algorithms/hashes hash))))

(defn check-length
  "Throw not-supported-error unless the `length` of a key in bits is a whole
  number of bytes, as the JDK and Node need."
  [length]
  (errors/check (zero? (mod length 8)) :not-supported-error
                "The library only takes HMAC keys of whole bytes, as the JDK and Node do"))

;; WebCrypto, section 31.6.3
(defn generate-key
  "A new key of the normalized algorithm `alg`, `extractable` and with the
  `usages`."
  [{:keys [hash length] :as alg} extractable usages]
  (keys/check-usages :hmac usages)
  (let [length (or length (block-length hash))]
    (errors/check (pos? length) :operation-error
                  "An HMAC key is longer than zero bits")
    (check-length length)
    #?(:clj  (keys/secret-key {:name :hmac :hash hash :length length}
                              extractable usages
                              (random/random-bytes (quot length 8)))
       :cljs (subtle/generate-key (assoc alg :length length) extractable usages))))

(defn- key-data
  "The bytes of the key `data` in the `format`, with the checks of a JWK of
  an HMAC key by the `hash`, which is `extractable` and has the `usages`."
  [format data hash extractable usages]
  (case format
    :raw data
    :jwk (let [b   (jwk/secret-bytes data)
               alg (jwk-algorithms hash)]
           (errors/check (contains? #{nil alg} (:alg data)) :data-error
                         (str "The JWK's alg isn't " alg))
           (jwk/check-uses data "sig" extractable usages)
           b)
    (throw (errors/error :not-supported-error
                         (str "The library can't import an HMAC key as " format)))))

;; WebCrypto, section 31.6.4
(defn import-key
  "The HMAC key of the key `data` in the `format`, for the normalized
  algorithm `alg`, `extractable` and with the `usages`."
  [format data {:keys [hash length] :as alg} extractable usages]
  (errors/check (not= 0 length) :data-error "An HMAC key is longer than zero bits")
  (keys/check-usages :hmac usages)
  (let [b    (key-data format data hash extractable usages)
        bits (* 8 (bytes/length b))]
    (errors/check (pos? bits) :data-error "An HMAC key can't be empty")
    (when length
      (errors/check (< (- bits 8) length (inc bits)) :data-error
                    (str "An HMAC key of " bits " bits can't have a length of " length))
      (check-length length))
    #?(:clj  (keys/secret-key {:name :hmac :hash hash :length bits}
                              extractable usages b)
       :cljs (subtle/import-raw b (assoc alg :length bits) extractable usages))))

;; WebCrypto, section 31.6.5
(defn export-key
  "The `key` in the `format`: its bytes for :raw, and a map for :jwk."
  [format key]
  (errors/check (contains? #{:raw :jwk} format) :not-supported-error
                (str "The library can't export an HMAC key as " format))
  (let [{:keys [algorithm usages extractable?]} (keys/info key)]
    (async/then (keys/raw key)
                (fn [b]
                  (if (= :jwk format)
                    (jwk/secret b (jwk-algorithms (:hash algorithm)) usages extractable?)
                    b)))))

;; WebCrypto, section 31.6.6
(defn key-length
  "The length in bits of a key of the normalized algorithm `alg`."
  [{:keys [hash length]}]
  (let [length (or length (block-length hash))]
    (errors/check (pos? length) :type-error "An HMAC key is longer than zero bits")
    (check-length length)
    length))
