(ns ^:no-doc dk.simongray.webcrypto.impl.subtle
  "The methods of WebCrypto's SubtleCrypto in JavaScript, which take the
  library's algorithms and usages, return bytes for an ArrayBuffer, and
  reject with the library's errors."
  (:require [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.errors :as errors]))

;; WebCrypto, section 10.2.1, whose subtle attribute is [SecureContext]
(defn- subtle
  "WebCrypto's SubtleCrypto, or a throw of not-supported-error outside a
  secure context."
  []
  (or (some-> js/globalThis .-crypto .-subtle)
      (throw (errors/error :not-supported-error
                           (str "WebCrypto's SubtleCrypto is only there in a "
                                "secure context, e.g. a page served over "
                                "https or from localhost")))))

(defn- translated
  "The library's error for `e`, which WebCrypto rejected with."
  [^js e]
  (if-let [kind (errors/kinds (.-name e))]
    (errors/error kind (.-message e) e)
    e))

(defn call
  "A promise of what the `method` of SubtleCrypto returns for the `args`,
  with an ArrayBuffer as bytes and an error as the library's."
  [method & args]
  (-> (apply js-invoke (subtle) method args)
      (.then #(if (instance? js/ArrayBuffer %) (js/Uint8Array. %) %))
      (.catch #(throw (translated %)))))

(def member-names
  "The name in WebCrypto of each member of an algorithm's parameters."
  {:name            "name"
   :hash            "hash"
   :length          "length"
   :iv              "iv"
   :additional-data "additionalData"
   :tag-length      "tagLength"
   :salt            "salt"
   :info            "info"
   :iterations      "iterations"
   :named-curve     "namedCurve"
   :modulus-length  "modulusLength"
   :public-exponent "publicExponent"
   :salt-length     "saltLength"
   :public          "public"})

(defn js-algorithm
  "The normalized algorithm `alg` as WebCrypto takes it."
  [alg]
  (let [o #js {}]
    (doseq [[k v] alg]
      (aset o (member-names k) (if (keyword? v) (algorithms/names v) v)))
    o))

(defn js-usages
  "The `usages` of a key as WebCrypto takes them."
  [usages]
  (into-array (map algorithms/usage-names usages)))

(defn digest
  "A promise of the digest of the bytes `data` by the hash `alg`."
  [alg data]
  (call "digest" (js-algorithm alg) data))

(defn sign
  "A promise of the signature of the bytes `data` with the `key` by `alg`."
  [alg key data]
  (call "sign" (js-algorithm alg) key data))

(defn verify
  "A promise of whether `signature` signs the bytes `data` with the `key`
  by `alg`."
  [alg key signature data]
  (call "verify" (js-algorithm alg) key signature data))

(defn encrypt
  "A promise of the bytes `data` encrypted with the `key` by `alg`."
  [alg key data]
  (call "encrypt" (js-algorithm alg) key data))

(defn decrypt
  "A promise of the bytes `data` decrypted with the `key` by `alg`."
  [alg key data]
  (call "decrypt" (js-algorithm alg) key data))

(defn derive-bits
  "A promise of `length` bits derived from the `key` by `alg`."
  [alg key length]
  (call "deriveBits" (js-algorithm alg) key length))

(defn derive-key
  "A promise of a key of the algorithm `derived` that the `key` derives by
  `alg`, which is `extractable` and has the `usages`."
  [alg key derived extractable usages]
  (call "deriveKey" (js-algorithm alg) key (js-algorithm derived) extractable
        (js-usages usages)))

(defn generate-key
  "A promise of a key of the algorithm `alg`, `extractable` and with the
  `usages`, or of a key pair as a map of :public-key and :private-key."
  [alg extractable usages]
  (.then (call "generateKey" (js-algorithm alg) extractable (js-usages usages))
         (fn [^js k]
           (if (.-privateKey k)
             {:public-key (.-publicKey k) :private-key (.-privateKey k)}
             k))))

(defn import-key
  "A promise of the key of the key `data` in the `format`, bytes or a JWK
  as a map, for the algorithm `alg`, `extractable` and with the `usages`."
  [format data alg extractable usages]
  (call "importKey" (name format) (if (map? data) (clj->js data) data)
        (js-algorithm alg) extractable (js-usages usages)))

(defn import-raw
  "A promise of the key of the bytes `data` for the algorithm `alg`,
  `extractable` and with the `usages`."
  [data alg extractable usages]
  (import-key :raw data alg extractable usages))

(defn export-raw
  "A promise of the bytes of the `key`."
  [key]
  (call "exportKey" "raw" key))

(defn export-jwk
  "A promise of the JWK of the `key` as a map with keyword keys."
  [key]
  (.then (call "exportKey" "jwk" key) #(js->clj % :keywordize-keys true)))
