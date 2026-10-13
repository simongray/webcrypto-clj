(ns ^:no-doc dk.simongray.webcrypto.impl.aes-gcm
  "AES-GCM, as WebCrypto has it in section 29, on both platforms, after
  NIST SP 800-38D. Each function returns its result on the JVM and a
  promise of it in ClojureScript.

  The library refuses AES keys of 192 bits, which Chrome refuses, tags of
  32 and 64 bits, which the JDK refuses, and IVs of fewer than 12 bytes or
  more than 128, which Node refuses."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.jwk :as jwk]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?(:clj  [dk.simongray.webcrypto.impl.random :as random]
               :cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.security GeneralSecurityException]
                   [javax.crypto Cipher]
                   [javax.crypto.spec GCMParameterSpec SecretKeySpec])))

(def jwk-algorithms
  "The JWA algorithm of an AES-GCM key by its length in bits."
  {128 "A128GCM"
   192 "A192GCM"
   256 "A256GCM"})

(defn check-length
  "Throw unless `length` is the length in bits of an AES key that every
  platform takes: not-supported-error for 192 bits, and the error of the
  `kind` for any other length but 128 and 256."
  [length kind]
  (errors/check (not= 192 length) :not-supported-error
                "The library refuses AES keys of 192 bits, since Chrome does")
  (errors/check (contains? #{128 256} length) kind
                "An AES key has 128 or 256 bits"))

(defn check-iv
  "Throw operation-error for an empty `iv`, which NIST SP 800-38D doesn't
  allow, and not-supported-error for an IV of fewer than 12 bytes or more
  than 128, which WebCrypto in Node refuses."
  [iv]
  (errors/check (pos? (bytes/length iv)) :operation-error
                "AES-GCM needs an IV of a byte at least")
  (errors/check (<= 12 (bytes/length iv) 128) :not-supported-error
                "The library only takes IVs of 12 to 128 bytes, as Node does"))

;; WebCrypto, sections 29.4.1 and 29.4.2
(defn tag-length
  "The length in bits of the tag of the normalized algorithm `alg`, 128
  by default."
  [{:keys [tag-length]}]
  (let [length (or tag-length 128)]
    (errors/check (not (contains? #{32 64} length)) :not-supported-error
                  "The library refuses GCM tags of 32 and 64 bits, since the JDK does")
    (errors/check (contains? #{96 104 112 120 128} length) :operation-error
                  "A GCM tag has 32, 64, 96, 104, 112, 120 or 128 bits")
    length))

#?(:clj
   (defn cipher
     "A Cipher of AES-GCM in the `mode` with the `key`, the IV and additional
     data of the normalized algorithm `alg`, and a tag of `tag-length` bits."
     [mode key {:keys [iv additional-data]} tag-length]
     (let [^bytes aad (or additional-data (byte-array 0))]
       (doto (Cipher/getInstance "AES/GCM/NoPadding")
         (.init (int mode)
                (SecretKeySpec. ^bytes (keys/handle key) "AES")
                (GCMParameterSpec. (int tag-length) ^bytes iv))
         (.updateAAD aad)))))

;; WebCrypto, section 29.4.1
(defn encrypt
  "The bytes `data` encrypted with the `key` by the normalized algorithm
  `alg`, followed by their tag."
  [alg key data]
  (check-iv (:iv alg))
  (let [tag-length (tag-length alg)]
    #?(:clj  (.doFinal ^Cipher (cipher Cipher/ENCRYPT_MODE key alg tag-length)
                       ^bytes data)
       :cljs (subtle/encrypt (assoc alg :tag-length tag-length) key data))))

;; WebCrypto, section 29.4.2
(defn decrypt
  "The plaintext of the bytes `data`, a ciphertext followed by its tag,
  which the `key` encrypted by the normalized algorithm `alg`. It throws
  operation-error when the ciphertext or its tag was changed, or when the
  key, the IV or the additional data differ."
  [alg key data]
  (let [tag-length (tag-length alg)]
    (check-iv (:iv alg))
    (errors/check (<= (quot tag-length 8) (bytes/length data)) :operation-error
                  "The ciphertext is shorter than its tag")
    #?(:clj  (try
               (.doFinal ^Cipher (cipher Cipher/DECRYPT_MODE key alg tag-length)
                         ^bytes data)
               (catch GeneralSecurityException e
                 (throw (errors/error :operation-error
                                      "The ciphertext doesn't open with this key, IV and additional data"
                                      e))))
       :cljs (subtle/decrypt (assoc alg :tag-length tag-length) key data))))

;; WebCrypto, section 29.4.3
(defn generate-key
  "A new key of the normalized algorithm `alg`, `extractable` and with the
  `usages`."
  [{:keys [length] :as alg} extractable usages]
  (keys/check-usages :aes-gcm usages)
  (check-length length :operation-error)
  #?(:clj  (keys/secret-key {:name :aes-gcm :length length} extractable usages
                            (random/random-bytes (quot length 8)))
     :cljs (subtle/generate-key alg extractable usages)))

(defn- jwk-bytes
  "The bytes of the key in the JWK `jwk` of AES-GCM, after the checks of
  its alg, for a key that is `extractable` and has the `usages`."
  [jwk extractable usages]
  (let [b      (jwk/secret-bytes jwk)
        length (* 8 (bytes/length b))]
    (check-length length :data-error)
    (errors/check (contains? #{nil (jwk-algorithms length)} (:alg jwk)) :data-error
                  (str "The JWK's alg isn't " (jwk-algorithms length)))
    (jwk/check-uses jwk "enc" extractable usages)
    b))

;; WebCrypto, section 29.4.4
(defn import-key
  "The AES-GCM key of the key `data` in the `format`, `extractable` and
  with the `usages`."
  [format data extractable usages]
  (keys/check-usages :aes-gcm usages)
  (let [b (case format
            :raw (do (check-length (* 8 (bytes/length data)) :data-error)
                     data)
            :jwk (jwk-bytes data extractable usages)
            (throw (errors/error :not-supported-error
                                 (str "The library can't import an AES-GCM key as " format))))]
    #?(:clj  (keys/secret-key {:name :aes-gcm :length (* 8 (bytes/length b))}
                              extractable usages b)
       :cljs (subtle/import-raw b {:name :aes-gcm} extractable usages))))

;; WebCrypto, section 29.4.5
(defn export-key
  "The `key` in the `format`: its bytes for :raw, and a map for :jwk."
  [format key]
  (errors/check (contains? #{:raw :jwk} format) :not-supported-error
                (str "The library can't export an AES-GCM key as " format))
  (let [{:keys [algorithm usages extractable?]} (keys/info key)]
    (async/then (keys/raw key)
                (fn [b]
                  (if (= :jwk format)
                    (jwk/secret b (jwk-algorithms (:length algorithm)) usages extractable?)
                    b)))))

;; WebCrypto, section 29.4.6
(defn key-length
  "The length in bits of a key of the normalized algorithm `alg`."
  [{:keys [length]}]
  (check-length length :operation-error)
  length)
