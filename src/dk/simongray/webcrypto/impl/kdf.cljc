(ns ^:no-doc dk.simongray.webcrypto.impl.kdf
  "HKDF and PBKDF2, as WebCrypto has them in sections 33 and 34, on both
  platforms. Each function returns its result on the JVM and a promise of
  it in ClojureScript.

  The JDK's PBKDF2 takes a password as characters and encodes them as UTF-8,
  and it refuses an empty salt. So the library refuses a password that isn't
  UTF-8 and an empty salt on every platform."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?(:clj  [dk.simongray.webcrypto.hash :as hash]
               :cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.nio ByteBuffer]
                   [java.nio.charset CharacterCodingException StandardCharsets]
                   [javax.crypto SecretKeyFactory]
                   [javax.crypto.spec PBEKeySpec])))

(defn check-length
  "Throw operation-error unless `length`, the bits to derive, is a whole
  number of bytes."
  [length]
  (errors/check (and (some? length) (zero? (mod length 8))) :operation-error
                "A key derivation needs a length in bits of whole bytes"))

;; WebCrypto, sections 33.4.2 and 34.4.2
(defn import-key
  "The key of the bytes `data` in the `format` for the KDF named `name`,
  which is `extractable` and has the `usages`."
  [name format data extractable usages]
  (errors/check (= :raw format) :not-supported-error
                (str "The library can only import a key of " name " as raw bytes"))
  (keys/check-usages name usages)
  (errors/check (false? extractable) :syntax-error
                (str "A key of " name " isn't extractable"))
  #?(:clj  (keys/secret-key {:name name} false usages data)
     :cljs (subtle/import-raw data {:name name} false usages)))

;; WebCrypto, section 33.4.1
(defn check-hkdf
  "Throw unless HKDF by the normalized algorithm `alg` can derive `length`
  bits."
  [{:keys [hash]} length]
  (check-length length)
  (errors/check (<= length (* 255 (algorithms/hash-size hash))) :operation-error
                (str "HKDF by " hash " derives "
                     (* 255 (algorithms/hash-size hash)) " bits at most")))

(defn hkdf-bits
  "The `length` bits that HKDF derives from the `key` by the normalized
  algorithm `alg`."
  [alg key length]
  (check-hkdf alg length)
  #?(:clj  (let [{:keys [hash salt info]} alg]
             (hash/hkdf hash (keys/handle key) salt info (quot length 8)))
     :cljs (subtle/derive-bits alg key length)))

(defn import-hkdf-key
  "The HKDF key of the input keying material `data` in the `format`, which
  is `extractable` and has the `usages`."
  [format data extractable usages]
  (import-key :hkdf format data extractable usages))

#?(:clj
   (defn- pbkdf2-name
     "The name of the JCA's PBKDF2 by the `hash`, e.g. PBKDF2WithHmacSHA256."
     [hash]
     (str "PBKDF2WithHmac" (.replace ^String (algorithms/names hash) "-" ""))))

;; WebCrypto, section 34.4.1
(defn check-pbkdf2
  "Throw unless PBKDF2 by the normalized algorithm `alg` can derive
  `length` bits."
  [{:keys [salt iterations]} length]
  (check-length length)
  (errors/check (pos? iterations) :operation-error
                "PBKDF2 needs an iteration at least")
  (errors/check (pos? (bytes/length salt)) :not-supported-error
                "The library refuses PBKDF2 with an empty salt, since the JDK does")
  ;; the JDK takes both as an int
  (errors/check (and (<= iterations 0x7FFFFFFF) (<= length 0x7FFFFFFF)) :not-supported-error
                "The library takes PBKDF2 with up to 2,147,483,647 iterations and bits, as the JDK does"))

#?(:clj
   (defn- pbkdf2
     "The `length` bits that the JDK's PBKDF2 derives from the password `key`
     by the normalized algorithm `alg`. The JDK takes the password as
     characters, which it encodes as UTF-8 again, and refuses a length of 0."
     [{:keys [hash salt iterations]} key length]
     (if (zero? length)
       (byte-array 0)
       (let [password (.toCharArray ^String (bytes/decode (keys/handle key)))
             spec     (PBEKeySpec. password ^bytes salt (int iterations) (int length))]
         (try
           (.getEncoded (.generateSecret (SecretKeyFactory/getInstance (pbkdf2-name hash))
                                         spec))
           (finally
             (.clearPassword spec)))))))

(defn pbkdf2-bits
  "The `length` bits that PBKDF2 derives from the password `key` by the
  normalized algorithm `alg`."
  [alg key length]
  (check-pbkdf2 alg length)
  #?(:clj  (pbkdf2 alg key length)
     :cljs (subtle/derive-bits alg key length)))

(defn- utf-8?
  "Whether the bytes `b` are UTF-8."
  [b]
  #?(:clj  (try
             (.decode (.newDecoder StandardCharsets/UTF_8) (ByteBuffer/wrap b))
             true
             (catch CharacterCodingException _
               false))
     :cljs (try
             (.decode (js/TextDecoder. "utf-8" #js {:fatal true}) b)
             true
             (catch :default _
               false))))

(defn import-pbkdf2-key
  "The PBKDF2 key of the password `data` in the `format`, which is
  `extractable` and has the `usages`. A password that isn't UTF-8 throws
  not-supported-error."
  [format data extractable usages]
  (errors/check (or (not= :raw format) (utf-8? data)) :not-supported-error
                "The library only takes PBKDF2 passwords of UTF-8, as the JDK does")
  (import-key :pbkdf2 format data extractable usages))
