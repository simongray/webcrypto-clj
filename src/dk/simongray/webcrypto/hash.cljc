(ns dk.simongray.webcrypto.hash
  "Hashes, HMACs and HKDF, synchronous on every platform.

  A hash is :sha-1, :sha-256, :sha-384 or :sha-512 (FIPS 180-4). They come
  from the JCA on the JVM and from the Closure Library in JavaScript, since
  WebCrypto only returns promises. For the same results as promises, which
  WebCrypto computes faster on large data, use digest, sign and derive-bits
  of the root namespace.

  An error is an ex-info whose :type is one of the keywords of the root
  namespace: not-supported-error for another hash, type-error for an
  argument that isn't bytes, and operation-error for an HKDF longer than it
  can be."
  (:require #?(:clj [clojure.string :as str])
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.errors :as errors]
            #?@(:cljs [[goog.crypt.Hmac]
                       [goog.crypt.Sha1]
                       [goog.crypt.Sha256]
                       [goog.crypt.Sha384]
                       [goog.crypt.Sha512]]))
  #?(:clj (:import [java.security MessageDigest]
                   [javax.crypto Mac]
                   [javax.crypto.spec SecretKeySpec])))

#?(:cljs
   (defn ^:no-doc hasher
     "A hasher of the Closure Library for the `hash`."
     [hash]
     (case hash
       :sha-1   (goog.crypt.Sha1.)
       :sha-256 (goog.crypt.Sha256.)
       :sha-384 (goog.crypt.Sha384.)
       :sha-512 (goog.crypt.Sha512.))))

;; FIPS 180-4, section 6
(defn digest
  "The digest of the bytes `data` by the `hash`, as bytes."
  [hash data]
  (algorithms/check-hash hash)
  (errors/check-bytes data "data")
  #?(:clj  (.digest (MessageDigest/getInstance ^String (algorithms/names hash))
                    ^bytes data)
     :cljs (let [h (hasher hash)]
             (.update h data)
             (js/Uint8Array.from (.digest h)))))

#?(:clj
   (defn- mac-name
     "The name of the JCA's Mac of HMAC by the `hash`, e.g. HmacSHA256."
     [hash]
     (str "Hmac" (str/replace (algorithms/names hash) "-" ""))))

;; RFC 2104, section 2
(defn hmac
  "The HMAC of the bytes `data` under the bytes `key` by the `hash`, as
  bytes. The key can be empty, as RFC 2104 allows."
  [hash key data]
  (algorithms/check-hash hash)
  (errors/check-bytes key "key")
  (errors/check-bytes data "data")
  #?(:clj  (let [algorithm (mac-name hash)
                 ;; the JCA refuses an empty key, but HMAC pads a key with
                 ;; zeros to a block, so a zero byte is the same key
                 key       (if (zero? (bytes/length key)) (byte-array 1) key)
                 mac       (Mac/getInstance algorithm)]
             (.init mac (SecretKeySpec. ^bytes key algorithm))
             (.doFinal mac ^bytes data))
     :cljs (js/Uint8Array.from (.getHmac (goog.crypt.Hmac. (hasher hash) key)
                                         data))))

;; RFC 5869, section 2.2
(defn hkdf-extract
  "The pseudorandom key that HKDF extracts from the input keying material
  `ikm` with the `salt` by the `hash`, as bytes. A nil salt is a hash's
  length of zeros, as is an empty one."
  [hash salt ikm]
  (hmac hash (or salt (bytes/of [])) ikm))

(defn- expansion-block
  "The block of HKDF's expansion that follows the block `previous`, the
  `i`th one, from the pseudorandom key `prk` and the `info` by the `hash`."
  [hash prk info previous i]
  (hmac hash prk (bytes/concat previous info (bytes/of [i]))))

;; RFC 5869, section 2.3
(defn hkdf-expand
  "The `length` bytes of output keying material that HKDF expands from the
  pseudorandom key `prk` and the `info` by the `hash`. A nil info is
  empty. The length is at most 255 times the size of the hash's digest."
  [hash prk info length]
  (algorithms/check-hash hash)
  (let [size (quot (algorithms/hash-size hash) 8)]
    (errors/check (and (nat-int? length) (<= length (* 255 size)))
                  :operation-error
                  (str "HKDF by " (pr-str hash) " gives from 0 to "
                       (* 255 size) " bytes"))
    (let [blocks (reductions (partial expansion-block hash prk (or info (bytes/of [])))
                             (bytes/of [])
                             (range 1 (inc (quot (+ length (dec size)) size))))]
      (bytes/slice (apply bytes/concat (rest blocks)) 0 length))))

;; RFC 5869, section 2
(defn hkdf
  "The `length` bytes of output keying material that HKDF derives from the
  input keying material `ikm`, the `salt` and the `info` by the `hash`. A
  nil salt or info is empty.

      (hkdf :sha-256 ikm salt (bytes/encode \"context\") 32)"
  [hash ikm salt info length]
  (hkdf-expand hash (hkdf-extract hash salt ikm) info length))

(comment
  (bytes/hex (digest :sha-256 (bytes/encode "abc")))
  ;; => "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  (bytes/hex (hmac :sha-256 (bytes/encode "Jefe")
                   (bytes/encode "what do ya want for nothing?")))
  ;; => "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  (bytes/hex (hkdf :sha-256 (bytes/of (repeat 22 0x0b))
                   (bytes/of (range 13)) (bytes/of (range 0xf0 0xfa)) 42))
  #_.)
