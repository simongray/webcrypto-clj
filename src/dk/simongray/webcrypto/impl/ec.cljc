(ns ^:no-doc dk.simongray.webcrypto.impl.ec
  "ECDSA and ECDH, as WebCrypto has them in sections 23 and 24, on the
  curves P-256, P-384 and P-521, on both platforms. Each function returns
  its result on the JVM and a promise of it in ClojureScript.

  The formats of a key come from its coordinates and private value, so
  that each platform exports the same bytes. Its PKCS#8 holds the public
  key but no parameters in its ECPrivateKey, as Chrome and Node write it.

  The JDK neither checks that a point is on its curve nor computes the
  public key of a private key, so the JVM does both here: the first by the
  curve's equation, and the second by ECDH with the curve's generator,
  which gives the point's x, and a signature, which tells which y it has."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.jwk :as jwk]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?(:clj  [dk.simongray.webcrypto.impl.random :as random]
               :cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.math BigInteger]
                   [java.security AlgorithmParameters GeneralSecurityException KeyFactory
                    KeyPair KeyPairGenerator PrivateKey PublicKey Signature]
                   [java.security.interfaces ECPrivateKey ECPublicKey]
                   [java.security.spec ECFieldFp ECGenParameterSpec ECParameterSpec ECPoint
                    ECPrivateKeySpec ECPublicKeySpec]
                   [javax.crypto KeyAgreement])))

;; RFC 5480, section 2.1.1.1, JWA, sections 3.4 and 6.2.1.1, and SEC 2,
;; section 2.4, for the orders
(def curves
  "The object identifier, the name in the JCA, the size in bytes of a
  coordinate, the JWA algorithm of ECDSA and the order in hex of that size
  of each curve."
  {:p-256 {:oid   (der/oids :secp256r1)
           :jca   "secp256r1"
           :size  32
           :jwa   "ES256"
           :order "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"}
   :p-384 {:oid   (der/oids :secp384r1)
           :jca   "secp384r1"
           :size  48
           :jwa   "ES384"
           :order (str "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                       "581a0db248b0a77aecec196accc52973")}
   :p-521 {:oid   (der/oids :secp521r1)
           :jca   "secp521r1"
           :size  66
           :jwa   "ES512"
           :order (str "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                       "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138"
                       "6409")}})

(def curve-names
  "The curve of each object identifier."
  (zipmap (map :oid (vals curves)) (keys curves)))

(defn check-curve
  "Throw not-supported-error unless `curve` is a curve of the library."
  [curve]
  (errors/check (contains? curves curve) :not-supported-error
                (str "The library has no curve " (pr-str curve))))

(defn- size
  "The size in bytes of a coordinate on the `curve`."
  [curve]
  (:size (curves curve)))

(defn- check-key-curve
  "Throw data-error unless the `found` curve, an object identifier, is the
  `curve`."
  [curve found]
  (errors/check (= curve (curve-names found)) :data-error
                (str "The key isn't a key of " (algorithms/names curve))))

#?(:clj
   (def parameters
     "The ECParameterSpec of each curve."
     (memoize (fn [curve]
                (let [ap (AlgorithmParameters/getInstance "EC")]
                  (.init ap (ECGenParameterSpec. (:jca (curves curve))))
                  (.getParameterSpec ap ECParameterSpec))))))

#?(:clj
   (defn- unsigned-bytes
     "The non-negative integer `n` as `size` bytes, the most significant
     first."
     [^BigInteger n size]
     (let [b (.toByteArray n)
           k (alength b)]
       (if (>= k size)
         (bytes/slice b (- k size))
         (bytes/concat (byte-array (- size k)) b)))))

#?(:clj
   (defn- curve-rhs
     "The right-hand side of the equation of the `curve` for `x`, x³ + ax +
     b modulo p, and p, as a pair."
     [curve ^BigInteger x]
     (let [ec (.getCurve ^ECParameterSpec (parameters curve))
           p  (.getP ^ECFieldFp (.getField ec))]
       [(-> (.multiply x (.multiply x x)) (.add (.multiply (.getA ec) x)) (.add (.getB ec)) (.mod p))
        p])))

;; SEC 1, section 3.2.2.1, the check that a point is on its curve
#?(:clj
   (defn- on-curve?
     "Whether the point of `x` and `y` is on the `curve`."
     [curve ^BigInteger x ^BigInteger y]
     (let [[rhs ^BigInteger p] (curve-rhs curve x)]
       (and (<= 0 (.signum x)) (neg? (.compareTo x p))
            (<= 0 (.signum y)) (neg? (.compareTo y p))
            (= rhs (.mod (.multiply y y) p))))))

;; SEC 1, section 2.3.4, where p is 3 modulo 4 on each curve here
#?(:clj
   (defn- y-of
     "The y of the point on the `curve` with `x` whose lowest bit is
     `odd?`, or nil when no point has `x`."
     [curve ^BigInteger x odd?]
     (let [[^BigInteger rhs ^BigInteger p] (curve-rhs curve x)
           y (.modPow rhs (.shiftRight (.add p BigInteger/ONE) 2) p)]
       (when (= rhs (.mod (.multiply y y) p))
         (if (= odd? (.testBit y 0)) y (.mod (.subtract p y) p))))))

#?(:clj
   (defn- public-key-of
     "The PublicKey of the point of `x` and `y` on the `curve`, or a throw of
     data-error when it isn't on the curve."
     [curve ^BigInteger x ^BigInteger y]
     (errors/check (on-curve? curve x y) :data-error
                   (str "The point isn't on " (algorithms/names curve)))
     (.generatePublic (KeyFactory/getInstance "EC")
                      (ECPublicKeySpec. (ECPoint. x y) (parameters curve)))))

;; SEC 1, section 2.3.4
#?(:clj
   (defn- decode-point
     "The PublicKey of the point in the bytes `b`, compressed or not, on the
     `curve`, or a throw of data-error."
     [curve b]
     (let [n      (size curve)
           big    #(BigInteger. 1 ^bytes %)
           prefix (when (pos? (bytes/length b)) (bit-and (aget ^bytes b 0) 0xff))]
       (cond
         (and (= 4 prefix) (= (inc (* 2 n)) (bytes/length b)))
         (public-key-of curve (big (bytes/slice b 1 (inc n))) (big (bytes/slice b (inc n))))

         (and (#{2 3} prefix) (= (inc n) (bytes/length b)))
         (let [x (big (bytes/slice b 1))
               y (y-of curve x (= 3 prefix))]
           (errors/check y :data-error "The compressed point isn't on its curve")
           (public-key-of curve x y))

         :else
         (throw (errors/error :data-error "The bytes aren't a point of the curve"))))))

#?(:clj
   (defn- point-bytes
     "The uncompressed point of the PublicKey `public`, as bytes."
     [curve ^ECPublicKey public]
     (let [w (.getW public)]
       (bytes/concat (bytes/of [4])
                     (unsigned-bytes (.getAffineX w) (size curve))
                     (unsigned-bytes (.getAffineY w) (size curve))))))

#?(:clj
   (defn- private-key-of
     "The PrivateKey of the private value in the bytes `d` on the `curve`,
     or a throw of data-error when it's out of range."
     [curve d]
     (let [s (BigInteger. 1 ^bytes d)
           n (.getOrder ^ECParameterSpec (parameters curve))]
       (errors/check (and (pos? (.signum s)) (neg? (.compareTo s n))) :data-error
                     "The private value isn't in the curve's range")
       (.generatePrivate (KeyFactory/getInstance "EC")
                         (ECPrivateKeySpec. s (parameters curve))))))

#?(:clj
   (defn- pair?
     "Whether the PublicKey `public` belongs to the PrivateKey `private`, by
     a signature of the one that the other verifies."
     [^PrivateKey private ^PublicKey public]
     (let [message (random/random-bytes 16)
           signer  (doto (Signature/getInstance "SHA256withECDSA") (.initSign private))
           _       (.update signer ^bytes message)
           verifier (doto (Signature/getInstance "SHA256withECDSA") (.initVerify public))]
       (.update verifier ^bytes message)
       (.verify verifier (.sign signer)))))

#?(:clj
   (defn- public-of-private
     "The PublicKey of the PrivateKey `private` on the `curve`: x by ECDH
     with the generator, and the y of the two that a signature verifies
     with."
     [curve ^PrivateKey private]
     (let [g      (.getGenerator ^ECParameterSpec (parameters curve))
           x      (BigInteger. 1 ^bytes (-> (doto (KeyAgreement/getInstance "ECDH")
                                              (.init private)
                                              (.doPhase (public-key-of curve (.getAffineX g) (.getAffineY g)) true))
                                            .generateSecret))
           public #(public-key-of curve x (y-of curve x %))]
       (if (pair? private (public false)) (public false) (public true)))))

#?(:clj
   (defn- key-pair-of
     "The KeyPair of the private value `d` on the `curve` and the point
     `point`, or of the point it computes when that's nil. It throws
     data-error when the point isn't the private value's."
     [curve d point]
     (let [private (private-key-of curve d)]
       (if point
         (let [public (decode-point curve point)]
           (errors/check (pair? private public) :data-error
                         "The public key isn't the private key's")
           (KeyPair. public private))
         ;; a point that public-of-private computes is the private key's
         (KeyPair. (public-of-private curve private) private)))))

(def jca-hashes
  "The name of each hash in the names of the JCA's signatures."
  {:sha-1 "SHA1" :sha-256 "SHA256" :sha-384 "SHA384" :sha-512 "SHA512"})

;; WebCrypto, section 23.7.1
(defn sign
  "The ECDSA signature of the bytes `data` with the private `key` by the
  normalized algorithm `alg`, as r and s side by side."
  [alg key data]
  (keys/check-type key :private)
  #?(:clj  (let [signature (Signature/getInstance (str (jca-hashes (:hash alg)) "withECDSAinP1363Format"))]
             (.initSign signature ^PrivateKey (keys/private-key key))
             (.update signature ^bytes data)
             (.sign signature))
     :cljs (subtle/sign alg key data)))

;; SEC 1, section 4.1.4
(defn- in-range?
  "Whether the integer of the bytes `b`, of the size of a coordinate on the
  `curve`, is from 1 to the curve's order minus 1. Hex of the same length
  sorts as its numbers do."
  [curve b]
  (and (not-every? #(zero? (bytes/at b %)) (range (bytes/length b)))
       (neg? (compare (bytes/hex b) (:order (curves curve))))))

;; WebCrypto, section 23.7.2, where a signature of another size is false,
;; though the JDK splits it in two all the same. The library checks r and
;; s too, which JDK 15 to 18 didn't (CVE-2022-21449).
(defn verify
  "Whether `signature`, r and s side by side, is the ECDSA signature of the
  bytes `data` with the public `key` by the normalized algorithm `alg`."
  [alg key signature data]
  (keys/check-type key :public)
  (and (let [curve (:named-curve (:algorithm (keys/info key)))
             n     (size curve)]
         (and (= (* 2 n) (bytes/length signature))
              (in-range? curve (bytes/slice signature 0 n))
              (in-range? curve (bytes/slice signature n))))
       #?(:clj  (let [verifier (Signature/getInstance (str (jca-hashes (:hash alg)) "withECDSAinP1363Format"))]
                  (.initVerify verifier ^PublicKey (keys/public-key key))
                  (.update verifier ^bytes data)
                  (try
                    (.verify verifier ^bytes signature)
                    (catch GeneralSecurityException _
                      false)))
          :cljs (subtle/verify alg key signature data))))

;; WebCrypto, sections 23.7.3 and 24.4.1
(defn generate-key
  "A new key pair of the normalized algorithm `alg`, of ECDSA or ECDH, whose
  private key is `extractable` and has its share of the `usages`."
  [{:keys [name named-curve] :as alg} extractable usages]
  (keys/check-usages name usages)
  (check-curve named-curve)
  #?(:clj  (keys/key-pair {:name name :named-curve named-curve} extractable usages
                          (.generateKeyPair (doto (KeyPairGenerator/getInstance "EC")
                                              (.initialize (ECGenParameterSpec. (:jca (curves named-curve)))))))
     :cljs (subtle/generate-key alg extractable usages)))

(defn- check-spki
  "Throw data-error unless the bytes `data` are the SubjectPublicKeyInfo of
  an EC key on the `curve`, and return its point."
  [curve data]
  (let [{:keys [algorithm parameters public-key]} (der/spki data)]
    (errors/check (= (der/oids :ec-public-key) algorithm) :data-error
                  "The key isn't an EC key")
    (errors/check parameters :data-error "The key has no curve")
    (check-key-curve curve (der/read-oid parameters))
    public-key))

(defn- check-pkcs8
  "Throw data-error unless the bytes `data` are the PrivateKeyInfo of an EC
  key on the `curve`, and return its ECPrivateKey as a map."
  [curve data]
  (let [{:keys [algorithm parameters private-key]} (der/private-key-info data)
        _          (errors/check (= (der/oids :ec-public-key) algorithm) :data-error
                                 "The key isn't an EC key")
        _          (errors/check parameters :data-error "The key has no curve")
        found      (der/read-oid parameters)
        ec-private (der/ec-private-key private-key)]
    (check-key-curve curve found)
    (errors/check (contains? #{nil found} (:parameters ec-private)) :data-error
                  "The key names two curves")
    (errors/check (= (size curve) (bytes/length (:d ec-private))) :data-error
                  "The private value has another size than its curve's")
    ec-private))

(defn- usages-of
  "The usages that a key of the algorithm named `name` can have when it's
  `private?`."
  [name private?]
  (if private?
    (remove (algorithms/public-usages name) (algorithms/usages name))
    (algorithms/public-usages name)))

(defn- check-jwk
  "Throw unless the `jwk` is a JWK of a key of the normalized algorithm
  `alg` that can have the `usages` and be `extractable`, and return its
  bytes as a map of :x, :y and :d (when it's private)."
  [{:keys [name named-curve]} jwk extractable usages]
  (let [private? (contains? jwk :d)
        n        (size named-curve)]
    (keys/check-allowed name (set (usages-of name private?)) usages)
    (errors/check (= "EC" (:kty jwk)) :data-error "The JWK of an EC key has the kty EC")
    (jwk/check-uses jwk (if (= :ecdsa name) "sig" "enc") extractable usages)
    (errors/check (= (algorithms/names named-curve) (:crv jwk)) :data-error
                  (str "The JWK's crv isn't " (algorithms/names named-curve)))
    (when (= :ecdsa name)
      (errors/check (contains? #{nil (:jwa (curves named-curve))} (:alg jwk)) :data-error
                    (str "The JWK's alg isn't " (:jwa (curves named-curve)))))
    (cond-> {:x (jwk/member-bytes jwk :x n)
             :y (jwk/member-bytes jwk :y n)}
      private? (assoc :d (jwk/member-bytes jwk :d n)))))

;; WebCrypto, sections 23.7.4 and 24.4.3
(defn import-key
  "The key of the key `data` in the `format` for the normalized algorithm
  `alg`, of ECDSA or ECDH, which is `extractable` and has the `usages`."
  [format data {:keys [name named-curve] :as alg} extractable usages]
  (check-curve named-curve)
  (let [private? (= :pkcs8 format)
        _        (when-not (= :jwk format)
                   (errors/check (contains? #{:raw :spki :pkcs8} format) :not-supported-error
                                 (str "The library can't import an EC key as " format))
                   (keys/check-allowed name (set (usages-of name private?)) usages))
        ;; the checks run on both platforms, but only the JVM needs the parts
        #_{:clj-kondo/ignore [:unused-binding]}
        parsed   (case format
                   :raw   {:point data}
                   :spki  {:point (check-spki named-curve data)}
                   :pkcs8 (let [{:keys [d public-key]} (check-pkcs8 named-curve data)]
                            {:d d :point public-key})
                   :jwk   (let [{:keys [x y d]} (check-jwk alg data extractable usages)]
                            {:d d :point (bytes/concat (bytes/of [4]) x y)}))]
    #?(:clj  (let [algorithm {:name name :named-curve named-curve}]
               (if (:d parsed)
                 (keys/make :private algorithm extractable usages
                            (key-pair-of named-curve (:d parsed) (:point parsed)))
                 (keys/make :public algorithm extractable usages
                            (decode-point named-curve (:point parsed)))))
       :cljs (subtle/import-key format data alg extractable usages))))

(defn- coordinates
  "The coordinates of the `key` and its private value, when it's private,
  as a map of :x, :y and :d as bytes."
  [key]
  #?(:clj  (let [curve (:named-curve (:algorithm (keys/info key)))
                 point (point-bytes curve (keys/public-key key))
                 n     (size curve)]
             (cond-> {:x (bytes/slice point 1 (inc n))
                      :y (bytes/slice point (inc n))}
               (= :private (:type (keys/info key)))
               (assoc :d (unsigned-bytes (.getS ^ECPrivateKey (keys/private-key key)) n))))
     :cljs (async/then (subtle/export-jwk key)
                       (fn [{:keys [x y d]}]
                         (cond-> {:x (bytes/from-base64url x)
                                  :y (bytes/from-base64url y)}
                           d (assoc :d (bytes/from-base64url d)))))))

;; WebCrypto, sections 23.7.5 and 24.4.4
(defn export-key
  "The `key` in the `format`: bytes for :raw, :spki and :pkcs8, and a map
  for :jwk."
  [format key]
  (let [{:keys [algorithm usages extractable?]} (keys/info key)
        curve (:named-curve algorithm)
        oid   (der/oid (:oid (curves curve)))]
    (errors/check (contains? #{:raw :spki :pkcs8 :jwk} format) :not-supported-error
                  (str "The library can't export an EC key as " format))
    (when (#{:raw :spki} format)
      (keys/check-type key :public))
    (when (= :pkcs8 format)
      (keys/check-type key :private))
    (async/then (coordinates key)
                (fn [{:keys [x y d]}]
                  (let [point (bytes/concat (bytes/of [4]) x y)]
                    (case format
                      :raw   point
                      :spki  (der/write-spki (der/oids :ec-public-key) oid point)
                      :pkcs8 (der/write-private-key-info (der/oids :ec-public-key) oid
                                                         (der/write-ec-private-key d point))
                      :jwk   (cond-> (jwk/with-uses {:kty "EC"
                                                     :crv (algorithms/names curve)
                                                     :x   (bytes/base64url x)
                                                     :y   (bytes/base64url y)}
                                                    usages extractable?)
                               d (assoc :d (bytes/base64url d)))))))))

(defn check-ecdh
  "Throw unless ECDH by the normalized algorithm `alg` can derive `length`
  bits for the private `key`."
  [{:keys [public] :as alg} key length]
  (errors/check (keys/crypto-key? public) :type-error "The public member of ECDH is a key")
  (let [public-info (keys/info public)
        private-info (keys/info key)
        curve        (get-in private-info [:algorithm :named-curve])]
    (errors/check (= :public (:type public-info)) :invalid-access-error
                  "The public member of ECDH isn't a public key")
    (errors/check (= :ecdh (get-in public-info [:algorithm :name])) :invalid-access-error
                  "The public member of ECDH isn't a key of ECDH")
    (errors/check (or (nil? length) (<= length (* 8 (size (get-in public-info [:algorithm :named-curve])))))
                  :operation-error "ECDH derives as many bits as its curve's coordinates have at most")
    (errors/check (= :private (:type private-info)) :invalid-access-error
                  "The key of ECDH isn't a private key")
    (errors/check (= curve (get-in public-info [:algorithm :named-curve])) :invalid-access-error
                  "The keys of ECDH are on two curves")))

#?(:clj
   (defn- first-bits
     "The first `length` bits of the bytes `b`, with the rest of the last byte
     set to zero."
     [b length]
     (let [out  (bytes/slice b 0 (quot (+ length 7) 8))
           kept (mod length 8)]
       (when (pos? kept)
         (let [i (dec (alength ^bytes out))]
           (aset ^bytes out i (unchecked-byte (bit-and (aget ^bytes out i)
                                                       (bit-shift-left 0xff (- 8 kept)))))))
       out)))

;; WebCrypto, section 24.4.2
(defn derive-bits
  "The `length` bits that ECDH derives from the private `key` and the
  public key of the normalized algorithm `alg`, or all of them for a nil
  length."
  [alg key length]
  (check-ecdh alg key length)
  #?(:clj  (let [secret (-> (doto (KeyAgreement/getInstance "ECDH")
                              (.init ^PrivateKey (keys/private-key key))
                              (.doPhase ^PublicKey (keys/public-key (:public alg)) true))
                            .generateSecret)]
             (if length (first-bits secret length) secret))
     :cljs (subtle/derive-bits alg key length)))
