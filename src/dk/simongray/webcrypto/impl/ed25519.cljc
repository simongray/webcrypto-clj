(ns ^:no-doc dk.simongray.webcrypto.impl.ed25519
  "Ed25519, as WebCrypto has it in section 25, on both platforms. Each
  function returns its result on the JVM and a promise of it in
  ClojureScript.

  The JDK has Ed25519 since Java 15, so on Java 11 to 14 each function
  throws not-supported-error. The formats of a key come from its public key
  and private seed, so that each platform exports the same bytes. The JDK
  doesn't compute the public key of a seed, so the JVM generates a key pair
  from a source of randomness that gives the seed."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.async :as async]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.impl.errors :as errors]
            [dk.simongray.webcrypto.impl.jwk :as jwk]
            [dk.simongray.webcrypto.impl.keys :as keys]
            #?(:cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.security GeneralSecurityException KeyFactory KeyPair KeyPairGenerator
                    PrivateKey PublicKey SecureRandom Signature]
                   [java.security.spec NamedParameterSpec X509EncodedKeySpec])))

(def algorithm
  "The algorithm of Ed25519, which has no parameters."
  {:name :ed25519})

#?(:clj
   (def available?
     "Whether the JDK has Ed25519, as Java 15 and later do."
     (delay (try
              (KeyFactory/getInstance "Ed25519")
              true
              (catch GeneralSecurityException _
                false)))))

(defn check-available
  "Throw not-supported-error unless the platform has Ed25519."
  []
  #?(:clj (errors/check @available? :not-supported-error "Ed25519 needs Java 15 or later")))

;; The points of small order (RFC 7748, section 7), including y = p and
;; y = p + 1, which encode 0 and 1 again
(def small-order
  "The encodings in hex of the points of small order on Ed25519, with the
  sign bit of x cleared."
  #{"0000000000000000000000000000000000000000000000000000000000000000"
    "0100000000000000000000000000000000000000000000000000000000000000"
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"})

(defn small-order?
  "Whether the 32 bytes `b` encode a point of small order, with either sign
  bit."
  [b]
  (contains? small-order (bytes/hex (bytes/concat (bytes/slice b 0 31)
                                                  (bytes/of [(bit-and (bytes/at b 31) 0x7f)])))))

;; RFC 8410, sections 4 and 7
(defn spki-of
  "The SubjectPublicKeyInfo of the public key `x`, 32 bytes."
  [x]
  (der/write-spki (der/oids :ed25519) nil x))

(defn pkcs8-of
  "The PrivateKeyInfo of the private seed `d`, 32 bytes."
  [d]
  (der/write-private-key-info (der/oids :ed25519) nil (der/octet-string d)))

#?(:clj
   (defn- seeded
     "A source of randomness that gives the bytes of the `seed`."
     [seed]
     (proxy [SecureRandom] []
       (nextBytes [^bytes b]
         (System/arraycopy seed 0 b 0 (alength b))))))

#?(:clj
   (defn- key-pair-of
     "The KeyPair of the private seed `d`."
     [d]
     (.generateKeyPair (doto (KeyPairGenerator/getInstance "Ed25519")
                         (.initialize (NamedParameterSpec. "Ed25519") ^SecureRandom (seeded d))))))

#?(:clj
   (defn- public-key-of
     "The PublicKey of the public key `x`, 32 bytes."
     [x]
     (.generatePublic (KeyFactory/getInstance "Ed25519") (X509EncodedKeySpec. (spki-of x)))))

(defn- check-spki
  "The public key in the SubjectPublicKeyInfo `data`, or a throw of
  data-error when it isn't one of Ed25519."
  [data]
  (let [{:keys [algorithm parameters public-key]} (der/spki data)]
    (errors/check (= (der/oids :ed25519) algorithm) :data-error "The key isn't an Ed25519 key")
    (errors/check (nil? parameters) :data-error "An Ed25519 key has no parameters")
    (errors/check (= 32 (bytes/length public-key)) :data-error "An Ed25519 key has 32 bytes")
    public-key))

(defn- check-pkcs8
  "The private seed in the PrivateKeyInfo `data`, or a throw of data-error
  when it isn't one of Ed25519."
  [data]
  (let [{:keys [algorithm parameters private-key]} (der/private-key-info data)
        seed (der/read-octet-string (der/parse private-key))]
    (errors/check (= (der/oids :ed25519) algorithm) :data-error "The key isn't an Ed25519 key")
    (errors/check (nil? parameters) :data-error "An Ed25519 key has no parameters")
    (errors/check (= 32 (bytes/length seed)) :data-error "An Ed25519 seed has 32 bytes")
    seed))

(defn- check-jwk
  "Throw unless the `jwk` is a JWK of Ed25519 that can have the `usages` and
  be `extractable`, and return its bytes as a map of :x and :d (when it's
  private)."
  [jwk extractable usages]
  (let [private? (contains? jwk :d)]
    (keys/check-allowed :ed25519 (if private? #{:sign} #{:verify}) usages)
    (errors/check (= "OKP" (:kty jwk)) :data-error "The JWK of an Ed25519 key has the kty OKP")
    (errors/check (= "Ed25519" (:crv jwk)) :data-error "The JWK's crv isn't Ed25519")
    (errors/check (contains? #{nil "Ed25519" "EdDSA"} (:alg jwk)) :data-error
                  "The JWK's alg isn't Ed25519 or EdDSA")
    (jwk/check-uses jwk "sig" extractable usages)
    (cond-> {:x (jwk/member-bytes jwk :x 32)}
      private? (assoc :d (jwk/member-bytes jwk :d 32)))))

#?(:clj
   (defn- raw-public
     "The 32 bytes of the PublicKey `public`."
     [^PublicKey public]
     (let [b (.getEncoded public)]
       (bytes/slice b (- (bytes/length b) 32)))))

#?(:clj
   (defn- seed-of
     "The private seed of the PrivateKey `private`."
     [^PrivateKey private]
     (-> (.getEncoded private) der/private-key-info :private-key der/parse der/read-octet-string)))

#?(:clj
   (defn- private-key-pair
     "The KeyPair of the private seed `d`, or a throw of data-error when the
     public key `x` isn't its own. A JDK whose generator doesn't take the
     seed from the source of randomness, e.g. one of a hardware module,
     throws not-supported-error."
     [d x]
     (let [^KeyPair kp (key-pair-of d)]
       (errors/check (bytes/same? d (seed-of (.getPrivate kp))) :not-supported-error
                     "The JDK's Ed25519 makes no key pair of a given seed")
       (errors/check (or (nil? x) (bytes/same? x (raw-public (.getPublic kp)))) :data-error
                     "The public key isn't the private key's")
       kp)))

;; WebCrypto, section 25.3.4
(defn import-key
  "The key of the key `data` in the `format`, which is `extractable` and
  has the `usages`."
  [format data extractable usages]
  (check-available)
  (let [parsed (case format
                 :raw   (do (keys/check-allowed :ed25519 #{:verify} usages)
                            (errors/check (= 32 (bytes/length data)) :data-error
                                          "An Ed25519 key has 32 bytes")
                            {:x data})
                 :spki  (do (keys/check-allowed :ed25519 #{:verify} usages)
                            {:x (check-spki data)})
                 :pkcs8 (do (keys/check-allowed :ed25519 #{:sign} usages)
                            {:d (check-pkcs8 data)})
                 :jwk   (check-jwk data extractable usages)
                 (throw (errors/error :not-supported-error
                                      (str "The library can't import an Ed25519 key as " format))))]
    ;; WebCrypto, section 25.3.2, has verify return false for such a key,
    ;; but in JavaScript a public key that isn't extractable can't be read
    ;; then, and no platform checks it itself
    (errors/check (not (some-> (:x parsed) small-order?)) :data-error
                  "An Ed25519 key of small order verifies no signature")
    #?(:clj  (try
               (if (:d parsed)
                 (keys/make :private algorithm extractable usages
                            (private-key-pair (:d parsed) (:x parsed)))
                 (keys/make :public algorithm extractable usages
                            (public-key-of (:x parsed))))
               (catch GeneralSecurityException e
                 (throw (errors/error :data-error "The key isn't an Ed25519 key" e))))
       :cljs (subtle/import-key format data algorithm extractable usages))))

;; WebCrypto, section 25.3.3
(defn generate-key
  "A new key pair of Ed25519 whose private key is `extractable` and has its
  share of the `usages`."
  [extractable usages]
  (check-available)
  (keys/check-usages :ed25519 usages)
  #?(:clj  (keys/key-pair algorithm extractable usages
                          (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519")))
     :cljs (subtle/generate-key algorithm extractable usages)))

(defn- key-bytes
  "The public key of the `key` and its private seed, when it's private, as
  a map of :x and :d."
  [key]
  #?(:clj  (cond-> {:x (raw-public (keys/public-key key))}
             (= :private (:type (keys/info key)))
             (assoc :d (seed-of (keys/private-key key))))
     :cljs (async/then (subtle/export-jwk key)
                       (fn [{:keys [x d]}]
                         (cond-> {:x (bytes/from-base64url x)}
                           d (assoc :d (bytes/from-base64url d)))))))

;; WebCrypto, section 25.3.5
(defn export-key
  "The `key` in the `format`: bytes for :raw, :spki and :pkcs8, and a map
  for :jwk."
  [format key]
  (let [{:keys [usages extractable?]} (keys/info key)]
    (errors/check (contains? #{:raw :spki :pkcs8 :jwk} format) :not-supported-error
                  (str "The library can't export an Ed25519 key as " format))
    (case format
      (:raw :spki) (keys/check-type key :public)
      :pkcs8       (keys/check-type key :private)
      nil)
    (async/then (key-bytes key)
                (fn [{:keys [x d]}]
                  (case format
                    :raw   x
                    :spki  (spki-of x)
                    :pkcs8 (pkcs8-of d)
                    :jwk   (cond-> (jwk/with-uses {:kty "OKP" :crv "Ed25519" :alg "Ed25519"
                                                   :x (bytes/base64url x)}
                                                  usages extractable?)
                             d (assoc :d (bytes/base64url d))))))))

;; WebCrypto, section 25.3.1
(defn sign
  "The Ed25519 signature of the bytes `data` with the private `key`."
  [key data]
  (keys/check-type key :private)
  #?(:clj  (let [s (Signature/getInstance "Ed25519")]
             (.initSign s ^PrivateKey (keys/private-key key))
             (.update s ^bytes data)
             (.sign s))
     :cljs (subtle/sign algorithm key data)))

;; WebCrypto, section 25.3.2, whose check of R neither the JDK, Node nor
;; Chrome makes
(defn verify
  "Whether `signature` is the Ed25519 signature of the bytes `data` with
  the public `key`."
  [key signature data]
  (keys/check-type key :public)
  (and (= 64 (bytes/length signature))
       (not (small-order? (bytes/slice signature 0 32)))
       #?(:clj  (try
                  (let [s (Signature/getInstance "Ed25519")]
                    (.initVerify s ^PublicKey (keys/public-key key))
                    (.update s ^bytes data)
                    (.verify s ^bytes signature))
                  (catch GeneralSecurityException _
                    false))
          :cljs (subtle/verify algorithm key signature data))))
