(ns ^:no-doc dk.simongray.webcrypto.impl.keys
  "Keys on both platforms. In ClojureScript a key is WebCrypto's own
  CryptoKey, and on the JVM a type with the same internal slots (WebCrypto,
  section 13.3). On the JVM the handle of a secret key is its bytes, that
  of a public key a PublicKey, and that of a private key a KeyPair, since
  its JWK and PKCS#8 hold the public key too."
  (:require [clojure.string :as str]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.errors :as errors]
            #?(:cljs [dk.simongray.webcrypto.impl.subtle :as subtle]))
  #?(:clj (:import [java.io Writer]
                   [java.security KeyPair PublicKey])))

#?(:clj
   (deftype CryptoKey [type extractable algorithm usages handle]
     Object
     (toString [_]
       (str "#<CryptoKey " (pr-str {:type type :algorithm algorithm}) ">"))))

#?(:clj
   (defmethod print-method CryptoKey [k ^Writer w]
     (.write w (str k))))

(defn crypto-key?
  "Whether `x` is a key."
  [x]
  #?(:clj  (instance? CryptoKey x)
     :cljs (and (exists? js/CryptoKey) (instance? js/CryptoKey x))))

#?(:cljs
   (defn- algorithm-data
     "The KeyAlgorithm `algorithm` of a CryptoKey as a map, with its name,
     curve and hash as keywords."
     [^js algorithm]
     (let [lower #(keyword (str/lower-case %))]
       (cond-> {:name (lower (.-name algorithm))}
         (.-length algorithm)         (assoc :length (.-length algorithm))
         (.-hash algorithm)           (assoc :hash (lower (.. algorithm -hash -name)))
         (.-namedCurve algorithm)     (assoc :named-curve (lower (.-namedCurve algorithm)))
         (.-modulusLength algorithm)  (assoc :modulus-length (.-modulusLength algorithm))
         (.-publicExponent algorithm) (assoc :public-exponent (.-publicExponent algorithm))))))

#?(:cljs
   (def usage-keywords
     "The keyword of each usage of a key, by its name in WebCrypto."
     (zipmap (vals algorithms/usage-names) (keys algorithms/usage-names))))

;; WebCrypto, section 13.4
(defn info
  "The type, extractability, algorithm and usages of the `key`, as a map
  of :type, :extractable?, :algorithm and :usages."
  [key]
  #?(:clj  (let [^CryptoKey key key
                 algorithm      (.-algorithm key)]
             {:type         (.-type key)
              :extractable? (.-extractable key)
              ;; a copy of the bytes of an RSA key's exponent, which its
              ;; key pair shares
              :algorithm    (cond-> algorithm
                              (:public-exponent algorithm)
                              (update :public-exponent #(aclone ^bytes %)))
              :usages       (.-usages key)})
     :cljs (let [^js key key]
             {:type         (keyword (.-type key))
              :extractable? (.-extractable key)
              :algorithm    (algorithm-data (.-algorithm key))
              :usages       (into #{} (map usage-keywords) (.-usages key))})))

#?(:clj
   (defn make
     "A key of the `type`, :secret, :public or :private, with the `algorithm`
     as a map, the `extractable` and `usages` of WebCrypto, and the
     `handle`."
     [type algorithm extractable usages handle]
     (CryptoKey. type (boolean extractable) algorithm (set usages) handle)))

#?(:clj
   (defn secret-key
     "A secret key of a copy of the bytes `b`, with the `algorithm` as a map
     and the `extractable` and `usages` of WebCrypto."
     [algorithm extractable usages b]
     (make :secret algorithm extractable usages (aclone ^bytes b))))

#?(:clj
   (defn handle
     "The handle of the `key`: bytes, a PublicKey or a KeyPair."
     [key]
     (.-handle ^CryptoKey key)))

#?(:clj
   (defn private-key
     "The PrivateKey of the private `key`."
     [key]
     (.getPrivate ^KeyPair (handle key))))

#?(:clj
   (defn public-key
     "The PublicKey of the public or private `key`."
     [key]
     (let [h (handle key)]
       (if (instance? PublicKey h) h (.getPublic ^KeyPair h)))))

#?(:clj
   (defn key-pair
     "The key pair of a public and a private key of the `algorithm`, as a
     map, from the KeyPair `kp`. The private key is `extractable` and has
     those of the `usages` that a private key has."
     [algorithm extractable usages ^KeyPair kp]
     (let [public-usages (algorithms/public-usages (:name algorithm))]
       {:public-key  (make :public algorithm true (filter public-usages usages)
                           (.getPublic kp))
        :private-key (make :private algorithm extractable (remove public-usages usages)
                           kp)})))

(defn raw
  "A copy of the bytes of the secret `key`, in ClojureScript as a promise."
  [key]
  #?(:clj  (aclone ^bytes (handle key))
     :cljs (subtle/export-raw key)))

;; WebCrypto, section 14.3: the checks of each method that takes a key
(defn check
  "Throw unless `key` is a key of the algorithm `alg` with the `usage`: a
  type-error for another value, and an invalid-access-error for another
  key."
  [key alg usage]
  (errors/check (crypto-key? key) :type-error "The key isn't a key")
  (let [{:keys [algorithm usages]} (info key)]
    (errors/check (= (:name alg) (:name algorithm)) :invalid-access-error
                  (str "The key is a key of " (:name algorithm) ", not of "
                       (:name alg)))
    (errors/check (contains? usages usage) :invalid-access-error
                  (str "The key's usages don't include " usage))))

(defn check-type
  "Throw invalid-access-error unless the `key` has the `type`, :public or
  :private."
  [key type]
  (errors/check (= type (:type (info key))) :invalid-access-error
                (str "The key isn't a " (name type) " key")))

;; WebIDL's conversion of a sequence of KeyUsage
(defn usages
  "The `usages` of a key as a set, or a throw of type-error when they
  aren't a collection of the usages of WebCrypto."
  [usages]
  (errors/check (and (coll? usages)
                     (every? #(contains? algorithms/usage-names %) usages))
                :type-error
                (str "The usages are a collection of "
                     (str/join ", " (keys algorithms/usage-names))))
  (set usages))

(defn check-allowed
  "Throw syntax-error when the `usages` include one that isn't among the
  `allowed` usages of a key of the algorithm named `name`."
  [name allowed usages]
  (errors/check (every? allowed usages) :syntax-error
                (str "This key of " name " can only have the usages "
                     (if (seq allowed) (str/join ", " (sort allowed)) "none"))))

(defn check-usages
  "Throw syntax-error when the `usages` include one that a key of the
  algorithm named `name` can't have."
  [name usages]
  (check-allowed name (algorithms/usages name) usages))

;; WebCrypto, sections 14.3.6, 14.3.7 and 14.3.9
(defn check-present-usages
  "Throw syntax-error when the `key`, or the private key of a key pair, is
  secret or private and has no usages."
  [key]
  (let [key              (or (:private-key key) key)
        {:keys [type usages]} (info key)]
    (errors/check (or (= :public type) (seq usages)) :syntax-error
                  (str "A " (name type) " key needs a usage"))))
