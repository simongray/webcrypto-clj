(ns ^:no-doc dk.simongray.webcrypto.impl.algorithms
  "The algorithms that the library supports, their parameters and the
  usages of their keys, and the normalization of an algorithm (WebCrypto,
  section 18.4).

  An algorithm is a keyword, its WebCrypto name in lower case, or a map of
  its :name and its parameters, named as the members of its dictionary in
  kebab case."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.errors :as errors]))

(def names
  "The WebCrypto name of each algorithm and named curve."
  {:sha-1             "SHA-1"
   :sha-256           "SHA-256"
   :sha-384           "SHA-384"
   :sha-512           "SHA-512"
   :hmac              "HMAC"
   :aes-gcm           "AES-GCM"
   :hkdf              "HKDF"
   :pbkdf2            "PBKDF2"
   :ecdsa             "ECDSA"
   :ecdh              "ECDH"
   :rsassa-pkcs1-v1_5 "RSASSA-PKCS1-v1_5"
   :rsa-pss           "RSA-PSS"
   :ed25519           "Ed25519"
   :p-256             "P-256"
   :p-384             "P-384"
   :p-521             "P-521"})

;; FIPS 180-4, section 1
(def hashes
  "The size of the digest and of the block of each hash, in bytes."
  {:sha-1   {:size 20 :block-size 64}
   :sha-256 {:size 32 :block-size 64}
   :sha-384 {:size 48 :block-size 128}
   :sha-512 {:size 64 :block-size 128}})

(def aes-gcm-params
  "The members of AesGcmParams (WebCrypto, section 29.3)."
  {:iv              [:bytes :required]
   :additional-data [:bytes]
   :tag-length      [:octet]})

(def hmac-params
  "The members of HmacImportParams and HmacKeyGenParams (WebCrypto, sections
  31.3 and 31.5)."
  {:hash   [:hash :required]
   :length [:unsigned-long]})

(def ec-params
  "The members of EcKeyGenParams and EcKeyImportParams (WebCrypto, sections
  23.4 and 23.6)."
  {:named-curve [:named-curve :required]})

(def rsa-key-gen-params
  "The members of RsaHashedKeyGenParams (WebCrypto, section 20.4)."
  {:modulus-length  [:unsigned-long :required]
   :public-exponent [:big-integer :required]
   :hash            [:hash :required]})

(def rsa-import-params
  "The members of RsaHashedImportParams (WebCrypto, section 20.8)."
  {:hash [:hash :required]})

;; WebCrypto, section 18.2.2, and the registration of each algorithm
(def dictionaries
  "The members of the parameters of each algorithm, by the operation and the
  algorithm. Each member has its type and whether it's required. An
  algorithm that isn't here doesn't support the operation."
  {:digest         {:sha-1 {} :sha-256 {} :sha-384 {} :sha-512 {}}
   :sign           {:hmac              {}
                    :ecdsa             {:hash [:hash :required]}
                    :rsassa-pkcs1-v1_5 {}
                    :rsa-pss           {:salt-length [:unsigned-long :required]}
                    :ed25519           {}}
   :verify         {:hmac              {}
                    :ecdsa             {:hash [:hash :required]}
                    :rsassa-pkcs1-v1_5 {}
                    :rsa-pss           {:salt-length [:unsigned-long :required]}
                    :ed25519           {}}
   :encrypt        {:aes-gcm aes-gcm-params}
   :decrypt        {:aes-gcm aes-gcm-params}
   :generate-key   {:hmac              hmac-params
                    :aes-gcm           {:length [:unsigned-short :required]}
                    :ecdsa             ec-params
                    :ecdh              ec-params
                    :rsassa-pkcs1-v1_5 rsa-key-gen-params
                    :rsa-pss           rsa-key-gen-params
                    :ed25519           {}}
   :import-key     {:hmac              hmac-params
                    :aes-gcm           {}
                    :hkdf              {}
                    :pbkdf2            {}
                    :ecdsa             ec-params
                    :ecdh              ec-params
                    :rsassa-pkcs1-v1_5 rsa-import-params
                    :rsa-pss           rsa-import-params
                    :ed25519           {}}
   :derive-bits    {:hkdf   {:hash [:hash :required]
                             :salt [:bytes :required]
                             :info [:bytes :required]}
                    :pbkdf2 {:salt       [:bytes :required]
                             :iterations [:unsigned-long :required]
                             :hash       [:hash :required]}
                    :ecdh   {:public [:crypto-key :required]}}
   :get-key-length {:hmac    hmac-params
                    :aes-gcm {:length [:unsigned-short :required]}
                    :hkdf    {}
                    :pbkdf2  {}}})

(def exportable
  "The algorithms whose keys export (WebCrypto, section 14.3.10)."
  #{:hmac :aes-gcm :ecdsa :ecdh :rsassa-pkcs1-v1_5 :rsa-pss :ed25519})

;; WebCrypto, section 13.2, where KeyUsage lists them in this order
(def usage-names
  "The name of each usage of a key in WebCrypto and in JWK's key_ops, in the
  order of a key's normalized usages."
  (array-map :encrypt     "encrypt"
             :decrypt     "decrypt"
             :sign        "sign"
             :verify      "verify"
             :derive-key  "deriveKey"
             :derive-bits "deriveBits"
             :wrap-key    "wrapKey"
             :unwrap-key  "unwrapKey"))

(def usages
  "The usages that a key of each algorithm can have. A key pair splits
  them, e.g. sign for the private key and verify for the public one."
  {:hmac              #{:sign :verify}
   :aes-gcm           #{:encrypt :decrypt :wrap-key :unwrap-key}
   :hkdf              #{:derive-key :derive-bits}
   :pbkdf2            #{:derive-key :derive-bits}
   :ecdsa             #{:sign :verify}
   :ecdh              #{:derive-key :derive-bits}
   :rsassa-pkcs1-v1_5 #{:sign :verify}
   :rsa-pss           #{:sign :verify}
   :ed25519           #{:sign :verify}})

(def public-usages
  "The usages that a public key of each asymmetric algorithm can have, of
  those of its private key."
  {:ecdsa             #{:verify}
   :ecdh              #{}
   :rsassa-pkcs1-v1_5 #{:verify}
   :rsa-pss           #{:verify}
   :ed25519           #{:verify}})

;; WebIDL, section 3.2.4, which [EnforceRange] limits to these
(def integer-ranges
  "The smallest and the largest value of each type of integer."
  {:octet          [0 0xFF]
   :unsigned-short [0 0xFFFF]
   :unsigned-long  [0 0xFFFFFFFF]})

(declare normalize)

(defn- member
  "The value `v` of the member `k` of an algorithm, converted to its
  `type`, or a throw of type-error. A key passes as it is, and the
  algorithm checks it."
  [k type v]
  (case type
    :hash        (:name (normalize :digest v))
    :crypto-key  v
    :named-curve (do (errors/check (keyword? v) :type-error
                                   (str "The " k " of an algorithm is a keyword, e.g. :p-256"))
                     v)
    (:bytes :big-integer)
    (do (errors/check (bytes/bytes? v) :type-error
                      (str "The " k " of an algorithm is bytes"))
        v)
    (let [[lowest highest] (integer-ranges type)]
      (errors/check (and (integer? v) (<= lowest v highest)) :type-error
                    (str "The " k " of an algorithm is an integer from "
                         lowest " to " highest))
      v)))

;; WebCrypto, section 18.4.4
(defn normalize
  "The algorithm `alg` normalized for the operation `op`: a map of its :name
  and the members of its parameters, each of its type, and a hash as a
  keyword. It throws not-supported-error when the operation doesn't take the
  algorithm, and type-error for a member that's missing or of another type."
  [op alg]
  (let [alg  (if (keyword? alg) {:name alg} alg)
        name (:name alg)]
    (errors/check (keyword? name) :type-error
                  "An algorithm is a keyword, or a map with a keyword as its :name")
    (errors/check (get-in dictionaries [op name]) :not-supported-error
                  (str "The library has no " name " for " (clojure.core/name op)))
    (reduce-kv (fn [normalized k [type required]]
                 (let [v (get alg k)]
                   (cond
                     (some? v) (assoc normalized k (member k type v))
                     required  (throw (errors/error :type-error
                                                    (str name " needs " k)))
                     :else     normalized)))
               {:name name}
               (get-in dictionaries [op name]))))

(defn hash-size
  "The size of the digest of the `hash` in bits."
  [hash]
  (* 8 (:size (hashes hash))))

(defn check-hash
  "Throw not-supported-error unless `hash` is a hash of the library."
  [hash]
  (errors/check (contains? hashes hash) :not-supported-error
                (str "The library has no hash " (pr-str hash))))

(comment
  (normalize :encrypt {:name :aes-gcm :iv (bytes/of (range 12)) :extra 1})
  (normalize :derive-bits {:name :hkdf :hash {:name :sha-256}
                           :salt (bytes/of []) :info (bytes/of [])})
  (normalize :digest :sha-3)
  #_.)
