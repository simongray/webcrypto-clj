(ns ^:no-doc dk.simongray.webcrypto.impl.jwk
  "JSON Web Keys of secret keys, which WebCrypto imports and exports for
  HMAC and AES (WebCrypto, sections 29.4.4, 29.4.5, 31.6.4 and 31.6.5).

  A JWK is a map of its JSON members as keywords, e.g. :kty and :key_ops,
  with their values as JSON has them."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.algorithms :as algorithms]
            [dk.simongray.webcrypto.impl.errors :as errors]))

;; JWA, section 6.4
(defn secret-bytes
  "The bytes of the secret key in the JWK `jwk`, or a throw of data-error
  when it isn't a JWK of a secret key."
  [jwk]
  (errors/check (= "oct" (:kty jwk)) :data-error
                "The JWK of a secret key has the kty oct")
  (let [k (:k jwk)]
    (or (and (string? k) (bytes/from-base64url k))
        (throw (errors/error :data-error
                             "The JWK of a secret key has its key in base64url as k")))))

;; JWA, sections 6.2 and 6.3, and RFC 8037, section 2
(defn member-bytes
  "The bytes of the member `k` of the JWK `jwk`, in base64url there, or a
  throw of data-error when it's missing or isn't base64url, or hasn't
  `size` bytes when that's given."
  ([jwk k]
   (member-bytes jwk k nil))
  ([jwk k size]
   (let [b (some-> (get jwk k) bytes/from-base64url)]
     (errors/check (and b (or (nil? size) (= size (bytes/length b)))) :data-error
                   (str "The JWK's " (name k) " isn't base64url"
                        (when size (str " of " size " bytes"))))
     b)))

;; RFC 7517, section 4.3
(defn- valid-key-ops?
  "Whether the key_ops of a JWK are `ops`: strings, none of them twice."
  [ops]
  (and (sequential? ops)
       (every? string? ops)
       (apply distinct? nil ops)))

(defn check-uses
  "Throw data-error when the JWK `jwk` doesn't allow the `usages` of a key,
  which is `extractable`. The JWK's use, when there's one, is the
  `use` (enc or sig) of the key's algorithm."
  [jwk use extractable usages]
  (errors/check (or (empty? usages) (nil? (:use jwk)) (= use (:use jwk)))
                :data-error (str "The JWK's use isn't " use))
  (when-some [ops (:key_ops jwk)]
    (errors/check (and (valid-key-ops? ops)
                       (every? (set ops) (map algorithms/usage-names usages)))
                  :data-error
                  "The JWK's key_ops don't include every usage of the key"))
  (errors/check (not (and (false? (:ext jwk)) extractable)) :data-error
                "The JWK isn't extractable, so the key can't be"))

(defn with-uses
  "The JWK `jwk` with the key_ops of the `usages`, in the spec's order, and
  the ext of `extractable`."
  [jwk usages extractable]
  (assoc jwk
         :key_ops (->> (keys algorithms/usage-names)
                       (filter (set usages))
                       (mapv algorithms/usage-names))
         :ext     (boolean extractable)))

(defn secret
  "The JWK of the bytes `b` of a secret key of the JWA algorithm `alg`,
  with the `usages` and `extractable` of the key."
  [b alg usages extractable]
  (with-uses {:kty "oct" :k (bytes/base64url b) :alg alg} usages extractable))
