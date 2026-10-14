(ns dk.simongray.webcrypto.pem
  "Keys in PEM (RFC 7468): the base64 of their DER between a BEGIN line and
  an END line with a label, e.g. PUBLIC KEY, as OpenSSL writes them.

  WebCrypto only imports SPKI and PKCS#8, so key-data turns the older
  PKCS#1 and SEC1 keys into those, without any cryptography."
  (:require [clojure.string :as str]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.impl.errors :as errors]))

;; RFC 7468, section 2
(defn encode
  "The PEM of the DER bytes `der` under the `label`, e.g. PUBLIC KEY, in
  lines of 64 characters.

      (encode \"PUBLIC KEY\" (webcrypto/export-key :spki public-key))"
  [label der]
  (str "-----BEGIN " label "-----\n"
       (str/join (map #(str (str/join %) "\n") (partition-all 64 (bytes/base64 der))))
       "-----END " label "-----\n"))

(defn- read-token
  "The `state` of a reading of PEM after the `token`, a match of a BEGIN or
  END line as its kind and label, or of other text. The state is a map of
  the finished :blocks, and of the :label and :lines of an open block."
  [{:keys [label lines] :as state} [text kind token-label]]
  (case kind
    "BEGIN" (assoc state :label token-label :lines [])
    "END"   (cond-> (dissoc state :label :lines)
              (= label token-label) (update :blocks conj {:label label :text (str/join lines)}))
    (cond-> state
      lines (update :lines conj text))))

;; RFC 7468, section 3, which allows whitespace between the lines. The
;; text is read in tokens, since a regex of a whole block with a
;; backreference to its label would take quadratic time on many BEGIN lines
(defn decode
  "The blocks of PEM in the text `s`, in order, as maps of their :label and
  their :der as bytes. Text around the blocks, e.g. a comment, doesn't count,
  and neither does a block whose base64 isn't valid."
  [s]
  (vec (for [{:keys [label text]} (->> (re-seq #"-----(BEGIN|END) ([^-\r\n]*)-----|[^-]+|-" (str s))
                                       (reduce read-token {:blocks []})
                                       :blocks)
             :let [der (bytes/from-base64 (str/replace text #"\s" ""))]
             :when der]
         {:label label :der der})))

(defn- rsa-encryption
  "The DER of the AlgorithmIdentifier of rsaEncryption."
  []
  (der/sequence-of (der/oid (der/oids :rsa-encryption)) (der/null)))

(def kinds
  "The kind of key of each object identifier of an algorithm of SPKI and
  PKCS#8 that key-data names."
  {(der/oids :rsa-encryption) :rsa
   (der/oids :rsassa-pss)     :rsa-pss
   (der/oids :ec-public-key)  :ec
   (der/oids :ed25519)        :ed25519})

(def curves
  "The named curve of each object identifier of an EC key's curve."
  {(der/oids :secp256r1) :p-256
   (der/oids :secp384r1) :p-384
   (der/oids :secp521r1) :p-521})

;; RFC 5480, section 2.1.1, and RFC 8410, section 3
(defn- with-kind
  "The `key-data` with the :kind of key that its SPKI or PKCS#8 holds, and
  the :named-curve of an EC key, when the library knows them."
  [{:keys [format data] :as key-data}]
  (let [{:keys [algorithm parameters]} (if (= :spki format)
                                         (der/spki data)
                                         (der/private-key-info data))
        kind                           (kinds algorithm)
        curve                          (when (and (= :ec kind) parameters)
                                         (curves (der/read-oid parameters)))]
    (cond-> key-data
      kind  (assoc :kind kind)
      curve (assoc :named-curve curve))))

;; RFC 4055, section 1.2: a key of RSASSA-PSS is an RSA key, which
;; WebCrypto imports under rsaEncryption alone
(defn- under-rsa-encryption
  "The `key-data` of a key of RSASSA-PSS with its SPKI or PKCS#8 under
  rsaEncryption, or else as it is."
  [{:keys [format data kind] :as key-data}]
  (if (= :rsa-pss kind)
    (assoc key-data :data (if (= :spki format)
                            (der/write-spki (der/oids :rsa-encryption) (der/null)
                                            (:public-key (der/spki data)))
                            (der/write-private-key-info (der/oids :rsa-encryption) (der/null)
                                                        (:private-key (der/private-key-info data)))))
    key-data))

;; RFC 8017, Appendix A.1, and RFC 5915, section 3
(defn- key-data-of
  "The key data of the PEM `block` as a map of :format and :data, or nil
  when the block isn't a key."
  [{:keys [label der]}]
  (case label
    "PUBLIC KEY"      {:format :spki :data der}
    "PRIVATE KEY"     {:format :pkcs8 :data der}
    "RSA PUBLIC KEY"  {:format :spki
                       :data   (der/sequence-of (rsa-encryption) (der/bit-string der))}
    "RSA PRIVATE KEY" {:format :pkcs8
                       :data   (der/sequence-of (der/small-integer 0) (rsa-encryption)
                                                (der/octet-string der))}
    "EC PRIVATE KEY"  (let [curve (:parameters (der/ec-private-key der))]
                        (errors/check curve :data-error "The EC private key names no curve")
                        {:format :pkcs8
                         :data   (der/write-private-key-info (der/oids :ec-public-key)
                                                             (der/oid curve) der)})
    nil))

(defn key-data
  "The first key in the PEM text `s` as the :format and :data that
  import-key takes, or nil when it holds no key. The labels are these:

  - PUBLIC KEY and PRIVATE KEY, SPKI and PKCS#8 as they are, but for keys
    of RSASSA-PSS, whose algorithm becomes rsaEncryption as WebCrypto needs
  - RSA PUBLIC KEY and RSA PRIVATE KEY of PKCS#1, which become SPKI and
    PKCS#8
  - EC PRIVATE KEY of SEC1, which becomes PKCS#8

  The map also has the :kind of key, :rsa, :rsa-pss, :ec or :ed25519, and
  the :named-curve of an EC key, e.g. :p-256, when the library knows them.
  They tell which algorithm to import a key for, since import-key needs
  one. A key of RSASSA-PSS (RFC 4055) is :rsa-pss, for RSA-PSS alone,
  although its data is under rsaEncryption. A key that isn't valid DER
  throws data-error.

      (let [{:keys [format data]} (key-data (slurp \"key.pem\"))]
        (webcrypto/import-key format data {:name :ecdsa :named-curve :p-256}
                              false [:sign]))"
  [s]
  (some-> (some key-data-of (decode s)) with-kind under-rsa-encryption))
