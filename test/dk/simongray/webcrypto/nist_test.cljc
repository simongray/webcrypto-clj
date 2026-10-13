(ns dk.simongray.webcrypto.nist-test
  "AES-GCM against NIST's test vectors of the CAVP (gcmtestvectors.zip),
  for keys of 128 and 256 bits, from the files that dev/fetch.sh puts in
  dev-resources/nist.

  The library refuses tags of 32 and 64 bits and IVs of 8 bits, so their
  vectors must be refused with not-supported-error, and one of each such
  section is enough to check that."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.test-support :as support :refer [all fails-with run then]]))

(defn- section-header
  "The parameters of the line `line` of a header of a section, e.g.
  [Taglen = 128], as a map entry, or nil."
  [line]
  (when-let [[_ k v] (re-matches #"\[(\w+) = (\d+)\]" line)]
    [(keyword k) (parse-long v)]))

(defn- field
  "The name and value of the line `line` of a vector, e.g. Key = 11754c…,
  as a map entry, or nil. A line FAIL is a failure of decryption."
  [line]
  (if (= "FAIL" line)
    [:FAIL true]
    (when-let [[_ k v] (re-matches #"(\w+) = ?(.*)" line)]
      [(keyword k) v])))

(defn vectors
  "The vectors of the response file `name`, each a map of its fields and
  the parameters of its section."
  [name]
  (when-let [text (support/text (str "nist/" name))]
    (->> (str/split text #"\r?\n\r?\n")
         (map str/split-lines)
         (reduce (fn [{:keys [section] :as acc} lines]
                   (let [lines   (map str/trim lines)
                         headers (keep section-header lines)]
                     (if (seq headers)
                       (assoc acc :section (into {} headers))
                       (let [fields (into {} (keep field) lines)]
                         (cond-> acc
                           (:Count fields) (update :vectors conj (merge section fields)))))))
                 {:section {} :vectors []})
         :vectors)))

(def short-tag?
  "Whether a tag of a number of bits is one that the library refuses."
  #{32 64})

(defn refused?
  "Whether the library refuses the vector `v`, for its tag or for its IV of
  fewer than 96 bits."
  [{:keys [Taglen IVlen]}]
  (or (short-tag? Taglen) (< IVlen 96)))

(defn- params
  "The AES-GCM parameters of the vector `v`."
  [{:keys [IV AAD Taglen]}]
  {:name :aes-gcm :iv (bytes/from-hex IV) :additional-data (bytes/from-hex AAD) :tag-length Taglen})

(defn- check-encryption
  "Check that the vector `v` of NIST encrypts as it should, with the key
  of its Key."
  [{:keys [Key PT CT Tag Count Keylen IVlen Taglen] :as v}]
  (let [why (str "encryption " Count " of " Keylen ", " IVlen ", " Taglen)]
    (then (webcrypto/import-key :raw (bytes/from-hex Key) :aes-gcm false [:encrypt])
          (fn [k]
            (if (refused? v)
              (fails-with :not-supported-error why #(webcrypto/encrypt (params v) k (bytes/from-hex PT)))
              (then (webcrypto/encrypt (params v) k (bytes/from-hex PT))
                    (fn [sealed] (is (= (str CT Tag) (bytes/hex sealed)) why))))))))

(defn- check-decryption
  "Check that the vector `v` of NIST decrypts as it should, or fails with
  operation-error when it's a FAIL."
  [{:keys [Key PT CT Tag Count Keylen IVlen Taglen FAIL] :as v}]
  (let [why  (str "decryption " Count " of " Keylen ", " IVlen ", " Taglen)
        data (bytes/from-hex (str CT Tag))]
    (then (webcrypto/import-key :raw (bytes/from-hex Key) :aes-gcm false [:decrypt])
          (fn [k]
            (cond
              (refused? v)        (fails-with :not-supported-error why #(webcrypto/decrypt (params v) k data))
              FAIL                (fails-with :operation-error why #(webcrypto/decrypt (params v) k data))
              :else               (then (webcrypto/decrypt (params v) k data)
                                        (fn [opened] (is (= PT (bytes/hex opened)) why))))))))

(defn- sampled
  "The `vectors` but for those that the library refuses, of which only the
  first of each section is left."
  [vectors]
  (remove #(and (refused? %) (not= "0" (:Count %))) vectors))

(deftest encryption
  (run #(all (map check-encryption (sampled (concat (vectors "gcmEncryptExtIV128.rsp")
                                                    (vectors "gcmEncryptExtIV256.rsp")))))))

(deftest decryption
  (run #(all (map check-decryption (sampled (concat (vectors "gcmDecrypt128.rsp")
                                                    (vectors "gcmDecrypt256.rsp")))))))
