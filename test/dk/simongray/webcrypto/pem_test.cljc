(ns dk.simongray.webcrypto.pem-test
  "PEM as RFC 7468 has it, and the keys of RFC 9421 under each label, which
  import as SPKI and PKCS#8 and export as the same bytes."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.asymmetric-test :as asymmetric-test]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.fixtures :as fixtures]
            [dk.simongray.webcrypto.impl.der :as der]
            [dk.simongray.webcrypto.pem :as pem]
            [dk.simongray.webcrypto.test-support :refer [all fails-with run then]]))

(defn blocks
  "The label and the DER in hex of each block of PEM in the text `s`."
  [s]
  (mapv (juxt :label (comp bytes/hex :der)) (pem/decode s)))

(deftest encode
  (let [der (bytes/of (range 100))
        s   (pem/encode "PUBLIC KEY" der)]
    (is (str/starts-with? s "-----BEGIN PUBLIC KEY-----\n"))
    (is (str/ends-with? s "\n-----END PUBLIC KEY-----\n"))
    (is (= [64 64 8] (map count (butlast (rest (str/split-lines s))))) "lines of 64 characters")
    (is (= [["PUBLIC KEY" (bytes/hex der)]] (blocks s)))))

(deftest decode
  (is (= [["CERTIFICATE" "010203"] ["PRIVATE KEY" "040506"]]
         (blocks (str "A comment\n"
                      "-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n"
                      "Another comment\n"
                      "-----BEGIN PRIVATE KEY-----\n  BA\n UG\n-----END PRIVATE KEY-----\n")))
      "text around the blocks, CRLF and whitespace")
  (is (= [] (blocks "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PRIVATE KEY-----\n"))
      "the END of another label")
  (is (= [] (blocks "-----BEGIN PUBLIC KEY-----\nAQI*\n-----END PUBLIC KEY-----\n"))
      "base64 that isn't valid")
  (is (= [] (blocks "No PEM")))
  ;; a regex with a backreference took half a minute for this
  (is (= [] (blocks (str/join (repeat 16000 "-----BEGIN A-----\n"))))
      "many BEGIN lines without an END, at once"))

(def rfc-9421-keys
  "The format that each key of RFC 9421 imports in, its algorithm and its
  usages."
  {:rsa-public       [:spki {:name :rsassa-pkcs1-v1_5 :hash :sha-256} [:verify]]
   :rsa-private      [:pkcs8 {:name :rsassa-pkcs1-v1_5 :hash :sha-256} [:sign]]
   :rsa-pss-public   [:spki {:name :rsa-pss :hash :sha-512} [:verify]]
   :rsa-pss-private  [:pkcs8 {:name :rsa-pss :hash :sha-512} [:sign]]
   :ecc-p256-public  [:spki {:name :ecdsa :named-curve :p-256} [:verify]]
   :ecc-p256-private [:pkcs8 {:name :ecdsa :named-curve :p-256} [:sign]]
   :ed25519-public   [:spki :ed25519 [:verify]]
   :ed25519-private  [:pkcs8 :ed25519 [:sign]]})

;; The library exports an EC key without the curve in its ECPrivateKey, and
;; SEC1 has it there
(deftest key-data
  (is (= (update-vals rfc-9421-keys first)
         (update-vals fixtures/rfc-9421 (comp :format pem/key-data))))
  (run #(all (for [[k [format algorithm usages]] rfc-9421-keys
                   :when (and (asymmetric-test/available? algorithm) (not= :ecc-p256-private k))
                   :let [{:keys [data]} (pem/key-data (fixtures/rfc-9421 k))]]
               (-> (webcrypto/import-key format data algorithm true usages)
                   (then (partial webcrypto/export-key format))
                   (then (fn [exported] (is (= (bytes/hex data) (bytes/hex exported)) (name k)))))))))

(deftest kinds
  (is (= {:rsa-public       {:kind :rsa}
          :rsa-private      {:kind :rsa}
          :rsa-pss-public   {:kind :rsa}
          :rsa-pss-private  {:kind :rsa}
          :ecc-p256-public  {:kind :ec :named-curve :p-256}
          :ecc-p256-private {:kind :ec :named-curve :p-256}
          :ed25519-public   {:kind :ed25519}
          :ed25519-private  {:kind :ed25519}}
         (update-vals fixtures/rfc-9421 #(select-keys (pem/key-data %) [:kind :named-curve]))))
  (is (= {:kind :ec :named-curve :p-384}
         (-> (der/write-spki (der/oids :ec-public-key) (der/oid (der/oids :secp384r1))
                             (bytes/of (cons 4 (range 96))))
             (->> (pem/encode "PUBLIC KEY"))
             pem/key-data
             (select-keys [:kind :named-curve]))))
  (is (nil? (:kind (pem/key-data (pem/encode "PUBLIC KEY" (der/write-spki "1.3.101.110" nil (bytes/of (range 32)))))))
      "an X25519 key, whose kind the library doesn't name"))

;; RFC 4055, section 1.2
(deftest rsa-pss-keys
  (let [oid-of #(:algorithm (der/private-key-info %))
        s      (:rsa-pss-private fixtures/rfc-9421)]
    (is (= (der/oids :rsassa-pss) (oid-of (:der (first (pem/decode s))))))
    (is (= (der/oids :rsa-encryption) (oid-of (:data (pem/key-data s))))
        "a key of RSASSA-PSS imports as a key of rsaEncryption")))

(deftest not-keys
  (let [{:keys [d public-key]} (der/ec-private-key
                                (:der (first (pem/decode (:ecc-p256-private fixtures/rfc-9421)))))]
    (is (nil? (pem/key-data (pem/encode "CERTIFICATE" (bytes/of [0x30 0])))))
    (run #(fails-with :data-error "an EC PRIVATE KEY without its curve"
                      (fn [] (pem/key-data (pem/encode "EC PRIVATE KEY" (der/write-ec-private-key d public-key)))))
         #(fails-with :data-error "a PUBLIC KEY that isn't DER"
                      (fn [] (pem/key-data (pem/encode "PUBLIC KEY" (bytes/of [1 2 3]))))))))
