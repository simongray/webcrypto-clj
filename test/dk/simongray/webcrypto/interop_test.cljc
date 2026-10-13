(ns dk.simongray.webcrypto.interop-test
  "Each platform opens what the other seals: ciphertexts that the library
  sealed on the JVM, that WebCrypto sealed in Node, and an envelope that
  like-minded's own code sealed before it took this library. And the
  synchronous hashes give what WebCrypto gives, for random inputs."
  (:require #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])
            [clojure.test :refer [deftest is]]
            [clojure.test.check.generators :as gen]
            [dk.simongray.webcrypto :as webcrypto]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]
            [dk.simongray.webcrypto.test-support :refer [all run then]]))

(def sealed
  "Ciphertexts of AES-256-GCM with their key, IV, additional data and
  plaintext, in hex."
  [{:key       "00fb5bbeee34326d34aef22aa85b76ea3a6f61f753a77bcee5b3a0c43714119b"
    :iv        "7e305033217800789bbd6f9c"
    :aad       "77656263727970746f2d636c6a"
    :plaintext "Sealed on the JVM, opened everywhere"
    :sealed    (str "0e4671924552755870fb7aabdc9c4294314c6794cd6f70f15deffa9595d8165b"
                    "c1ea323f30ba49fa166cfb36ddf063b1ddc6f0aa")}
   {:key       "1aedee8a566e6dbc1bb0381f875ff624841e05a1809793170e3099074f55741b"
    :iv        "9b30c20c4ba045b68e27d286"
    :aad       "77656263727970746f2d636c6a"
    :plaintext "Sealed in Node, opened everywhere"
    :sealed    (str "047d88a7667b07b06cc0d345aba5cf18c92c362cfa66bea3bf233e8eea64e505"
                    "f0eabe797e5242f9aeff0555b0346fcf84")}])

(deftest sealed-elsewhere
  (run #(all (for [{:keys [key iv aad plaintext] :as c} sealed
                   :let [params {:name :aes-gcm :iv (bytes/from-hex iv) :additional-data (bytes/from-hex aad)}]]
               (then (webcrypto/import-key :raw (bytes/from-hex key) :aes-gcm false [:encrypt :decrypt])
                     (fn [k]
                       (then (all [(webcrypto/decrypt params k (bytes/from-hex (:sealed c)))
                                   (webcrypto/encrypt params k (bytes/encode plaintext))])
                             (fn [[opened again]]
                               (is (= plaintext (bytes/decode opened)))
                               (is (= (:sealed c) (bytes/hex again)) "and seals it the same")))))))))

(def envelope
  "A document that like-minded 0.2.0 sealed on the JVM with the passphrase
  correct horse battery staple, before it took this library."
  (str "{:encrypted 1, :cipher \"AES-256-GCM\", :kdf \"PBKDF2-HMAC-SHA256\", "
       ":iterations 1000, :salt \"md99j/nW43LqOB+mDe+tCQ==\", :iv \"Kwo+1vl0XW2fU5JN\", "
       ":data \"78kYZE5UHavt8IlxQldsbICQYlZliXBZY4E4RmKP6RXtH0QPzW/P5gMrpjnCwHwifYE=\"}"))

(defn opened
  "A promise of the text in the envelope `s` of like-minded, opened with
  the `passphrase` as like-minded would open it with this library."
  [s passphrase]
  (let [{:keys [iterations salt iv data]} (edn/read-string s)]
    (-> (webcrypto/import-key :raw (bytes/encode passphrase) :pbkdf2 false [:derive-key])
        (then (fn [password]
                (webcrypto/derive-key {:name       :pbkdf2
                                       :hash       :sha-256
                                       :salt       (bytes/from-base64 salt)
                                       :iterations iterations}
                                      password
                                      {:name :aes-gcm :length 256}
                                      false
                                      [:decrypt])))
        (then (fn [k]
                (webcrypto/decrypt {:name :aes-gcm :iv (bytes/from-base64 iv)} k
                                   (bytes/from-base64 data))))
        (then bytes/decode))))

(deftest like-minded
  (run #(then (opened envelope "correct horse battery staple")
              (fn [text] (is (= "{:notes [\"Sealed by like-minded\"]}" text))))))

(def samples
  "Random inputs of a hash: the hash, a key and data."
  (gen/sample (gen/tuple (gen/elements [:sha-1 :sha-256 :sha-384 :sha-512])
                         (gen/fmap bytes/of (gen/vector (gen/choose 0 255) 1 200))
                         (gen/fmap bytes/of (gen/vector (gen/choose 0 255) 0 300)))
              50))

;; in ClojureScript, the Closure Library against WebCrypto
(deftest hashes-against-webcrypto
  (run #(all (for [[h _ data] samples]
               (then (webcrypto/digest h data)
                     (fn [d] (is (= (bytes/hex (hash/digest h data)) (bytes/hex d)))))))
       #(all (for [[h k data] samples]
               (then (webcrypto/import-key :raw k {:name :hmac :hash h} false [:sign])
                     (fn [key]
                       (then (webcrypto/sign :hmac key data)
                             (fn [mac] (is (= (bytes/hex (hash/hmac h k data)) (bytes/hex mac)))))))))
       #(all (for [[h k data] samples
                   :let [length (bytes/length data)]]
               (then (webcrypto/import-key :raw k :hkdf false [:derive-bits])
                     (fn [key]
                       (then (webcrypto/derive-bits {:name :hkdf :hash h :salt data :info k} key (* 8 length))
                             (fn [bits]
                               (is (= (bytes/hex (hash/hkdf h k data k length)) (bytes/hex bits)))))))))))
