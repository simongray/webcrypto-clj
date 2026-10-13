(ns dk.simongray.webcrypto.bytes-test
  "Bytes and their encodings, the same on both platforms: the test vectors
  of RFC 4648, the strictness of the decoders, UTF-8, and round trips of
  random bytes."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [dk.simongray.webcrypto.bytes :as bytes]))

(defn numbers
  "The bytes `b` as a vector of numbers from 0 to 255."
  [b]
  (mapv #(bit-and % 0xff) #?(:clj (seq b) :cljs (array-seq b))))

;; RFC 4648, section 10
(def rfc-4648
  "The test vectors of RFC 4648: text, its base64 and its hex."
  [[""       ""         ""]
   ["f"      "Zg=="     "66"]
   ["fo"     "Zm8="     "666F"]
   ["foo"    "Zm9v"     "666F6F"]
   ["foob"   "Zm9vYg==" "666F6F62"]
   ["fooba"  "Zm9vYmE=" "666F6F6261"]
   ["foobar" "Zm9vYmFy" "666F6F626172"]])

(deftest the-vectors-of-rfc-4648
  (doseq [[s b64 b16] rfc-4648
          :let [b       (bytes/encode s)
                b64-url (re-find #"[^=]*" b64)]]
    (testing (pr-str s)
      (is (= b64 (bytes/base64 b)))
      (is (= s (bytes/decode (bytes/from-base64 b64))))
      (is (= b64-url (bytes/base64url b)) "without padding")
      (is (= b64 (bytes/base64url b {:padding? true})) "with padding")
      (is (= s (bytes/decode (bytes/from-base64url b64-url))))
      (is (= s (bytes/decode (bytes/from-base64url b64))))
      (is (= (str/lower-case b16) (bytes/hex b)))
      (is (= s (bytes/decode (bytes/from-hex b16)))))))

(deftest the-alphabets
  (let [b (bytes/of [0 1 2 250 251 252 253 254 255])]
    (is (= "AAEC+vv8/f7/" (bytes/base64 b)))
    (is (= "AAEC-vv8_f7_" (bytes/base64url b)))
    (is (= (numbers b) (numbers (bytes/from-base64url "AAEC-vv8_f7_"))))
    (is (nil? (bytes/from-base64 "AAEC-vv8_f7_")) "base64 takes no URL alphabet")
    (is (nil? (bytes/from-base64url "AAEC+vv8/f7/")) "and base64url no plain one")))

;; RFC 4648, sections 3.2, 3.3 and 3.5
(deftest strict-decoding
  (testing "base64 needs its padding, and padding only at the end"
    (doseq [s ["Zg" "Zg=" "Zg===" "Z===" "Zg==Zg==" "=" "===="]]
      (is (nil? (bytes/from-base64 s)) (pr-str s))))
  (testing "base64url takes padding, but only padding that fits"
    (is (= [102] (numbers (bytes/from-base64url "Zg"))))
    (is (= [102] (numbers (bytes/from-base64url "Zg=="))))
    (doseq [s ["Zg=" "Zg===" "Zm8==" "Z"]]
      (is (nil? (bytes/from-base64url s)) (pr-str s))))
  (testing "pad bits that aren't zero"
    (doseq [s ["Zh==" "Zm9=" "Zm9vYh=="]]
      (is (nil? (bytes/from-base64 s)) (pr-str s)))
    (doseq [s ["Zh" "Zm9" "Zm9vYh"]]
      (is (nil? (bytes/from-base64url s)) (pr-str s))))
  (testing "characters outside the alphabet, whitespace included"
    (doseq [s ["Zm9v\n" " Zm9v" "Zm 9v" "Zm9v!" "Zm9vYmFy\r\n"]]
      (is (nil? (bytes/from-base64 s)) (pr-str s))
      (is (nil? (bytes/from-base64url s)) (pr-str s))))
  (testing "values that aren't text"
    (doseq [x [nil 42 (bytes/of [1])]]
      (is (nil? (bytes/from-base64 x)))
      (is (nil? (bytes/from-base64url x)))
      (is (nil? (bytes/from-hex x)))))
  (testing "hex with an odd number of digits, or other characters"
    (doseq [s ["abc" "0g" "0x00" "00 11"]]
      (is (nil? (bytes/from-hex s)) (pr-str s))))
  ;; a regex of the pads took a minute for this
  (testing "a long run of pads that doesn't end the text, at once"
    (let [s (str (str/join (repeat 160000 "=")) "A")]
      (is (nil? (bytes/from-base64 s)))
      (is (nil? (bytes/from-base64url s))))))

(deftest utf-8
  (is (= "Blåbær" (bytes/decode (bytes/encode "Blåbær"))))
  (is (= "426cc3a562c3a672" (bytes/hex (bytes/encode "Blåbær"))))
  (is (= "f09f9880" (bytes/hex (bytes/encode "😀"))) "a surrogate pair is one code point")
  (testing "a lone surrogate becomes U+FFFD, as with TextEncoder"
    (is (= "61efbfbd62" (bytes/hex (bytes/encode "a\uD800b"))))
    (is (= "efbfbd" (bytes/hex (bytes/encode "\uDC00")))))
  (testing "a byte order mark stays"
    (is (= "﻿A" (bytes/decode (bytes/of [0xEF 0xBB 0xBF 0x41])))))
  (testing "bytes that aren't UTF-8 become U+FFFD"
    (is (= "a�b" (bytes/decode (bytes/of [0x61 0xC0 0x62]))))
    (is (= "�" (bytes/decode (bytes/of [0xE2 0x82]))))))

(deftest bytes-on-both-platforms
  (is (bytes/bytes? (bytes/of [1 2 3])))
  (is (not (bytes/bytes? [1 2 3])))
  (is (= [0 128 255] (numbers (bytes/of [0 128 255]))))
  (is (= 3 (bytes/length (bytes/of [1 2 3]))))
  (is (= [1 2 3 4] (numbers (bytes/concat (bytes/of [1]) (bytes/of []) (bytes/of [2 3 4])))))
  (is (= [] (numbers (bytes/concat))))
  (is (= [2 3] (numbers (bytes/slice (bytes/of [1 2 3 4]) 1 3))))
  (is (= [3 4] (numbers (bytes/slice (bytes/of [1 2 3 4]) 2))))
  (testing "a slice outside the bytes throws, as subvec does"
    (doseq [[start end] [[-1 2] [3 2] [0 5]]]
      (is (thrown? #?(:clj Exception :cljs :default)
                   (bytes/slice (bytes/of [1 2 3 4]) start end)))))
  (testing "a slice is a copy"
    (let [b (bytes/of [1 2 3])
          c (bytes/slice b 0)]
      (aset c 0 #?(:clj (byte 9) :cljs 9))
      (is (= [1 2 3] (numbers b))))))

(deftest comparisons-of-secrets
  (is (bytes/same? (bytes/of [1 2 3]) (bytes/of [1 2 3])))
  (is (not (bytes/same? (bytes/of [1 2 3]) (bytes/of [1 2 4]))))
  (is (not (bytes/same? (bytes/of [1 2]) (bytes/of [1 2 3]))))
  (is (bytes/same? (bytes/of []) (bytes/of [])))
  (is (not (bytes/same? nil (bytes/of []))))
  (is (not (bytes/same? "abc" "abc")) "text isn't bytes")
  (is (bytes/same-text? "s3cr3t" "s3cr3t"))
  (is (not (bytes/same-text? "s3cr3t" "s3cr3T")))
  (is (not (bytes/same-text? "s3cr3t" nil)))
  (is (not (bytes/same-text? nil nil)))
  (is (not (bytes/same-text? "\uD800" "\uDFFF")) "lone surrogates aren't the same U+FFFD"))

(def random-bytes
  "Bytes of any length up to a few hundred."
  (gen/fmap bytes/of (gen/vector (gen/choose 0 255) 0 300)))

(defspec round-trips 200
  (prop/for-all [b random-bytes]
    (let [n (numbers b)]
      (and (= n (numbers (bytes/from-base64 (bytes/base64 b))))
           (= n (numbers (bytes/from-base64url (bytes/base64url b))))
           (= n (numbers (bytes/from-base64url (bytes/base64url b {:padding? true}))))
           (= n (numbers (bytes/from-hex (bytes/hex b))))
           (= (bytes/base64 b) (bytes/base64 (bytes/from-base64url (bytes/base64url b))))))))

(defspec one-text-for-each-bytes 200
  (prop/for-all [b random-bytes
                 c (gen/elements "AQgwEIMUYcko048BRhx")]
    ;; changing the last digit either decodes to other bytes or is refused
    (let [s       (bytes/base64url b)
          changed (when (seq s) (str (subs s 0 (dec (count s))) c))]
      (or (nil? changed)
          (= changed s)
          (let [d (bytes/from-base64url changed)]
            (or (nil? d) (not= (numbers b) (numbers d))))))))
