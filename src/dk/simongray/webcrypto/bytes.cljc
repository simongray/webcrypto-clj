(ns dk.simongray.webcrypto.bytes
  "Bytes on both platforms, a byte array on the JVM and a Uint8Array in
  JavaScript, and their encodings: UTF-8, hex, base64 and base64url.

  Each decoder returns nil for text that isn't valid. The decoders of
  base64 are strict on both platforms: they take only the alphabet, the
  padding where RFC 4648 asks for it and pad bits of zero, so that no two
  texts decode to the same bytes."
  (:refer-clojure :exclude [bytes? concat])
  (:require [clojure.string :as str]
            #?(:cljs [goog.crypt :as crypt]))
  #?(:clj (:import [java.nio CharBuffer]
                   [java.nio.charset CodingErrorAction StandardCharsets]
                   [java.security MessageDigest]
                   [java.util Arrays Base64])))

(defn bytes?
  "Whether `x` is bytes: a byte array on the JVM, or a Uint8Array in
  JavaScript (and a Buffer in Node is one)."
  [x]
  #?(:clj  (clojure.core/bytes? x)
     :cljs (instance? js/Uint8Array x)))

(defn of
  "The bytes of the numbers `xs`, each from 0 to 255."
  [xs]
  #?(:clj  (byte-array (map unchecked-byte xs))
     :cljs (js/Uint8Array.from (into-array xs))))

(defn length
  "The number of bytes in `b`."
  [b]
  #?(:clj  (alength ^bytes b)
     :cljs (.-length b)))

(defn at
  "The byte at the index `i` of `b`, as a number from 0 to 255."
  [b i]
  #?(:clj  (bit-and (aget ^bytes b (int i)) 0xff)
     :cljs (aget b i)))

(defn concat
  "The bytes of each of `bs`, one after another, as new bytes."
  [& bs]
  (let [out #?(:clj  (byte-array (reduce + (map length bs)))
               :cljs (js/Uint8Array. (reduce + (map length bs))))]
    (reduce (fn [at b]
              #?(:clj  (System/arraycopy b 0 out (int at) (alength ^bytes b))
                 :cljs (.set out b at))
              (+ at (length b)))
            0
            bs)
    out))

(defn slice
  "The bytes of `b` from `start` to `end`, or to the end of `b`, as new
  bytes. It throws when they aren't within `b`."
  ([b start]
   (slice b start (length b)))
  ([b start end]
   (when-not (<= 0 start end (length b))
     (throw (ex-info (str "The bytes from " start " to " end
                          " aren't within " (length b) " bytes")
                     {:start start :end end :length (length b)})))
   #?(:clj  (Arrays/copyOfRange ^bytes b (int start) (int end))
      :cljs (.slice b start end))))

(defn same?
  "Whether `a` and `b` are the same bytes, in a time that doesn't tell where
  they differ, as a comparison of secrets needs. Nil or another value is
  never the same."
  [a b]
  (and (bytes? a)
       (bytes? b)
       #?(:clj  (MessageDigest/isEqual ^bytes a ^bytes b)
          :cljs (and (= (.-length a) (.-length b))
                     (zero? (areduce a i acc 0
                                     (bit-or acc (bit-xor (aget a i)
                                                          (aget b i)))))))))

;; RFC 3629, and the Encoding Standard, section 9.1, for TextEncoder
(defn encode
  "The bytes of the text `s` in UTF-8, or a throw of type-error when `s`
  isn't a string. A lone surrogate, which UTF-8 can't hold, becomes U+FFFD
  on both platforms, as with TextEncoder."
  [s]
  ;; TextEncoder would encode nil as the text null, where the JDK throws an
  ;; exception of its own
  (when-not (string? s)
    (throw (ex-info "The text to encode is a string"
                    {:type :dk.simongray.webcrypto/type-error})))
  #?(:clj  (let [encoder (-> StandardCharsets/UTF_8
                             .newEncoder
                             (.onMalformedInput CodingErrorAction/REPLACE)
                             (.replaceWith (of [0xEF 0xBF 0xBD])))
                 buffer  (.encode encoder (CharBuffer/wrap ^String s))
                 out     (byte-array (.remaining buffer))]
             (.get buffer out)
             out)
     :cljs (.encode (js/TextEncoder.) s)))

(defn decode
  "The text of the UTF-8 bytes `b`. A byte order mark stays, and bytes that
  aren't UTF-8 become U+FFFD, though the JVM and JavaScript can differ in
  how many."
  [b]
  #?(:clj  (String. ^bytes b StandardCharsets/UTF_8)
     :cljs (.decode (js/TextDecoder. "utf-8" #js {:ignoreBOM true}) b)))

(defn same-text?
  "Whether `a` and `b` are the same text, in a time that doesn't tell where
  they differ. Nil or another value is never the same."
  [a b]
  (let [code-unit #?(:clj  #(int (.charAt ^String %1 (int %2)))
                     :cljs #(.charCodeAt %1 %2))]
    (and (string? a)
         (string? b)
         (= (count a) (count b))
         ;; the code units, since UTF-8 would turn each lone surrogate
         ;; into the same U+FFFD
         (zero? (reduce bit-or 0 (map #(bit-xor (code-unit a %) (code-unit b %))
                                      (range (count a))))))))

;; RFC 4648, section 8
(defn hex
  "The bytes `b` in hexadecimal, two digits in lower case for each byte."
  [b]
  #?(:clj  (let [alphabet "0123456789abcdef"
                 out      (char-array (* 2 (alength ^bytes b)))]
             (dotimes [i (alength ^bytes b)]
               (let [x (bit-and (aget ^bytes b i) 0xff)]
                 (aset out (* 2 i) (.charAt alphabet (bit-shift-right x 4)))
                 (aset out (inc (* 2 i)) (.charAt alphabet (bit-and x 0xf)))))
             (String. out))
     :cljs (crypt/byteArrayToHex b)))

;; RFC 4648, section 8
(defn from-hex
  "The bytes of the hexadecimal text `s`, in upper or lower case, or nil
  when it isn't hexadecimal or has an odd number of digits."
  [s]
  (when (and (string? s)
             (even? (count s))
             (re-matches #"[0-9a-fA-F]*" s))
    #?(:clj  (let [out (byte-array (quot (count s) 2))]
               (dotimes [i (alength out)]
                 (aset out i (unchecked-byte
                              (+ (* 16 (Character/digit (.charAt ^String s (* 2 i)) 16))
                                 (Character/digit (.charAt ^String s (inc (* 2 i))) 16)))))
               out)
       :cljs (js/Uint8Array.from (crypt/hexToByteArray s)))))

#?(:cljs
   (defn- binary-string
     "The bytes `b` as a string of one character for each byte, in pieces so
     that a large array never overflows the stack of `apply`."
     [b]
     (let [n (.-length b)]
       (apply str (for [i (range 0 n 32768)]
                    (.apply js/String.fromCharCode nil
                            (.subarray b i (min n (+ i 32768)))))))))

;; RFC 4648, section 4
(defn base64
  "The bytes `b` in base64, with padding."
  [b]
  #?(:clj  (.encodeToString (Base64/getEncoder) ^bytes b)
     :cljs (js/btoa (binary-string b))))

;; RFC 4648, section 5
(defn base64url
  "The bytes `b` in base64url, the alphabet of base64 for URLs and file
  names, with `opts`:

  - :padding?, true to pad the text to a multiple of four characters, as
    base64 is. It's false by default, as in JOSE and most other uses."
  ([b]
   (base64url b {}))
  ([b {:keys [padding?] :as opts}]
   #?(:clj  (.encodeToString (cond-> (Base64/getUrlEncoder)
                               (not padding?) .withoutPadding)
                             ^bytes b)
      :cljs (cond-> (str/escape (base64 b) {\+ "-" \/ "_"})
              (not padding?) (str/replace #"=+$" "")))))

;; RFC 4648, section 3.2, where a regex of the pads would take quadratic
;; time on a long run of = that doesn't end the text
(defn ^:no-doc digits
  "The digits of the base64 text `s` without its padding, or nil when the
  padding doesn't end the last group of four digits, or when there's none
  although it's `required?`. A third pad stays among the digits, where it
  isn't valid."
  [s required?]
  (let [pads (cond (str/ends-with? s "==") 2
                   (str/ends-with? s "=")  1
                   :else                   0)]
    (when (or (and (zero? pads) (not required?))
              (zero? (mod (count s) 4)))
      (subs s 0 (- (count s) pads)))))

;; RFC 4648, section 3.5
(defn ^:no-doc canonical?
  "Whether the base64 `digits`, without padding, encode whole bytes and
  leave the pad bits of the last digit at zero. The digits that do are the
  same in both alphabets."
  [digits]
  (let [n    (count digits)
        last (subs digits (max 0 (dec n)))]
    (case (int (mod n 4))
      0 true
      1 false
      2 (str/includes? "AQgw" last)
      3 (str/includes? "AEIMQUYcgkosw048" last))))

(defn ^:no-doc decode-base64
  "The bytes of the canonical `digits` of base64, or of base64url when
  `url?`."
  [digits url?]
  #?(:clj  (.decode (if url? (Base64/getUrlDecoder) (Base64/getDecoder))
                    ^String digits)
     :cljs (let [s (js/atob (cond-> digits
                              url? (str/escape {\- "+" \_ "/"})))]
             (js/Uint8Array.from s #(.charCodeAt % 0)))))

;; RFC 4648, section 4
(defn from-base64
  "The bytes of the base64 text `s`, which has its padding, or nil when it
  isn't base64."
  [s]
  (when-let [digits (and (string? s) (digits s true))]
    (when (and (re-matches #"[A-Za-z0-9+/]*" digits)
               (canonical? digits))
      (decode-base64 digits false))))

;; RFC 4648, section 5
(defn from-base64url
  "The bytes of the base64url text `s`, with or without padding, or nil
  when it isn't base64url."
  [s]
  (when-let [digits (and (string? s) (digits s false))]
    (when (and (re-matches #"[A-Za-z0-9_-]*" digits)
               (canonical? digits))
      (decode-base64 digits true))))

(comment
  (hex (encode "Blåbær"))
  ;; => "426cc3a562c3a672"
  (base64url (of [0 1 2 250 251 252 253 254 255]))
  ;; => "AAEC-vv8_f7_"
  (from-base64 "Zh==")
  ;; => nil, since the pad bits aren't zero
  (same-text? "s3cr3t" "s3cr3t")
  #_.)
