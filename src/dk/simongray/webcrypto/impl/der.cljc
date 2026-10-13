(ns ^:no-doc dk.simongray.webcrypto.impl.der
  "The DER of the key formats that WebCrypto reads and writes (X.690):
  SubjectPublicKeyInfo (RFC 5280), PrivateKeyInfo (RFC 5208), and the
  RSA (RFC 8017) and EC (RFC 5915) keys inside them.

  A parsed value is a map of its :tag and either its :content as bytes or,
  when it's constructed, its :children. The reader only takes DER, so a
  length in more bytes than it needs is an error. Each error is data-error,
  as WebCrypto has it for key data that doesn't parse."
  (:require [clojure.string :as str]
            [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.impl.errors :as errors]))

(def tags
  "The tags of the universal types that keys use, and of the context tags
  [0] and [1] of their optional fields."
  {:integer      0x02
   :bit-string   0x03
   :octet-string 0x04
   :null         0x05
   :oid          0x06
   :sequence     0x30
   :context-0    0xA0
   :context-1    0xA1})

(def oids
  "The object identifiers of the algorithms and curves of keys."
  {:rsa-encryption  "1.2.840.113549.1.1.1"
   :rsassa-pss      "1.2.840.113549.1.1.10"
   :ec-public-key   "1.2.840.10045.2.1"
   :secp256r1       "1.2.840.10045.3.1.7"
   :secp384r1       "1.3.132.0.34"
   :secp521r1       "1.3.132.0.35"
   :ed25519         "1.3.101.112"})

(defn- invalid
  "The data-error for key data that isn't DER, because of `why`."
  [why]
  (errors/error :data-error (str "The key data isn't valid DER: " why)))

(defn- byte-at
  "The byte at `i` of `b` as a number from 0 to 255, or a throw when `b`
  ends before it."
  [b i]
  (when (>= i (bytes/length b))
    (throw (invalid "it ends too soon")))
  (bytes/at b i))

;; X.690, section 8.1.3 and 10.1
(defn- read-length
  "The length that starts at `i` of the bytes `b` and the index after it,
  as a pair."
  [b i]
  (let [first-byte (byte-at b i)]
    (if (< first-byte 0x80)
      [first-byte (inc i)]
      (let [n      (bit-and first-byte 0x7f)
            digits (map #(byte-at b (+ i 1 %)) (range n))]
        (when (or (zero? n) (> n 4) (zero? (first digits)))
          (throw (invalid "a length isn't in its shortest form")))
        (let [length (reduce #(+ (* 256 %1) %2) 0 digits)]
          (when (< length 0x80)
            (throw (invalid "a length isn't in its shortest form")))
          [length (+ i 1 n)])))))

(declare read-all)

(defn- read-value
  "The value that starts at `i` of the bytes `b` and the index after it,
  as a pair. The value is inside `depth` others."
  [b i depth]
  (let [tag            (byte-at b i)
        [length start] (read-length b (inc i))
        end            (+ start length)]
    (when (> end (bytes/length b))
      (throw (invalid "a value is longer than the data")))
    [(if (pos? (bit-and tag 0x20))
       {:tag tag :children (read-all (bytes/slice b start end) (inc depth))}
       {:tag tag :content (bytes/slice b start end)})
     end]))

(defn read-all
  "The values of the bytes `b`, one after another, as a vector. They're
  inside `depth` others."
  [b depth]
  ;; the parameters of RSASSA-PSS nest values deepest in a key, inside 6
  ;; others, and values nested without end would overflow the stack
  (when (> depth 8)
    (throw (invalid "it nests values too deep for a key")))
  (loop [i 0 values []]
    (if (< i (bytes/length b))
      (let [[value next-i] (read-value b i depth)]
        (recur (long next-i) (conj values value)))
      values)))

(defn parse
  "The single value of the bytes `b`, or a throw of data-error when they
  hold another number of values or aren't DER."
  [b]
  (let [values (read-all b 0)]
    (when-not (= 1 (count values))
      (throw (invalid "it isn't a single value")))
    (first values)))

(defn expect
  "The `value`, or a throw of data-error unless its tag is the `tag`, a key
  of tags."
  [value tag]
  (when-not (= (tags tag) (:tag value))
    (throw (invalid (str "a value isn't " (name tag)))))
  value)

(defn children
  "The children of the `value`, a sequence, or a throw unless it has from
  `least` to `most` of them."
  [value least most]
  (let [cs (:children (expect value :sequence))]
    (when-not (<= least (count cs) most)
      (throw (invalid "a sequence has the wrong number of fields")))
    cs))

(defn- arc-digits
  "The digits in base 128 of each arc of the bytes `b` of an object
  identifier, or a throw when an arc isn't in its fewest digits. Keys have
  no arc of more than 7 digits, and a longer one wouldn't fit a number in
  JavaScript."
  [b]
  (let [[arcs unfinished] (reduce (fn [[arcs arc] x]
                                    (let [arc (conj arc x)]
                                      (if (< x 0x80) [(conj arcs arc) []] [arcs arc])))
                                  [[] []]
                                  (map #(byte-at b %) (range (bytes/length b))))]
    (when (or (empty? arcs)
              (seq unfinished)
              (some #(or (= 0x80 (first %)) (> (count %) 7)) arcs))
      (throw (invalid "an object identifier isn't in its shortest form")))
    arcs))

;; X.690, section 8.19
(defn read-oid
  "The object identifier of the `value` as text, e.g. 1.3.101.112."
  [value]
  (let [[first-arc & arcs] (map (fn [digits] (reduce #(+ (* 128 %1) (bit-and %2 0x7f)) 0 digits))
                                (arc-digits (:content (expect value :oid))))]
    (str/join "." (concat (if (< first-arc 80)
                            [(quot first-arc 40) (mod first-arc 40)]
                            [2 (- first-arc 80)])
                          arcs))))

;; X.690, section 8.3
(defn read-unsigned
  "The non-negative integer of the `value` as its bytes, the most
  significant first and without leading zeros."
  [value]
  (let [b (:content (expect value :integer))
        n (bytes/length b)]
    (when (zero? n)
      (throw (invalid "an integer is empty")))
    (when (>= (byte-at b 0) 0x80)
      (throw (invalid "an integer is negative")))
    (if (and (> n 1) (zero? (byte-at b 0)))
      (do (when (< (byte-at b 1) 0x80)
            (throw (invalid "an integer has a leading zero too many")))
          (bytes/slice b 1))
      b)))

(defn read-bit-string
  "The bytes of the bit string `value`, which has no unused bits."
  [value]
  (let [b (:content (expect value :bit-string))]
    (when-not (and (pos? (bytes/length b)) (zero? (byte-at b 0)))
      (throw (invalid "a bit string has unused bits")))
    (bytes/slice b 1)))

(defn read-octet-string
  "The bytes of the octet string `value`."
  [value]
  (:content (expect value :octet-string)))

;; X.690, section 8.1.3
(defn- length-bytes
  "The DER of the length `n`."
  [n]
  (if (< n 0x80)
    (bytes/of [n])
    (let [digits (loop [n n digits ()]
                   (if (zero? n) digits (recur (quot n 256) (cons (mod n 256) digits))))]
      (bytes/of (cons (+ 0x80 (count digits)) digits)))))

(defn tlv
  "The DER of a value of the `tag`, a key of tags, with the bytes
  `content`."
  [tag content]
  (bytes/concat (bytes/of [(tags tag)]) (length-bytes (bytes/length content)) content))

(defn sequence-of
  "The DER of a sequence of the DER `values`."
  [& values]
  (tlv :sequence (apply bytes/concat values)))

(defn unsigned
  "The DER of the non-negative integer of the bytes `b`, the most
  significant first."
  [b]
  (let [n        (bytes/length b)
        zeros    (count (take-while #(zero? (byte-at b %)) (range (dec n))))
        stripped (bytes/slice b zeros)]
    (tlv :integer (if (or (zero? (bytes/length stripped)) (>= (byte-at stripped 0) 0x80))
                    (bytes/concat (bytes/of [0]) stripped)
                    stripped))))

(defn small-integer
  "The DER of the integer `n`, from 0 to 127."
  [n]
  (tlv :integer (bytes/of [n])))

(defn oid
  "The DER of the object identifier `s`, e.g. 1.3.101.112."
  [s]
  (let [[a b & more] (map parse-long (str/split s #"\."))
        base-128     (fn [n]
                       (let [digits (loop [n n digits ()]
                                      (if (< n 128)
                                        (cons n digits)
                                        (recur (quot n 128) (cons (mod n 128) digits))))]
                         (concat (map #(bit-or % 0x80) (butlast digits)) [(last digits)])))]
    (tlv :oid (bytes/of (mapcat base-128 (cons (+ (* 40 a) b) more))))))

(defn null
  "The DER of NULL."
  []
  (tlv :null (bytes/of [])))

(defn bit-string
  "The DER of a bit string of the bytes `b`, with no unused bits."
  [b]
  (tlv :bit-string (bytes/concat (bytes/of [0]) b)))

(defn octet-string
  "The DER of an octet string of the bytes `b`."
  [b]
  (tlv :octet-string b))

(defn context
  "The DER of the explicitly tagged `value` as the field [`n`], 0 or 1."
  [n value]
  (tlv (if (zero? n) :context-0 :context-1) value))

;; RFC 5280, section 4.1.2.7
(defn spki
  "The SubjectPublicKeyInfo in the bytes `b` as a map of its :algorithm,
  an object identifier, its :parameters, a value or nil, and its
  :public-key, bytes."
  [b]
  (let [[algorithm public-key] (children (parse b) 2 2)
        [identifier params]    (children algorithm 1 2)]
    {:algorithm  (read-oid identifier)
     :parameters params
     :public-key (read-bit-string public-key)}))

(defn write-spki
  "The DER of a SubjectPublicKeyInfo of the `algorithm`, an object
  identifier, with the DER `parameters` (or none) and the bytes
  `public-key`."
  [algorithm parameters public-key]
  (sequence-of (apply sequence-of (oid algorithm) (keep identity [parameters]))
               (bit-string public-key)))

;; RFC 5208, section 5, and RFC 5958, section 2, its version 2
(defn private-key-info
  "The PrivateKeyInfo in the bytes `b` as a map of its :algorithm, an
  object identifier, its :parameters, a value or nil, and its
  :private-key, bytes."
  [b]
  (let [[version algorithm private-key] (children (parse b) 3 5)
        [identifier params]             (children algorithm 1 2)]
    (when-not (#{"00" "01"} (bytes/hex (read-unsigned version)))
      (throw (invalid "a private key has another version")))
    {:algorithm   (read-oid identifier)
     :parameters  params
     :private-key (read-octet-string private-key)}))

(defn write-private-key-info
  "The DER of a PrivateKeyInfo of version 0 of the `algorithm`, an object
  identifier, with the DER `parameters` (or none) and the bytes
  `private-key`."
  [algorithm parameters private-key]
  (sequence-of (small-integer 0)
               (apply sequence-of (oid algorithm) (keep identity [parameters]))
               (octet-string private-key)))

(defn- context-field
  "The field among the `values` with the context tag of the `tag`."
  [values tag]
  (first (filter #(= (tags tag) (:tag %)) values)))

;; RFC 5915, section 3
(defn ec-private-key
  "The ECPrivateKey in the bytes `b` as a map of its private key :d, bytes,
  its :parameters, an object identifier or nil, and its :public-key, the
  bytes of a point or nil."
  [b]
  (let [[version d & more] (children (parse b) 2 4)
        parameters         (context-field more :context-0)
        public-key         (context-field more :context-1)]
    (when-not (= "01" (bytes/hex (read-unsigned version)))
      (throw (invalid "an EC private key has another version")))
    {:d          (read-octet-string d)
     :parameters (some-> parameters :children first read-oid)
     :public-key (some-> public-key :children first read-bit-string)}))

(defn write-ec-private-key
  "The DER of an ECPrivateKey of the private key `d` and the point
  `public-key`, both bytes, without its parameters, as Chrome and Node
  write it."
  [d public-key]
  (sequence-of (small-integer 1)
               (octet-string d)
               (context 1 (bit-string public-key))))

;; RFC 8017, Appendix A.1.1
(defn rsa-public-key
  "The RSAPublicKey in the bytes `b` as a map of its modulus :n and its
  exponent :e, as bytes."
  [b]
  (let [[n e] (children (parse b) 2 2)]
    {:n (read-unsigned n)
     :e (read-unsigned e)}))

;; RFC 8017, Appendix A.1.2
(def rsa-private-fields
  "The fields of an RSAPrivateKey of two primes after its version, in
  order."
  [:n :e :d :p :q :dp :dq :qi])

(defn rsa-private-key
  "The RSAPrivateKey of two primes in the bytes `b` as a map of its fields,
  each as bytes."
  [b]
  (let [[version & fields] (children (parse b) 9 9)]
    (when-not (= "00" (bytes/hex (read-unsigned version)))
      (throw (invalid "an RSA private key has more than two primes")))
    (zipmap rsa-private-fields (map read-unsigned fields))))

(defn write-rsa-private-key
  "The DER of an RSAPrivateKey of two primes with the fields of the map
  `m`, each as bytes."
  [m]
  (apply sequence-of (small-integer 0) (map #(unsigned (m %)) rsa-private-fields)))

(defn write-rsa-public-key
  "The DER of an RSAPublicKey of the modulus `n` and the exponent `e`, as
  bytes."
  [n e]
  (sequence-of (unsigned n) (unsigned e)))
