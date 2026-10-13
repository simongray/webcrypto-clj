(ns ^:no-doc dk.simongray.webcrypto.impl.random
  "Random bytes from the platform's secure source of randomness."
  #?(:clj (:import [java.security SecureRandom])))

#?(:clj
   (def secure-random
     "The source of random bytes on the JVM, which threads can share."
     (SecureRandom.)))

;; WebCrypto, section 10.1.1
(defn random-bytes
  "An array of `n` random bytes. In JavaScript they come from
  getRandomValues, which gives at most 65,536 bytes a call, so more take
  several calls."
  [n]
  #?(:clj  (let [b (byte-array n)]
             (.nextBytes ^SecureRandom secure-random b)
             b)
     :cljs (let [b (js/Uint8Array. n)]
             (doseq [start (range 0 n 65536)]
               (js/crypto.getRandomValues (.subarray b start (min n (+ start 65536)))))
             b)))
