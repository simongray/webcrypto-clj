(ns ^:no-doc dk.simongray.webcrypto.impl.async
  "Values on the JVM and promises in ClojureScript, so that the methods of
  SubtleCrypto are written once.")

(defn promised
  "The result of calling `f`: on the JVM the value it returns, and in
  ClojureScript a promise of it, which rejects when `f` throws. A promise
  that `f` returns resolves the promise."
  [f]
  #?(:clj  (f)
     :cljs (js/Promise. (fn [resolve _] (resolve (f))))))

(defn then
  "The result of calling `f` on `x`: at once on the JVM, and in
  ClojureScript a promise of it, once `x` resolves if it's a promise."
  [x f]
  #?(:clj  (f x)
     :cljs (.then (js/Promise.resolve x) f)))
