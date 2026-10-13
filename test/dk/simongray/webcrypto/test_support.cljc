(ns dk.simongray.webcrypto.test-support
  "What the tests share: steps that give values on the JVM and promises in
  ClojureScript, the outcome of a call as data, and the files that
  dev/fetch.sh puts in dev-resources, read the same way on the JVM, in Node
  and in a browser. A file is nil when it isn't there, and the tests of its
  data then check nothing."
  (:require #?(:clj  [clojure.test :refer [is]]
               :cljs [cljs.test :refer [async is]])
            #?(:cljs ["fs" :as fs])
            #?(:clj [clojure.data.json :as json])
            #?(:clj [clojure.java.io :as io])))

(defn run
  "Run the steps `fs` one after another as a test on either platform. Each
  step is a function of no arguments that gives a value or a promise.

  In ClojureScript, a deftest runs only the async test that it returns. So
  a deftest calls `run` once, as its last form, with all its steps."
  [& fs]
  #?(:clj  (doseq [f fs] (f))
     :cljs (async done
             (-> (reduce (fn [p f] (.then p (fn [_] (f)))) (js/Promise.resolve nil) fs)
                 (.catch (fn [e] (is false (str "rejected: " e (some-> e .-stack)))))
                 (.finally done)))))

(defn then
  "The result of `f` on `x`, a value or (in ClojureScript) a promise."
  [x f]
  #?(:clj  (f x)
     :cljs (.then (js/Promise.resolve x) f)))

(defn all
  "The values of `xs`, which can be promises in ClojureScript, as a vector,
  in ClojureScript as a promise."
  [xs]
  #?(:clj  (vec xs)
     :cljs (.then (js/Promise.all (into-array xs)) vec)))

(defn outcome
  "The outcome of calling `f` as a map of its :value, or of the :error's
  :type when it throws (or in ClojureScript rejects), in ClojureScript as a
  promise."
  [f]
  (let [failed (fn [e] {:error (or (:type (ex-data e)) e)})]
    #?(:clj  (try
               {:value (f)}
               (catch Exception e
                 (failed e)))
       :cljs (-> (js/Promise.resolve nil)
                 (.then (fn [_] (f)))
                 (.then (fn [v] {:value v}))
                 (.catch failed)))))

(defn error-of
  "The :type of the error that calling `f` throws (or in ClojureScript,
  rejects with), or nil, in ClojureScript as a promise."
  [f]
  ;; a promise ignores a keyword, which isn't a JavaScript function
  (then (outcome f) #(:error %)))

(defn fails-with
  "Check that calling `f` fails with the error of the `kind`, e.g.
  :operation-error, for the reason `why`, in ClojureScript as a promise."
  [kind why f]
  (then (error-of f)
        #(is (= (keyword "dk.simongray.webcrypto" (name kind)) %) why)))

(defn text
  "The text of the file at `path` in dev-resources, or nil."
  [path]
  (let [path (str "dev-resources/" path)]
    #?(:clj  (let [f (io/file path)]
               (when (.exists f) (slurp f)))
       :cljs (if (exists? js/XMLHttpRequest)
               ;; in a browser, from a server of the project's directory
               (let [request (js/XMLHttpRequest.)]
                 (.open request "GET" (str "/" path) false)
                 (.send request)
                 (when (= 200 (.-status request))
                   (.-responseText request)))
               (when (fs/existsSync path)
                 (fs/readFileSync path "utf8"))))))

(defn json
  "The data of the JSON file at `path` in dev-resources, with string keys,
  or nil."
  [path]
  (when-let [s (text path)]
    #?(:clj  (json/read-str s)
       :cljs (js->clj (js/JSON.parse s)))))
