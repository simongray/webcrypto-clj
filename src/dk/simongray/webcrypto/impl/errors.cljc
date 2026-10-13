(ns ^:no-doc dk.simongray.webcrypto.impl.errors
  "The errors of the library, named as WebCrypto names its exceptions, the
  same way on both platforms."
  (:require [dk.simongray.webcrypto.bytes :as bytes]))

;; WebCrypto, section 14.4
(def kinds
  "The kind of error that the library throws for each exception that
  WebCrypto throws, by the exception's name."
  {"NotSupportedError"  :not-supported-error
   "SyntaxError"        :syntax-error
   "InvalidAccessError" :invalid-access-error
   "DataError"          :data-error
   "OperationError"     :operation-error
   "QuotaExceededError" :quota-exceeded-error
   "TypeError"          :type-error})

(defn error
  "An ex-info with the `message` whose :type is the `kind` of error, e.g.
  :operation-error, as a keyword in the root namespace. Its cause is
  `cause`, when there's one."
  ([kind message]
   (error kind message nil))
  ([kind message cause]
   (ex-info message
            {:type (keyword "dk.simongray.webcrypto" (name kind))}
            cause)))

(defn check
  "Throw the error of the `kind` with the `message` unless `ok?` is true."
  [ok? kind message]
  (when-not ok?
    (throw (error kind message))))

(defn check-bytes
  "Throw type-error unless `x`, the argument named `what`, is bytes."
  [x what]
  (check (bytes/bytes? x) :type-error (str "The " what " is bytes")))
