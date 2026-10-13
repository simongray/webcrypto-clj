webcrypto-clj
=============

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/webcrypto-clj.svg)](https://clojars.org/dk.simongray/webcrypto-clj)

This library brings the W3C's
[Web Cryptography API](https://w3c.github.io/webcrypto/) to Clojure and
ClojureScript, along with the bytes and encodings that cryptography needs.
It uses each platform's own cryptography (the JCA on the JVM and WebCrypto
in browsers and Node), so the results are the same everywhere.

- **WebCrypto in Clojure.** The methods of SubtleCrypto have the same names
  in kebab case and take their arguments in the same order, so an example
  on MDN translates line by line.
- **Hashes without promises.** SHA-1 and SHA-2, HMAC and HKDF are
  synchronous everywhere, so a Ring handler can check a signature in place.
- **Keys in every format.** Each platform exports a key as the same SPKI,
  PKCS#8 or JWK, and the library reads and writes PEM, including the keys
  that OpenSSL writes.
- **Bytes on both platforms.** Concatenation, slices, comparisons in
  constant time, UTF-8, hex, base64 and base64url, with strict decoders.
- **The same results everywhere.** Where the platforms disagree, the
  library refuses what any of them refuses, and its errors are data. It
  passes the test vectors of the RFCs, NIST and Wycheproof on the JVM, in
  Node and in Chrome.

> This library brings together the bytes and cryptography of
> [wary-fetch](https://github.com/simongray/wary-fetch), podcast-clj and
> like-minded, which each had a copy of their own. Like them, it was
> developed with assistance from frontier LLMs.

Getting started
---------------

The library needs Clojure 1.11+ and Java 11+ (15+ for Ed25519), and in
ClojureScript Node 22+ or a browser with WebCrypto. Add the latest release from
[Clojars](https://clojars.org/dk.simongray/webcrypto-clj) to the `:deps` of
your `deps.edn`:

```clojure
dk.simongray/webcrypto-clj {:mvn/version "0.1.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead. In shadow-cljs a Git dependency only works through
`deps.edn`, so set `:deps true` in your `shadow-cljs.edn` too.

Bytes
-----

Bytes are a byte array on the JVM and a Uint8Array in JavaScript. The
[`bytes`](src/dk/simongray/webcrypto/bytes.cljc) namespace turns them into
text and back:

```clojure
(require '[dk.simongray.webcrypto.bytes :as bytes])

(bytes/hex (bytes/encode "Blåbær"))
;; => "426cc3a562c3a672"

(bytes/base64url (bytes/of [0 1 2 250 251 252 253 254 255]))
;; => "AAEC-vv8_f7_"
```

Each encoding has a decoder of its own, e.g. `bytes/from-hex`, and
`bytes/decode` reads UTF-8. A decoder returns nil for text that isn't
valid. They're strict: base64 needs its padding, base64url takes it or
not, and neither takes whitespace or pad bits that aren't zero.

Compare secrets with `bytes/same?` and `bytes/same-text?`, which take the
same time wherever the bytes differ.

Hashes and HMACs
----------------

The [`hash`](src/dk/simongray/webcrypto/hash.cljc) namespace has SHA-1 and
SHA-2, HMAC and HKDF. They return their results at once on every platform:

```clojure
(require '[dk.simongray.webcrypto.hash :as hash])

(bytes/hex (hash/digest :sha-256 (bytes/encode "abc")))
;; => "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

(bytes/hex (hash/hmac :sha-256 (bytes/encode "key")
                      (bytes/encode "The quick brown fox jumps over the lazy dog")))
;; => "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
```

Derive keys with `hash/hkdf`, or with its two steps, `hash/hkdf-extract`
and `hash/hkdf-expand`. In JavaScript the hashes come from the Closure
Library, since WebCrypto only returns promises. For a large file in a
browser, WebCrypto's own `webcrypto/digest` is faster.

The Web Cryptography API
------------------------

The root namespace has random bytes and the methods of SubtleCrypto. On the
JVM each returns its result (and in ClojureScript a promise of it). This
seals a text with AES-GCM under a key from a passphrase:

```clojure
(require '[dk.simongray.webcrypto :as webcrypto])

(def password
  (webcrypto/import-key :raw (bytes/encode "correct horse battery staple")
                        :pbkdf2 false [:derive-key]))

(def pbkdf2
  {:name :pbkdf2 :hash :sha-256 :salt (webcrypto/random-bytes 16) :iterations 600000})

(def aes-key
  (webcrypto/derive-key pbkdf2 password {:name :aes-gcm :length 256}
                        false [:encrypt :decrypt]))

(def aes-gcm
  {:name :aes-gcm :iv (webcrypto/random-bytes 12)})

(def sealed
  (webcrypto/encrypt aes-gcm aes-key (bytes/encode "a secret")))

(bytes/decode (webcrypto/decrypt aes-gcm aes-key sealed))
;; => "a secret"
```

In ClojureScript each of these is a promise. Chain them with
`webcrypto/then`, which takes a value or a promise, so that the same code
runs on both platforms:

```clojure
(-> (webcrypto/import-key :raw (bytes/encode "correct horse battery staple")
                          :pbkdf2 false [:derive-key])
    (webcrypto/then #(webcrypto/derive-key pbkdf2 % {:name :aes-gcm :length 256}
                                           false [:encrypt :decrypt])))
```

An algorithm is a keyword, or a map of its `:name` and its parameters,
named as in WebCrypto but in kebab case (e.g. `:additional-data`). Usages
and formats are keywords too, and a JWK is a map. To see what a key is,
use `webcrypto/key-info`:

```clojure
(webcrypto/key-info aes-key)
;; => {:type :secret :extractable? false
;;     :algorithm {:name :aes-gcm :length 256} :usages #{:encrypt :decrypt}}
```

| Methods | Algorithms |
|---|---|
| `digest` | `:sha-1`, `:sha-256`, `:sha-384` and `:sha-512` |
| `sign` and `verify` | `:hmac`, `:ecdsa`, `:rsassa-pkcs1-v1_5`, `:rsa-pss` and `:ed25519` |
| `encrypt` and `decrypt` | `:aes-gcm` |
| `derive-bits` and `derive-key` | `:hkdf`, `:pbkdf2` and `:ecdh` |
| `generate-key` | `:hmac`, `:aes-gcm`, and the key pairs of `:ecdsa`, `:ecdh`, `:rsassa-pkcs1-v1_5`, `:rsa-pss` and `:ed25519` |
| `import-key` and `export-key` | secret keys as `:raw` or `:jwk`, key pairs as `:spki`, `:pkcs8` or `:jwk` (and EC and Ed25519 public keys as `:raw`), and an import of `:hkdf` or `:pbkdf2` as `:raw` |

Signatures and keys
-------------------

A key pair is a map of its `:public-key` and its `:private-key`. This signs
with ECDSA, whose signature is r and s side by side, as in JOSE and RFC
9421:

```clojure
(def key-pair
  (webcrypto/generate-key {:name :ecdsa :named-curve :p-256} false [:sign :verify]))

(def ecdsa
  {:name :ecdsa :hash :sha-256})

(def signature
  (webcrypto/sign ecdsa (:private-key key-pair) (bytes/encode "a message")))

(webcrypto/verify ecdsa (:public-key key-pair) signature (bytes/encode "a message"))
;; => true
```

ECDSA and ECDH take the curves `:p-256`, `:p-384` and `:p-521`. With
ECDH, `derive-bits` and `derive-key` take the other party's public key as
`:public`.

The [`pem`](src/dk/simongray/webcrypto/pem.cljc) namespace writes the
keys that `export-key` returns as PEM, and reads PEM for `import-key`:

```clojure
(require '[dk.simongray.webcrypto.pem :as pem])

(pem/encode "PUBLIC KEY" (webcrypto/export-key :spki (:public-key key-pair)))
;; => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"

(let [{:keys [format data]} (pem/key-data (slurp "private-key.pem"))]
  (webcrypto/import-key format data {:name :rsa-pss :hash :sha-512} false [:sign]))
```

WebCrypto only imports SPKI and PKCS#8, so `pem/key-data` turns the
PKCS#1 and SEC1 keys that OpenSSL writes, e.g. RSA PRIVATE KEY, into those.

Errors
------

A call that fails throws an ex-info (or in ClojureScript, rejects with
one) whose `:type` is the name of WebCrypto's exception, e.g. a ciphertext
that someone changed:

```clojure
(try
  (webcrypto/decrypt aes-gcm aes-key (bytes/of (range 32)))
  (catch Exception e
    (:type (ex-data e))))
;; => :dk.simongray.webcrypto/operation-error
```

The docstring of the root namespace lists the types. The library runs the
spec's checks itself before it calls the platform, so a mistake throws the
same error everywhere.

Where the platforms disagree, the library refuses what any of them refuses
with `:dk.simongray.webcrypto/not-supported-error`:

- AES keys of 192 bits, which Chrome refuses
- GCM tags of 32 and 64 bits, which the JDK refuses
- IVs of fewer than 12 bytes or more than 128, which WebCrypto in Node
  refuses
- PBKDF2 with an empty salt or a password that isn't UTF-8, which the
  JDK's PBKDF2 can't take
- New RSA key pairs whose modulus isn't a multiple of 128 bits from 512 to
  8,192, or whose public exponent isn't 3 or 65537, which Chrome can't make
- RSA keys of fewer than 512 bits or more than 16,384, which the JDK
  refuses, and public exponents of more than 33 bits, which Chrome refuses
- PBKDF2 with more than 2,147,483,647 iterations or bits, which the JDK
  takes as an int

Where only some platforms check a key, the library checks it on all of
them, e.g. that the numbers of an RSA private key agree, which Chrome
checks and Node doesn't. A key that fails a check throws data-error
everywhere.

Security
--------

- Take an algorithm's parameters, e.g. the tag length, the hash, the salt
  length and the iterations, from your own configuration and never from
  the message you check.
- Never encrypt twice with the same key and IV. A random IV of 12 bytes is
  safe for 2³² messages under one key (NIST SP 800-38D, section 8.3).
- On the JVM, `export-key` refuses a key that isn't extractable, but its
  material is in memory that any code in the JVM can reach.
- An Ed25519 public key of small order verifies forged signatures on every
  platform, so the library refuses it on import.

Not yet
-------

- **The rest of WebCrypto:** X25519, `wrap-key` and `unwrap-key` with
  AES-KW, AES-CTR, AES-CBC, RSA-OAEP and `randomUUID`.
- **Streaming digests,** which WebCrypto doesn't have.

Principles
----------

- **Standards first.** The code follows the Web Cryptography API (the
  Level 2 Editor's Draft of 11 August 2026) and cites its sections, and
  those of the RFCs and FIPS it relies on.
- **The platform's cryptography.** The library writes no primitive that
  the platforms have. Where the JDK lacks a step, e.g. HKDF before Java 25
  or the public key of an EC private key, the library composes it from the
  JDK's own primitives.
- **Plain data.** Algorithms are keywords and maps, a key describes itself
  as a map, and errors are ex-infos with a `:type`.
- **One codebase.** The library is written in `.cljc` and has no
  dependencies.

Development
-----------

```bash
dev/fetch.sh                        # once, for the vectors of Wycheproof and NIST
clojure -X:test                     # the tests on the JVM
npm install                         # once, for the Node tests
clojure -M:cljs compile test        # the tests in Node
clojure -M:cljs watch browser-test  # the tests in a browser, at http://localhost:8021
```

The fetch script downloads the test vectors of
[Wycheproof](https://github.com/C2SP/wycheproof) at a pinned commit and
NIST's vectors of GCM into `dev-resources/` (which Git ignores). NIST
doesn't version its file, so the script checks its SHA-256. Without these
files the tests check only the vectors of the RFCs.

The public namespaces are the root, `bytes`, `hash` and `pem`. The
internal ones are under `impl`:

- `impl.algorithms`, the algorithms and the normalization of their
  parameters
- `impl.keys` and `impl.jwk`, keys and their JWKs
- `impl.der`, the DER of SPKI, PKCS#8 and the keys inside them
- `impl.hmac`, `impl.aes-gcm`, `impl.kdf`, `impl.ec`, `impl.rsa` and
  `impl.ed25519`, the operations of each algorithm on each platform
- `impl.subtle`, the calls of WebCrypto in JavaScript
- `impl.errors`, `impl.async` and `impl.random`, the errors, the promises
  and the random bytes

License
-------

The webcrypto-clj project is licensed under the [MIT licence](LICENSE).
