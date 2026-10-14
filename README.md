webcrypto-clj
=============

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/webcrypto-clj.svg)](https://clojars.org/dk.simongray/webcrypto-clj)

This library is the W3C's
[Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
for Clojure and ClojureScript, with the bytes and encodings that
cryptography needs. It runs on each platform's own cryptography: the
[Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)
on the JVM and WebCrypto in browsers and Node.

- **WebCrypto as you know it.** The methods have the same names in kebab
  case and take the same arguments, so an example on
  [MDN](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
  translates line by line.
- **Hashes without promises.** SHA-1, SHA-2,
  [HMAC](https://en.wikipedia.org/wiki/HMAC) and
  [HKDF](https://en.wikipedia.org/wiki/HKDF) return at once on every
  platform, so a Ring handler can check a webhook's signature in place.
- **Keys that travel.** A key exports as the same
  [SPKI](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#subjectpublickeyinfo),
  [PKCS#8](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#pkcs_8)
  or [JWK](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#json_web_key)
  on every platform, and the
  [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) keys that
  OpenSSL writes import too.
- **The same results everywhere.** Where the platforms disagree, the
  library refuses what any of them refuses. It passes the test vectors of
  the RFCs,
  [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
  and [Wycheproof](https://github.com/C2SP/wycheproof) on the JVM, in Node
  and in Chrome.

> This library brings together the bytes and cryptography of
> [wary-fetch](https://github.com/simongray/wary-fetch), podcast-clj and
> like-minded, which each had a copy of their own. Like them, it was
> developed with assistance from frontier LLMs.

Getting started
---------------

The library needs Clojure 1.11+ and Java 11+ (15+ for
[Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519)). In
ClojureScript it needs Node 22+ or a browser with WebCrypto. Add the latest
release from [Clojars](https://clojars.org/dk.simongray/webcrypto-clj) to
the `:deps` of your `deps.edn`:

```clojure
dk.simongray/webcrypto-clj {:mvn/version "0.1.2"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead. In shadow-cljs a Git dependency only works through
`deps.edn`, so set `:deps true` in your `shadow-cljs.edn` too.

Bytes
-----

Bytes are a byte array on the JVM and a
[Uint8Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)
in JavaScript. The
[`bytes`](src/dk/simongray/webcrypto/bytes.cljc) namespace turns them into
text and back:

```clojure
(require '[dk.simongray.webcrypto.bytes :as bytes])

(bytes/hex (bytes/encode "Blåbær"))
;; => "426cc3a562c3a672"

(bytes/base64url (bytes/of [0 1 2 250 251 252 253 254 255]))
;; => "AAEC-vv8_f7_"
```

Each encoding has a strict decoder, e.g. `bytes/from-hex`, which returns
nil for text that isn't valid. Base64 needs its padding,
[base64url](https://en.wikipedia.org/wiki/Base64#Variants) doesn't, and
neither takes whitespace. Compare secrets with `bytes/same?` and
`bytes/same-text?`, which take the same time wherever the bytes differ, so
a [timing attack](https://en.wikipedia.org/wiki/Timing_attack) learns
nothing.

Hashes and HMACs
----------------

The [`hash`](src/dk/simongray/webcrypto/hash.cljc) namespace has SHA-1,
SHA-2, HMAC and HKDF, which return their results at once on every
platform:

```clojure
(require '[dk.simongray.webcrypto.hash :as hash])

(bytes/hex (hash/digest :sha-256 (bytes/encode "abc")))
;; => "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

(bytes/hex (hash/hmac :sha-256 (bytes/encode "key")
                      (bytes/encode "The quick brown fox jumps over the lazy dog")))
;; => "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
```

Derive keys with `hash/hkdf`, or call its two steps `hash/hkdf-extract`
and `hash/hkdf-expand` yourself. In JavaScript the hashes come from the Closure
Library, since WebCrypto only returns promises. For a large file in a
browser, WebCrypto's own `webcrypto/digest` is faster.

The Web Cryptography API
------------------------

The root namespace has random bytes and the methods of
[SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto).
Each returns its result on the JVM (and a promise of it in ClojureScript).
This seals a text with
[AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) under a key
that [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) derives from a
passphrase:

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

To run the same code on both platforms, chain the calls with
`webcrypto/then`, which takes a value or a promise:

```clojure
(-> (webcrypto/import-key :raw (bytes/encode "correct horse battery staple")
                          :pbkdf2 false [:derive-key])
    (webcrypto/then #(webcrypto/derive-key pbkdf2 % {:name :aes-gcm :length 256}
                                           false [:encrypt :decrypt])))
```

An algorithm is a keyword, or a map of its `:name` and its parameters
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
and verifies with ECDSA:

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

[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
take the curves `:p-256`, `:p-384` and `:p-521`. An ECDSA signature is r
and s side by side, as in [JSON Web Tokens](https://jwt.io/introduction)
and [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).
With ECDH, `derive-bits` and `derive-key` take the other party's public
key as `:public`.

The [`pem`](src/dk/simongray/webcrypto/pem.cljc) namespace writes keys as
PEM and reads them back for `import-key`. That includes keys in OpenSSL's
traditional formats (e.g. RSA PRIVATE KEY), which WebCrypto can't import on
its own:

```clojure
(require '[dk.simongray.webcrypto.pem :as pem])

(pem/encode "PUBLIC KEY" (webcrypto/export-key :spki (:public-key key-pair)))
;; => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…"

(let [{:keys [format data]} (pem/key-data (slurp "private-key.pem"))]
  (webcrypto/import-key format data {:name :rsa-pss :hash :sha-512} false [:sign]))
```

The key data also says what kind of key it holds, e.g. `{:kind :ec
:named-curve :p-256}`, for a key whose algorithm you don't know yet.

Errors
------

A call that fails throws an ex-info (or in ClojureScript rejects with one)
whose `:type` names WebCrypto's exception, e.g. for a ciphertext that
someone changed:

```clojure
(try
  (webcrypto/decrypt aes-gcm aes-key (bytes/of (range 32)))
  (catch Exception e
    (:type (ex-data e))))
;; => :dk.simongray.webcrypto/operation-error
```

The docstring of the root namespace lists the types. The library runs the
spec's checks itself before it calls the platform, so a mistake throws the
same error everywhere. Where the platforms disagree, it refuses what any of
them refuses with `:dk.simongray.webcrypto/not-supported-error`:

- AES keys of 192 bits, which Chrome refuses
- GCM tags of 32 and 64 bits, which the JDK refuses
- [IVs](https://en.wikipedia.org/wiki/Initialization_vector) of fewer than
  12 bytes or more than 128, which Node refuses
- PBKDF2 with an empty salt, a password that isn't UTF-8 or more than
  2,147,483,647 iterations, which the JDK can't take
- RSA keys of fewer than 512 bits or more than 16,384, which the JDK
  refuses, and public exponents of more than 33 bits, which Chrome refuses
- New RSA key pairs that Chrome can't make, i.e. with a modulus that isn't
  a multiple of 128 bits from 512 to 8,192, or a public exponent other
  than 3 and 65537

Where only some platforms check a key, the library checks it on all of
them, e.g. that the numbers of an RSA private key agree. It also refuses
the weak Ed25519 public keys (those of small order) that verify forged
signatures on every platform. A key that fails a check throws data-error.

Security
--------

- Take an algorithm's parameters (e.g. the tag length, the hash, the salt
  length and the iterations) from your own configuration, never from the
  message you check.
- Never encrypt twice with the same key and IV. Random IVs of 12 bytes are
  safe for 2³² messages under one key
  ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), section
  8.3).
- A key that isn't extractable won't export, but on the JVM its material
  is in memory that any code in the JVM can reach.

Not yet
-------

- **The rest of WebCrypto:** X25519, `wrap-key` and `unwrap-key` with
  AES-KW, AES-CTR, AES-CBC, RSA-OAEP and `randomUUID`.
- **Streaming digests,** which WebCrypto doesn't have.

Principles
----------

- **Standards first.** The code follows the
  [Web Cryptography API](https://w3c.github.io/webcrypto/) (the Level 2
  Editor's Draft of 11 August 2026) and cites its sections, and those of
  the RFCs and FIPS it relies on.
- **The platform's cryptography.** The library writes no primitive that
  the platforms have. Where the JDK lacks a step (e.g. HKDF before Java
  25), the library composes it from the JDK's own primitives.
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

The fetch script downloads the test vectors of Wycheproof at a pinned
commit and NIST's vectors of GCM into `dev-resources/` (which Git ignores). NIST
doesn't version its file, so the script checks its SHA-256. Without these
files the tests check only the vectors of the RFCs.

The public namespaces are the root, `bytes`, `hash` and `pem`. The
internal ones are under `impl`:

- `impl.algorithms`, the algorithms and the normalization of their
  parameters
- `impl.keys` and `impl.jwk`, keys and their JWKs
- `impl.der`, the [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding)
  of SPKI, PKCS#8 and the keys inside them
- `impl.hmac`, `impl.aes-gcm`, `impl.kdf`, `impl.ec`, `impl.rsa` and
  `impl.ed25519`, the operations of each algorithm on each platform
- `impl.subtle`, the calls of WebCrypto in JavaScript
- `impl.errors`, `impl.async` and `impl.random`, the errors, the promises
  and the random bytes

License
-------

The webcrypto-clj project is licensed under the [MIT licence](LICENSE).
