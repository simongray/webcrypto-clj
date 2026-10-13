webcrypto-clj: a proposal
=========================

This is a proposal for webcrypto-clj, a Clojure and ClojureScript library
for bytes, their encodings and the cryptography that the dk.simongray
libraries need. Its coordinate would be `dk.simongray/webcrypto-clj` and its
root namespace `dk.simongray.webcrypto`. Its API follows the W3C's
[Web Cryptography API](https://w3c.github.io/webcrypto/) (the Level 2
Editor's Draft of 11 August 2026). It uses each platform's own
cryptography: the JCA on the JVM, and WebCrypto in browsers and Node.

Today three libraries each carry a bytes namespace of their own. The copies
in wary-fetch and podcast-clj hash and sign, and like-minded's encrypts.
They mostly agree, but not always, e.g. like-minded's `decode` keeps a byte
order mark that wary-fetch's drops in JavaScript. Two libraries to come,
httpsig-clj and one for Web Push, will also need keys, signatures and key
agreement, which none of them has.

The library follows whatwg-url as a spec library: one `.cljc` codebase,
the spec's section beside each rule, small named functions for the steps
of each algorithm, and errors as data. The first release is built and
tested in this repository.


What it replaces
----------------

- **wary-fetch**, `bytes.cljc`: bytes as a byte array on the JVM and a
  Uint8Array in JavaScript, UTF-8, base64, base64url and `unbase64url`,
  hex, random bytes, comparisons in constant time (`same?` and
  `same-text?`), and digests and HMACs by SHA-1 and SHA-2. The hashes are
  synchronous everywhere and come from the Closure Library in JavaScript.
  Its callers are websub-clj, indieauth-clj, relmeauth-clj,
  webmention-clj, micropub-clj and wary-fetch itself.
- **podcast-clj**, `util/bytes.cljc`: the same functions, plus `from-hex`,
  `from-base64`, `join`, `copy` and `at`, data URLs, decoding of Latin-1
  and UTF-16, a check for UTF-8 and the signatures of image formats. It
  has no HKDF. Instead, NIP-44 writes HKDF's extract and expand steps by
  hand on top of `bytes/hmac`. In ClojureScript, the integrity check of a
  download hashes with WebCrypto rather than the Closure Library, since
  WebCrypto digests a large file faster. The server compares passwords
  with `MessageDigest/isEqual`.
- **like-minded**, `bytes.cljc` and `aes_gcm.cljc`: a smaller copy of the
  bytes, and AES-256-GCM under a key that PBKDF2-HMAC-SHA256 derives from a
  passphrase. It uses javax.crypto on the JVM and WebCrypto in
  ClojureScript, where each function returns a promise. Its encrypted
  store seals each document in an EDN envelope with the salt, IV and
  iteration count that open it.

A search through the other projects found these:

- Both websub-clj and indieauth-clj have a public `token`, the base64url
  of 32 random bytes, and the `state` namespace of indieauth-clj has a
  private `random-text` that does the same.
- The blog hashes the URLs of avatars with `MessageDigest` and writes the
  hex by hand.
- Four libraries read a Ring body into bytes up to a limit: websub-clj,
  indieauth-clj, webmention-clj and micropub-clj. That isn't cryptography,
  so it stays out (see [Nice to have](#nice-to-have)).
- The cache of corpus-probe names its files by MD5, which WebCrypto
  doesn't have. It stays as it is.

No other library compares secrets, so `same?` and podcast-clj's
`isEqual` are the only comparisons in constant time.


Sync or async
-------------

**Bytes, hashes, HMACs and HKDF are synchronous on every platform. The API
of WebCrypto, which takes keys, returns a value on the JVM and a promise in
ClojureScript.** That puts the synchronous functions in the `bytes` and
`hash` namespaces, and the WebCrypto API in the root namespace. Random
bytes are synchronous too, as `crypto.getRandomValues` is.

The callers need it this way:

- **In websub-clj,** the callback handler verifies the X-Hub-Signature of
  a delivery, and it's a synchronous Ring handler. The hub signs each
  delivery while it builds the request. An asynchronous HMAC would make the
  handler return a promise in ClojureScript, which only the asynchronous
  arity of a Ring handler can do.
- **In indieauth-clj,** `digest.cljc` hashes PKCE verifiers and tokens with
  SHA-256, and `signed.cljc` signs the state with HMAC. Both run inside
  handlers and in the keys of its stores. The handler of relmeauth-clj
  compares a state too.
- **In podcast-clj,** NIP-44 runs HKDF, HMAC and its own ChaCha20
  synchronously. The secp256k1 code hashes with SHA-256 in the middle of a
  BIP-340 signature, and the feed GUIDs are UUIDs of version 5, which hash
  with SHA-1.
- **In like-minded,** AES-GCM and PBKDF2 already return a value on the JVM
  and a promise in ClojureScript, and they still would.
- **The proposal of httpsig-clj** makes the same split. Its signatures
  return promises in ClojureScript, while the components, the signature
  base and the digests stay synchronous.

One asynchronous API everywhere would turn each of those handlers and all
of NIP-44 into promises, and it would gain nothing on the JVM. Node's
`node:crypto` is synchronous for everything, but using it would make Node
behave unlike a browser, and the code would need a build of its own for
Node. The proposal of httpsig-clj turns it down for the same reasons.

In JavaScript the synchronous hashes come from the Closure Library, as they
do in wary-fetch today. They're slower than the platform's native code, so
the root namespace has WebCrypto's `digest` as well, e.g. for podcast-clj's
large downloads. They also work on a page served over plain http, where a
browser has no `crypto.subtle`.

The JDK has no HKDF before Java 25 (javax.crypto.KDF), and WebCrypto's HKDF
only comes as a promise. So the `hash` namespace composes the two steps of
RFC 5869 from the platform's HMAC, which is also what NIP-44 needs, since
it calls the steps separately. In ClojureScript the root namespace's
`derive-bits` uses WebCrypto's HKDF, and the tests check each against the
other.

PBKDF2 stays asynchronous. Its iterations are slow by design, so a page
shouldn't run them on its main thread, and the Closure Library only has
PBKDF2 with SHA-1.


Namespaces
----------

| Namespace | What it holds |
|---|---|
| `webcrypto` | The Web Cryptography API: random bytes, and the methods of SubtleCrypto for keys, digests, signatures, encryption and key derivation |
| `webcrypto.bytes` | Bytes on both platforms: concatenation, slices, comparison in constant time, UTF-8, hex, base64 and base64url |
| `webcrypto.hash` | SHA-1 and SHA-2, HMAC and HKDF, synchronously |
| `webcrypto.pem` | Keys in PEM, and the PKCS#1 and SEC1 keys of OpenSSL as SPKI and PKCS#8 |
| `webcrypto.impl.*` | `^:no-doc`: the normalization of algorithms, keys, the DER of keys, each algorithm's operations and the calls of WebCrypto |

The byte encodings go in `bytes`, as planned. The synchronous hashes get a
namespace of their own rather than going into `bytes` or the root. That
keeps `bytes` free of cryptography, and the namespace tells a reader which
calls are synchronous.

```clojure
(require '[dk.simongray.webcrypto :as webcrypto]
         '[dk.simongray.webcrypto.bytes :as bytes]
         '[dk.simongray.webcrypto.hash :as hash])

(bytes/hex (hash/digest :sha-256 (bytes/encode "abc")))
;; => "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

(bytes/base64url (webcrypto/random-bytes 32))
;; => e.g. "FJA48XVJXdFW1p3wpBbks_Xi0fLxncXrFQN61bYJJ-w"
```

The `bytes` namespace has `bytes?`, `of`, `length`, `at`, `concat`, `slice`,
`same?`, `same-text?`, `encode` and `decode` (UTF-8), and pairs like `hex`
and `from-hex` for each encoding. The names are those that the copies
share, except that wary-fetch's `unbase64url` becomes `from-base64url` to
match podcast-clj's other decoders. The `hash` namespace has `digest`,
`hmac`, `hkdf`, `hkdf-extract` and `hkdf-expand`, whose arguments come in
the order of Node's `createHmac` and `hkdfSync`.

The root namespace has the methods of SubtleCrypto under their names in
kebab case, with their arguments in the same order, so an example on MDN
translates line by line:

```clojure
(def aes-key
  (webcrypto/generate-key {:name :aes-gcm :length 256} false [:encrypt :decrypt]))

(def iv
  (webcrypto/random-bytes 12))

(webcrypto/encrypt {:name :aes-gcm :iv iv} aes-key (bytes/encode "a secret"))
```

On the JVM, `aes-key` is a key and `encrypt` returns bytes. In
ClojureScript both are promises. The library's own `then` chains them the
same way on both platforms, as wary-fetch's `async/then` does, so a caller
needs no wary-fetch for it.


Keys and algorithms
-------------------

- **A key is the platform's own in ClojureScript,** a CryptoKey. A page can
  then keep an unextractable key in IndexedDB, as the proposal of
  httpsig-clj wants. On the JVM it's a type of the library's own with the
  same four attributes and the key material, which it doesn't print. Use
  `key-info` for its attributes as data, on both platforms:

  ```clojure
  (webcrypto/key-info aes-key)
  ;; => {:type :secret :extractable? false
  ;;     :algorithm {:name :aes-gcm :length 256} :usages #{:encrypt :decrypt}}
  ```

- **Algorithms are keywords,** the WebCrypto names in lower case (e.g.
  `:aes-gcm` and `:sha-256`), or maps of a `:name` and the members of the
  algorithm's dictionary in kebab case (e.g. `:additional-data` and
  `:tag-length`). Usages and formats are keywords too (e.g. `:derive-key`
  and `:raw`). A JWK is a map of its JSON members as keywords, e.g.
  `:kty` and `:key_ops`, since it's JSON and should go back to JSON
  unchanged.
- **A key pair is a map** of `:public-key` and `:private-key`, as
  WebCrypto's CryptoKeyPair has them.
- **The first release imports and exports secret keys** for HMAC and
  AES-GCM as raw bytes and as JWK, and imports passwords and keying
  material for PBKDF2 and HKDF as raw bytes. It imports and exports key
  pairs as SPKI, PKCS#8 and JWK, and the public keys of EC and Ed25519 as
  raw bytes too.
- **Each format is built from the key's numbers** on both platforms, so it's
  the same bytes or the same map everywhere. A JWK of a secret key comes
  from its raw bytes, and the DER of a key pair from its numbers, its
  coordinates or its seed. The PKCS#8 of an EC key holds the public key but
  not the curve in its ECPrivateKey, as Chrome and Node write it, where the
  JDK writes neither.


Errors
------

WebCrypto rejects with a DOMException whose name says what went wrong,
e.g. NotSupportedError or OperationError. The library throws an ex-info
with that name as its `:type`, a keyword in the root namespace, e.g.
`:dk.simongray.webcrypto/operation-error`. In ClojureScript the promise
rejects with it. The library translates the platforms' own exceptions into
these, e.g. the JDK's AEADBadTagException for a changed ciphertext.

The library runs the checks of the spec's steps itself before it calls the
platform: the normalization of the algorithm, the key's algorithm and
usages, and the ranges of the parameters. So a mistake gets the same error
everywhere, with a message that says which check failed.

The decoders of `bytes` return nil for text that isn't valid, as the copies
do today. A signature that doesn't match makes `verify` return false, as in
WebCrypto.


The same results everywhere
---------------------------

Like whatwg-url, the library relies on the platform only where every
platform gives the same answer. Where the platforms differ, it refuses what
any of them refuses with not-supported-error, so code that works in one
place works in all of them:

- **AES keys of 192 bits.** Chrome refuses them, while the JDK and Node
  take them.
- **GCM tags of 32 and 64 bits.** The JDK only takes tags of 96 to 128
  bits. NIST SP 800-38D (Appendix C) restricts the short tags too.
- **GCM IVs of fewer than 12 bytes or more than 128.** WebCrypto in Node
  refuses them, although the JDK takes any IV of a byte or more. NIST
  recommends IVs of 12 bytes anyway. An empty IV is an operation-error, as
  in the spec.
- **PBKDF2 with an empty salt.** The JDK refuses it.
- **PBKDF2 with a password that isn't UTF-8.** The JDK's PBKDF2 takes the
  password as characters and encodes them as UTF-8, so it can't take other
  bytes. Wycheproof's NonUtf8 vectors check that every platform refuses
  them.
- **HMAC keys whose length in bits isn't a whole number of bytes.** Neither
  the JDK nor Node can make one.
- **New RSA key pairs other than Chrome's.** Chrome makes moduli of a
  multiple of 128 bits from 512 to 8,192, with the public exponent 3 or
  65537, while the JDK and Node make others too.
- **RSA keys of fewer than 512 bits or more than 16,384.** The JDK refuses
  them.
- **RSA public exponents of more than 33 bits.** Chrome refuses them, and
  the JDK refuses those of more than 64 bits for moduli of more than 3,072.
- **PBKDF2 with more than 2,147,483,647 iterations or bits.** The JDK takes
  both as an int.

The checks of keys and signatures that only some platforms make run on
every platform, so that a key or a signature that one refuses fails
everywhere:

- **RSA keys.** Chrome checks that the modulus and the public exponent are
  odd, that the exponent is more than 1, that rsaEncryption has NULL
  parameters, and that the numbers of a private key agree. Node checks none
  of these, and the JDK some. Each is a data-error, as in Chrome.
- **Ed25519 keys and signatures of small order.** WebCrypto (section
  25.3.2) has verify return false for a public key or an R of small order,
  but neither the JDK, Node nor Chrome checks. So with the identity as the
  key and as R, and S of zero, a signature verifies for any message. The
  library returns false for an R of small order. It refuses a key of small
  order on import with data-error, since in JavaScript a public key that
  isn't extractable can't be read when it verifies.
- **ECDSA signatures.** The JDK splits a signature of any size in two, and
  Wycheproof found it verifying some of the wrong size, which the spec says
  are false. JDK 15 to 18 also verified r and s of zero (CVE-2022-21449).
  So the library checks the size, and that r and s are from 1 to the
  curve's order minus 1.
- **RSA-PSS salts that don't fit the key.** RFC 8017 makes them an error,
  where the JDK threw an exception of its own for a salt longer than an
  int. So a signature fails with operation-error and a verification is
  false.

A few differences need no refusal:

- **An empty HMAC key in `hash/hmac`.** RFC 2104 allows it, but the JDK's
  SecretKeySpec doesn't. The library passes a single zero byte instead,
  which HMAC pads to the same block, so the HMAC is the same. WebCrypto's
  `import-key` refuses an empty key with data-error on every platform, as
  the spec says.
- **UTF-8.** On the JVM, `bytes/encode` turns a lone surrogate into
  U+FFFD as TextEncoder does, where the JDK alone would write a question
  mark. Decoding keeps a byte order mark on both platforms. Invalid UTF-8
  can still decode to a different number of U+FFFD (the JDK reads the bytes
  ED A0 80 as one character where JavaScript reads three). As in
  whatwg-mime, that difference stays.
- **Base64.** The decoders are strict on both platforms. They take only
  the alphabet, the padding where RFC 4648 asks for it, and pad bits of
  zero (section 3.5), so no two texts decode to the same bytes. Both the
  JDK and `atob` accept pad bits that aren't zero, and `atob` also
  skips whitespace.
- **The order of `key_ops` in an exported JWK.** Node keeps the order that
  the caller gave, so the library sorts it in the spec's order.
- **EC points and private keys on the JVM.** The JDK neither checks that a
  point is on its curve nor computes the public key of a private key,
  which WebCrypto does on import. So the library checks the curve's
  equation, and finds the public key by ECDH with the curve's generator,
  which gives x, and a signature, which tells which of the two y it is.
- **Ed25519 seeds on the JVM.** The JDK can't compute the public key of a
  seed either, so the library generates the key pair from a source of
  randomness that returns the seed. It checks that the key pair has the
  seed, which a JDK of a hardware module might not take.


Input from strangers
--------------------

Keys, signatures and PEM often come from strangers, e.g. the public key of
an actor that httpsig-clj fetches. So the decoders of base64 and PEM run in
linear time, as no regex of theirs backtracks, and the DER reader refuses
values nested deeper than any key's, which would overflow the stack.
Malformed input should throw the library's own errors, which a caller
catches, rather than an exception of the platform.

The library can't guard the parameters of an algorithm, so the callers
have to: a tag length, a hash, a salt length or a number of iterations
comes from their own configuration, never from the message they check.


Platforms
---------

- **Clojure 1.11 and Java 11 or later.** Java 11 lacks HexFormat (Java 17),
  Ed25519 (Java 15) and HKDF (Java 25), so hex and HKDF are a few lines of
  the library's own on the JVM.
- **Node 22 or later.** Node 20 reached its end of life in April 2026, and
  Node 22 has `globalThis.crypto` and stable Ed25519.
- **Any browser with WebCrypto.** Browsers only have `crypto.subtle` in a
  secure context (https or localhost). On a page served over plain http,
  `bytes`, `hash` and `random-bytes` still work, and the rest of the root
  namespace rejects with not-supported-error and a message that says why.
- **The Closure Library,** for the synchronous hashes in JavaScript. Google
  archived it in 2024, and ClojureScript ships a copy of its own. If that
  copy ever loses `goog.crypt`, the library would port SHA-1, SHA-2 and
  HMAC to `.cljc` rather than take an npm dependency.
- **The CI of whatwg-url:** Java 25 and Node 24, a job on Java 11, and the
  Node tests again with advanced compilation. A browser test build runs by
  hand, as websub-clj's does.


The first release
-----------------

Version 0.1.0 has bytes and RFC 4648's encodings, random bytes, SHA-1 and
SHA-2, HMAC, HKDF, PBKDF2, AES-GCM, ECDSA, RSASSA-PKCS1-v1_5, RSA-PSS,
Ed25519 and ECDH, with WebCrypto's key API and PEM. It passes its tests on
Java 11 and Java 24, in Node 24 (also compiled with advanced
optimizations) and in Chrome 152. Each runs the same assertions, except
that Java 11 checks that the library refuses Ed25519 instead of running
its vectors.

Signatures, ECDH and the formats of key pairs were planned for 0.2.0, but
Simon chose one fuller release over several small ones. So httpsig-clj and
a library for Web Push can start out on the first release.


Signatures, ECDH and key formats
--------------------------------

These are the decisions for httpsig-clj and Web Push:

- **ECDSA signatures are raw on every platform:** r and s side by side, as
  in WebCrypto, JOSE (RFC 7518, section 3.4) and RFC 9421. The JDK's
  `SHA256withECDSAinP1363Format` and `SHA384withECDSAinP1363Format` produce
  that format directly, and Java 11's SunEC has them (checked on 11.0.32).
  So no platform needs a DER conversion. Only a format that wants DER
  signatures, e.g. X.509, would need one.
- **Ed25519 needs Java 15** (JEP 339). The library keeps Java 11 as its
  floor and checks at runtime whether the JDK has Ed25519. On Java 11 to 14
  its functions throw not-supported-error. Browsers have it since Chrome
  137, Firefox 129 and Safari 17. Node has had it since 16.17, and it's
  stable since 22.13 and 23.5.
- **X25519 is in Java 11** (JEP 324), Chrome 133, Firefox 130, Safari 17
  and Node 22.13. Neither httpsig-clj nor Web Push needs it, so it waits.
- **RSASSA-PKCS1-v1_5, RSA-PSS and ECDH on P-256** are all in Java 11
  (`SHA256withRSA`, `RSASSA-PSS` and `ECDH`).
- **Key formats.** The library reads and writes the DER of SPKI and PKCS#8
  itself (`impl.der`), so that a key exports the same bytes everywhere. On
  the JVM it makes the JDK's keys from their parts: RSA keys from their
  numbers, EC keys from their coordinates and the curve's parameters, and
  Ed25519 keys from their raw bytes. The raw format of an EC public key is
  the uncompressed point, 65 bytes on P-256, and each platform also
  imports a compressed one.
- **PEM, PKCS#1 and SEC1 go in a `pem` namespace.** PEM (RFC 7468) is
  base64 under a label, and Mastodon publishes its keys as PEM. PKCS#1 and
  SEC1 ("RSA PRIVATE KEY" and "EC PRIVATE KEY") aren't formats of
  WebCrypto, and neither platform imports them. The namespace reads and
  writes PEM and rewraps PKCS#1 and SEC1 as PKCS#8 and SPKI, which only
  rewrites DER, so `import-key` keeps to WebCrypto's formats. It also
  rewraps a key of RSASSA-PSS (RFC 4055) as one of rsaEncryption, which is
  what WebCrypto imports, e.g. the RSA-PSS key of RFC 9421. Since the
  library has `impl.der`, httpsig-clj needs no DER code of its own.

Web Push (RFC 8291 and RFC 8292) needs only these. It makes an ECDH key
pair on P-256 for each message, imports the subscription's public key
(raw, 65 bytes), runs HKDF twice and encrypts with AES-128-GCM in the
records of RFC 8188. It signs its VAPID token with ECDSA on P-256 (ES256),
whose JWT takes the raw signature that WebCrypto gives.


httpsig-clj
-----------

Its proposal and this one agree on these points:

- **The same split.** Hashes and HMACs are synchronous, and anything with
  a key returns a promise in ClojureScript. Both use WebCrypto in Node
  rather than `node:crypto`.
- **Its cryptography would come from webcrypto-clj:** hashes, HMACs,
  comparisons in constant time, keys and signatures, and the PEM and DER of
  its keys. It would take only the `async` helpers, the hidden texts and
  the sender from wary-fetch. Its section "Crypto on each platform" becomes
  calls to `sign` and `verify`, e.g. `{:name :rsa-pss :salt-length 64}`
  for rsa-pss-sha512 and `{:name :ecdsa :hash :sha-256}` for
  ecdsa-p256-sha256.
- **No conversion of ECDSA signatures,** as both proposals found.
- **A page over plain http has no WebCrypto,** and the error says so.
- **The `:key` of an httpsig-clj key map** is a key of webcrypto-clj, which
  in ClojureScript is the CryptoKey that a page keeps.

One point differs. The proposal of httpsig-clj moves its floor to Java 17
for Ed25519, while webcrypto-clj keeps Java 11 and refuses Ed25519 below
Java 15. Each library can then choose its own floor.


Tests
-----

The tests use the published vectors:

- RFC 4648, section 10, for hex and base64, and the same strings in
  base64url
- the examples of FIPS 180-4 for SHA-1 and SHA-2
- RFC 2202 for HMAC-SHA-1, and RFC 4231 for HMAC-SHA-2
- RFC 5869, Appendix A, for HKDF
- RFC 6070 and RFC 7914, section 11, for PBKDF2 (except RFC 6070's
  16,777,216 iterations, which take too long for every run)
- the test cases 3 and 4 of the GCM specification, which NIST published
  with SP 800-38D
- NIST's GCM vectors from the CAVP (gcmtestvectors.zip), for keys of 128
  and 256 bits
- RFC 8032, section 7.1, for Ed25519
- RFC 9421's keys in PEM, and its signatures with them by
  RSASSA-PKCS1-v1_5 (section 4.3), RSA-PSS, ECDSA and Ed25519 (Appendix
  B.2)
- Wycheproof at commit 7a32593 of 12 October 2026: AES-GCM, HMAC with SHA-1
  and SHA-2, HKDF, PBKDF2, ECDSA on each curve, ECDH on each curve with
  JWKs, RSASSA-PKCS1-v1_5 (signing and verifying), RSA-PSS and Ed25519

The RFC vectors are short, so they're in the tests with their sections. As
whatwg-url does with the data of web-platform-tests, `dev/fetch.sh`
downloads Wycheproof at its commit and NIST's file into `dev-resources/`,
which Git ignores. NIST doesn't version the file, so the script checks its
SHA-256. A vector that the library refuses on purpose, e.g. one with an AES
key of 192 bits, has to be refused with not-supported-error.

Beyond the vectors:

- **Each platform opens what the other seals.** The tests hold a
  ciphertext that the library sealed on the JVM and one that WebCrypto
  sealed in Node, and each platform opens both and seals them again to
  the same bytes. They also open an envelope that like-minded 0.2.0's own
  code sealed, so like-minded's documents still open after it adopts the
  library.
- **Each platform takes the other's key pairs.** The tests hold key pairs
  and signatures that the library made on the JVM and WebCrypto made in
  Node. Each platform imports both, exports the same SPKI, PKCS#8 and JWK,
  verifies the signatures, and signs again to the same bytes where the
  algorithm always does. ECDH between the two key pairs derives the same
  secret both ways.
- **The synchronous hashes against WebCrypto.** In ClojureScript, the
  tests check that `hash` gives what the root namespace's `digest`, `sign`
  and `derive-bits` give, for random inputs.
- **The same errors.** The tests check the `:type` of each refusal above,
  and of the spec's own errors, on every platform.
- **A browser.** The browser test build reads the vectors over HTTP, so
  the whole suite runs in a browser too.


Adoption
--------

The first to adopt it is wary-fetch, since most of the libraries take its
`bytes` namespace. Its callers follow in any order: websub-clj,
indieauth-clj, relmeauth-clj, webmention-clj and micropub-clj. Next come
like-minded and then podcast-clj, which takes wary-fetch and websub-clj,
and last the blog. The new httpsig-clj starts out on webcrypto-clj.

### wary-fetch

- **Deletes** `bytes.cljc` and its test.
- **Changes** the namespaces that use it to require `webcrypto.bytes`: the
  base64 of basic authentication, the empty bodies and lengths of range
  requests, and the bodies of the proxy. The README's pointer to its
  `bytes` namespace points to webcrypto-clj instead.
- **Keeps** `digest!`, which streams a body through MessageDigest on the
  JVM. WebCrypto has no streaming digest.

### websub-clj

- Its `token` returns `(bytes/base64url (webcrypto/random-bytes n))`.
- In `algorithms`, each signature method maps to `:sha-1`, `:sha-256`,
  `:sha-384` or `:sha-512`.
- Its `signature` returns `(bytes/hex (hash/hmac algorithm k body))`, and
  `signed?` still compares with `bytes/same?`.
- The hub, `document` and `ring` take `encode`, `decode`, `length`,
  `base64url` and `from-base64url` from `webcrypto.bytes`.

### indieauth-clj

- Its `digest/text` becomes `(bytes/base64url (hash/digest :sha-256
  (bytes/encode s)))`.
- In `signed.cljc`, it signs with `(hash/hmac :sha-256 k message)`,
  decodes with `bytes/from-base64url` and compares with `bytes/same?`.
- Its `token` and `state/random-text` take `webcrypto/random-bytes`.
- The root namespace, `endpoint`, `grant` and `state` take `same-text?`
  from `webcrypto.bytes`, and `ring` takes `encode`, `decode` and `length`.

### relmeauth-clj, webmention-clj and micropub-clj

The one change in relmeauth-clj is `same-text?` from `webcrypto.bytes`.
Both webmention-clj and micropub-clj take `encode`, `decode` and `length`
for their Ring bodies.

### like-minded

- **Deletes** `aes_gcm.cljc` and its test, and all of `bytes.cljc` but `as`.
- **Changes** its encrypted store to derive its key with `import-key` (the
  passphrase as raw bytes, for PBKDF2) and `derive-key` (PBKDF2 with
  SHA-256 to AES-GCM of 256 bits), and to seal and open with `encrypt` and
  `decrypt`. A passphrase that doesn't open a document throws
  operation-error, which `locked` wraps as it does now. The `opened`
  function in `interop_test.cljc` is the whole of it.
- **Keeps** the envelope and the cache of keys as they are. Keys are
  CryptoKeys on both platforms, so the cache holds the same kind of value
  everywhere.

### podcast-clj

- **Deletes** from `util/bytes.cljc` everything that webcrypto-clj has:
  hex, base64 and base64url both ways, the digests, `sha1`, `sha256`,
  `hmac`, `generate!`, `join`, `copy`, `same?`, `encode`, `length`, `of`
  and `at`.
- **Keeps** in `util/bytes.cljc` what's about formats rather than bytes:
  `decode` with Latin-1 and UTF-16, data URLs, `as`, `utf8?` and
  `image-type`. Its forgiving base64 strips whitespace and then calls
  `bytes/from-base64`.
- **Changes** NIP-44's `extracted` and `expanded` to `hash/hkdf-extract`
  and `hash/hkdf-expand`, and its slices to `bytes/slice`. For secp256k1,
  the GUIDs and the Podcast Index it takes `hash/digest`, and for NWC and
  gpodder `webcrypto/random-bytes`. In ClojureScript, the integrity check
  hashes with the root namespace's `digest`. The server compares passwords
  with `bytes/same?`.
- **Keeps** ChaCha20, NIP-44 and secp256k1 in podcast-clj. WebCrypto has
  neither ChaCha20 nor secp256k1.

### The blog

Its `sha256-hex` becomes `(bytes/hex (hash/digest :sha-256 (bytes/encode
s)))`.


Nice to have
------------

- **A `random-uuid`** from `crypto.randomUUID`, since ClojureScript's own
  uses Math.random.
- **Streaming digests on the JVM,** if wary-fetch's `digest!` should move
  here. WebCrypto has none, so it would be a JVM-only function.
- **The platforms' own hex and base64,** once they're everywhere:
  `Uint8Array.fromBase64` and its siblings (in Chrome 140, Firefox 133,
  Safari 18.2 and Node 25, but not in Node 22 or 24), HexFormat when the
  floor reaches Java 17, and javax.crypto.KDF for HKDF at Java 25.
- **One Ring helper for request bodies,** for the four copies that read a
  body into bytes up to a limit. It belongs in wary-fetch or a library of
  Ring helpers rather than here.
- **The rest of WebCrypto:** X25519, AES-KW for `wrap-key` and
  `unwrap-key`, AES-CTR, AES-CBC and RSA-OAEP. No library needs them yet.


Questions for Simon
-------------------

Simon decided each of these on 13 October 2026.

1. **The Java floor.** Should all the libraries move to Java 17 now? No:
   webcrypto-clj keeps Java 11 and checks for Ed25519 at runtime. All the
   libraries move to Java 17 together, once Clojure itself requires it.
2. **Refusing what one platform refuses.** Should the library refuse
   AES-192, short GCM tags, IVs outside 12 to 128 bytes, empty PBKDF2 salts
   and PBKDF2 passwords that aren't UTF-8 on every platform? Yes, since the
   point of the library is the same results everywhere. NIST discourages
   the short tags and IVs, and the rest are rare in practice.
3. **Invalid UTF-8.** Should the JVM decode invalid UTF-8 exactly as
   browsers do? No, the platform's decoder is good enough, as in
   whatwg-mime. Only the number of U+FFFD differs. If it ever matters,
   whatwg-url has a decoder of the Encoding Standard.
4. **The `bytes` of wary-fetch.** Should wary-fetch keep it for a release
   as a namespace that calls webcrypto-clj? No, wary-fetch deletes it in
   its next release. Every caller is one of these libraries, each pins its
   version of wary-fetch, and such a namespace would have to translate the
   names that changed.
5. **PKCS#1 and SEC1.** Should webcrypto-clj import these PEM keys,
   although WebCrypto doesn't? Yes, but in a `pem` namespace of its own
   rather than in `import-key`, which keeps to WebCrypto's formats. It
   reads and writes PEM and rewraps PKCS#1 and SEC1 as PKCS#8 and SPKI,
   which only rewrites DER. The `impl.der` of httpsig-clj's proposal moves
   here.
6. **Names.** Do `hash`, `same?`, and `encode` and `decode` for UTF-8 still
   read well? Yes, they stay. They're the names that the copies share, and
   `encode` and `decode` are those of TextEncoder and TextDecoder.
7. **Algorithm names as strings.** Should the library also take
   WebCrypto's strings, e.g. "SHA-256"? No, keywords only, so each
   algorithm has one spelling. Either way, httpsig-clj needs a table from
   RFC 9421's names.
8. **Chaining in `.cljc`.** Should webcrypto-clj have a `then` of its own,
   so that a caller needs no wary-fetch to chain its results? Yes, and only
   that: `webcrypto/then` takes a value or a promise. The libraries that
   take wary-fetch can keep its `async` namespace for the rest.
9. **The Closure Library.** If ClojureScript ever drops `goog.crypt`, where
   do the synchronous hashes come from? The library would port SHA-1, SHA-2
   and HMAC to `.cljc` rather than take an npm dependency, since browsers
   have no synchronous hash of their own. Until then, it takes the risk.
