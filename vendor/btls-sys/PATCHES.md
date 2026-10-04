# How this copy differs from btls-sys 0.5.6 on crates.io

One change: **BoringSSL knows Chrome's post-quantum signature algorithms**.

Chrome 151 advertises three ML-DSA entries first in `signature_algorithms`
(`0x0904`, `0x0905`, `0x0906`, i.e. ML-DSA-44/65/87), followed by the usual
eight. The BoringSSL in this build did not know them: `set_sigalg_prefs`
rejects a code point that has no entry in `kSignatureAlgorithms`, so the third
JA4 part (extensions + signatures) matched no real browser. Cloudflare reads
JA4 on every request.

Two files changed:

- `deps/boringssl/include/openssl/ssl.h`: declares `SSL_SIGN_MLDSA44`,
  `SSL_SIGN_MLDSA65`, `SSL_SIGN_MLDSA87`.
- `deps/boringssl/ssl/ssl_privkey.cc`: names `mldsa44`/`mldsa65`/`mldsa87` in
  `kSignatureAlgorithmNames` (used to map names to code points when the list
  is given as a string), and lets these three through `set_sigalg_prefs`.

**Signing or verifying with them is not possible.** They have no
`kSignatureAlgorithms` entry, so `ssl_pkey_supports_algorithm` returns false,
and a server that picks ML-DSA gets `SSL_R_WRONG_SIGNATURE_TYPE`; the handshake
fails. That is intended: Chrome only advertises these too, and no certificates
use them yet.

One-line check: `tls.peet.ws` must return the same JA4 as Chrome on this
machine:

```
nokk --load https://tls.peet.ws/api/all --eval \
  "fetch('https://tls.peet.ws/api/all').then(r=>r.json()).then(d=>d.tls.ja4)"
# t13d1517h2_8daaf6152771_a87ad97598a9
```

The copy is wired in via `[patch.crates-io]` in the root `Cargo.toml`. Once
btls-sys upstream gains ML-DSA, the patch and this copy can be dropped.
