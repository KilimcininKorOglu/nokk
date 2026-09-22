# Чем эта копия отличается от btls-sys 0.5.6 с crates.io

Одним: **BoringSSL знает постквантовые подписи Chrome**.

Chrome 151 объявляет в `signature_algorithms` три ML-DSA первыми —
`0x0904`, `0x0905`, `0x0906` (ML-DSA-44/65/87), а дальше обычные восемь.
BoringSSL из этой сборки про них не знал: `set_sigalg_prefs` отвергает кодовую
точку, для которой нет записи в `kSignatureAlgorithms`, — и третий кусок JA4
(расширения + подписи) у нас не совпадал ни с одним настоящим браузером.
Cloudflare читает JA4 на каждом запросе.

Изменено два файла:

- `deps/boringssl/include/openssl/ssl.h` — объявлены `SSL_SIGN_MLDSA44`,
  `SSL_SIGN_MLDSA65`, `SSL_SIGN_MLDSA87`.
- `deps/boringssl/ssl/ssl_privkey.cc` — имена `mldsa44`/`mldsa65`/`mldsa87` в
  `kSignatureAlgorithmNames` (по ним имя переводится в кодовую точку, когда
  список задают строкой) и пропуск этих трёх в `set_sigalg_prefs`.

**Подписать или проверить такой подписью нельзя.** Записи в
`kSignatureAlgorithms` у них нет, поэтому `ssl_pkey_supports_algorithm`
отвечает «нет», и сервер, выбравший ML-DSA, получит
`SSL_R_WRONG_SIGNATURE_TYPE` — рукопожатие не состоится. Так и надо: у Chrome
эти точки тоже только объявлены, сертификатов с ними пока не выдают.

Проверяется одной строкой — `tls.peet.ws` должен отдать тот же JA4, что и
Chrome на этой машине:

```
nokk --load https://tls.peet.ws/api/all --eval \
  "fetch('https://tls.peet.ws/api/all').then(r=>r.json()).then(d=>d.tls.ja4)"
# t13d1517h2_8daaf6152771_a87ad97598a9
```

Копия подключена через `[patch.crates-io]` в корневом `Cargo.toml`. Когда
ML-DSA появится в btls-sys наверху, заплатку и копию можно выбросить.
