# ICU data: why `Intl` is not browser-like without it

The prebuilt V8 the engine runs on contains all of ICU but **no data**: without
`icudtl.dat` any `Intl` call aborts the process. So the stealth layer replaced
`Intl` and locale date formatting with a stub.

The stub answers differently from a browser, and visibly so:

| query | stub | Chrome |
|---|---|---|
| `new Intl.NumberFormat('de-DE',{style:'currency',currency:'EUR'}).format(1234.5)` | `1234.5` | `1.234,50 €` |
| `new Intl.PluralRules('ru').select(2)` | `other` | `few` |
| `new Intl.RelativeTimeFormat('en').format(-1,'day')` | `-1 day` | `1 day ago` |
| `(1234.5678).toLocaleString()` | `1234.5678` | `1,234.568` |
| `'a'.localeCompare('B')` | `1` | `-1` |
| `[...new Intl.Segmenter('en',{granularity:'word'}).segment('a b')].length` | `1` | `3` |
| `Intl.DateTimeFormat().resolvedOptions()` | four fields | all |

Of the twenty-two checks a fingerprinting script typically runs, twenty
differed from Chrome, and fourteen of them are fixed by this one file.

## Providing the data

Put `icudtl.dat` next to the binary, or point to it:

```
NOKK_ICU_DATA=/path/to/icudtl.dat nokk --load https://example.com
```

The engine logs `ICU data loaded` and steps aside: native `Intl` answers from
then on. Without the file the stub stays: it works, but is wrong on locales.

## Which file

**ICU 74.** The binding calls `udata_setCommonData_74`; data of another version
is accepted, but every call then throws `TypeError: Internal error. Icu
error.` Verified here: files from Electron builds of that era
(~10,467,680 bytes) work, files from Chromium 128+ do not.

Get it from an [icu4c](https://github.com/unicode-org/icu/releases) release
(package `icu4c-74_2-data-bin-*`); ICU data is under the Unicode license and
freely redistributable. The file is about ten megabytes; it can be rebuilt for
specific locales with `pkgdata` from the same release.
