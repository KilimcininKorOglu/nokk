# ICU data: why `Intl` needs it

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

## Where the data comes from

The binary carries it. `crates/pool/icu/icudtl.dat` is Chrome 151's own file
(ICU 78, byte for byte the one Chromium ships), embedded at build time, so `Intl`
gives Chrome's answers with nothing to install. ICU data is under the
[Unicode license](../crates/pool/icu/LICENSE).

An external file still wins, which lets the data follow a V8 upgrade without a
rebuild:

```
NOKK_ICU_DATA=/path/to/icudtl.dat nokk --load https://example.com
```

or `icudtl.dat` next to the binary. The file must match the ICU version V8 links
(`set_common_data_78`): data of another version loads, and then every call throws
`TypeError: Internal error. Icu error.` When V8 moves to a new ICU, replace the
embedded file with the one from the matching Chrome release.

## Timezone

With native `Intl` the page sees the process's zone: `TZ`, else the host's
`/etc/localtime`, else `America/New_York` (a host with no zone at all, such as a
distroless image, would otherwise report `Etc/Unknown`). A context whose zone
comes from `--geoip-timezone` keeps the JS layer for `Intl` and `Date`, because
native `Intl` knows only one zone per process.
