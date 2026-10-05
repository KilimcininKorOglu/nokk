# How nokk works

nokk is a Cargo workspace of small, single-responsibility crates:

| Crate            | Responsibility |
|------------------|----------------|
| `nokk`         | Public `Engine`/`BrowserContext` API; ties the layers together |
| `nokk-pool`    | Isolate worker pool + backpressure (one V8 isolate per thread) |
| `nokk-net`     | Chrome-fingerprinted HTTP client (BoringSSL), connection pool, proxy |
| `nokk-dom`     | HTML parsing (`html5ever`) → DOM tree |
| `nokk-stealth` | The spoofed JS environment + fingerprint hardening |
| `nokk-cdp`     | Chrome DevTools Protocol WebSocket server (Puppeteer-compatible) |
| `nokk-cli`     | The `nokk` binary |

Three constraints shape every design decision:

1. **V8 isolates are single-threaded.** Concurrency is a pool of OS threads, one isolate
   each, every isolate multiplexing several contexts ("tabs"). Contexts are pinned to a
   thread and never move; a crash in one must not take down the pool.
2. **Network is non-blocking and off the isolate threads.** All IO runs on `tokio` over a
   shared connection pool, so a slow request never occupies a JS worker.
3. **Fingerprint coherence is sacred.** The JS-level fingerprint and the TLS/HTTP
   fingerprint must always agree — changing one without the other is what gets you caught.

The DOM, timers, `fetch`, and most stealth shims are implemented in JavaScript injected
into each context, bridged to Rust through a handful of hidden globals — so the browser
surface a page sees is real JS objects, not native bindings a detector can trivially probe.
