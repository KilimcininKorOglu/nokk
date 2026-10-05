# Rotating fingerprints

With `--rotate-fingerprint`, every browser context presents its **own coherent machine** —
not just a different User-Agent, but a matched set of `{ TLS/JA3 emulation OS + UA +
navigator.userAgentData + sec-ch-ua + platform + screen + hardwareConcurrency + WebGL }`
where every layer agrees. The profile is chosen deterministically from the context's identity
(the Puppeteer browser-context id), so a given context is the **same** machine across runs,
and distinct contexts look like distinct devices. Naive UA rotation is a *net negative* — a UA
that contradicts the TLS handshake or the client hints is itself a detection signal — so nokk
rotates the whole identity or nothing.

```js
// Two contexts → two self-consistent, distinct machines (Chrome on Linux / Windows / macOS)
const a = await browser.createBrowserContext();
const b = await browser.createBrowserContext();
```

Add `--geoip-timezone` to derive each context's `Intl` timezone and `navigator.languages`
from its **proxy's exit IP** (one lookup per proxy, made through that proxy and cached), so a
context routed through a German proxy reports `Europe/Berlin` and `de-DE` — a browser whose
timezone disagrees with its IP is a classic tell. Both flags are off by default, so a single
context stays deterministic. From the Rust API these are `EngineConfig::rotate_fingerprint`
and `EngineConfig::geoip_timezone`.
