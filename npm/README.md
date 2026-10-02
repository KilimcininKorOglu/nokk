# nokk

**Undetectable headless-browser engine, one `npm install` away.**

`nokk` is a lightweight, Chrome-fingerprinted headless-browser engine (V8 + a
minimal DOM, no rendering) that speaks the Chrome DevTools Protocol. Install it,
call `launch()`, and connect your existing **Puppeteer** or **Playwright** script
over CDP — no Chromium download.

```bash
npm install @koloss777/nokk
```

> **Alpha:** the prebuilt binary is fetched on install and is currently **Linux
> x64** only. macOS/Windows are on the roadmap.

## Puppeteer

```js
const nokk = require("@koloss777/nokk");
const puppeteer = require("puppeteer");

(async () => {
  const server = await nokk.launch({ rotateFingerprint: true });
  const browser = await puppeteer.connect({ browserWSEndpoint: server.wsEndpoint });
  const page = await browser.newPage();
  await page.goto("https://example.com");
  console.log(await page.title());
  await browser.close();
  await server.close();
})();
```

## Playwright

```js
const nokk = require("@koloss777/nokk");
const { chromium } = require("playwright");

(async () => {
  const server = await nokk.launch();
  const browser = await chromium.connectOverCDP(server.wsEndpoint);
  const page = await browser.newPage();
  await page.goto("https://example.com");
  console.log(await page.title());
  await browser.close();
  await server.close();
})();
```

## `launch(options)`

Starts the CDP server on a free port and resolves to a `NokkServer`. Options
(all optional): `host`, `port`, `workers`, `maxContexts`, `proxy`,
`sessionStore`, `rotateFingerprint`, `geoipTimezone`, `allowTrackers`,
`chromeVersion`, `autoSolve`, `args`, `env`, `timeout`.

```js
// Each browser context looks like a different machine, timezone matched to its proxy:
const server = await nokk.launch({ rotateFingerprint: true, geoipTimezone: true });
```

`server.wsEndpoint` → hand to `puppeteer.connect` / `chromium.connectOverCDP`.
`server.close()` stops it; it's also killed when the Node process exits.

## Cloudflare challenges

With `autoSolve`, a navigation that lands on Cloudflare's "Just a moment…" page
or a Turnstile widget returns only once it is through: `page.goto()` resolves
on the real page. `true` gives each challenge 30 s; a number sets the budget in
seconds.

```js
const server = await nokk.launch({ autoSolve: true });
// …
await page.goto("https://www.scrapingcourse.com/cloudflare-challenge");
console.log(await page.title()); // the page behind the challenge
```

Or on demand, for a Puppeteer page, a Playwright page or a raw CDP session:

```js
const state = await nokk.challengeState(page);
// { kind: "cloudflare-interstitial" | "turnstile-widget" | "datadome" | "none", solvable, … }
if (state.solvable) {
  const r = await nokk.solveChallenge(page, { timeout: 30000 });
  // { status: "cleared" | "token-issued" | "cleared-but-stuck" | "timeout", solved, presses, remaining, … }
}
```

Nobody passes selectors: the engine finds and presses the checkbox itself.

## CLI

```bash
npx @koloss777/nokk --port 9222 --workers 4      # run the CDP server directly
```

Point at a locally built binary during development with the `NOKK_BINARY`
environment variable.

## Links

- Source & docs: <https://github.com/koloss777/nokk>

Licensed under MIT OR Apache-2.0.
