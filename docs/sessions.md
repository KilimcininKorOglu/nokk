# Persistent sessions

Start nokk with a session store, then bind a browser context to a **session name**. Its
cookie jar — login state, `cf_clearance`, session cookies and all — persists to
`<store>/<name>.json` and reloads automatically, even in a new process. Warm a session once
and re-attach it later instead of re-solving a challenge every run:

```bash
nokk --port 9222 --session-store ./sessions
```

```js
const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222/devtools/browser/nokk',
});
// `sessionName` is a nokk extension to Target.createBrowserContext, sent via raw CDP.
const cdp = await browser.target().createCDPSession();
const { browserContextId } = await cdp.send('Target.createBrowserContext', {
  sessionName: 'acme',
  // proxyServer: 'http://user:pass@host:port',   // optional, per-session IP
});
```

Every page opened in that context shares the named jar; it flushes to disk when the context
closes. Distinct session names are fully isolated. Without `--session-store`, sessions are
in-memory only. From the Rust API this is `Engine::new_context_with_session(name, proxy)`.

A `cf_clearance` earned in a real browser can be imported into a session with
`--import-cookies`; see [Cloudflare challenges](cloudflare.md#replaying-a-cf_clearance-from-a-real-browser).
