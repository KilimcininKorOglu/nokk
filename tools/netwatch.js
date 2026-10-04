#!/usr/bin/env node
// What Cloudflare served the browser, observed without touching the page.
//
// `chrome-compare.js` injects a hook, and that changes the answer: with it
// Chrome gets a 617 KB challenge program, without it (same minute, same
// address) 635 KB. A perturbing instrument is only good for comparing two
// equally perturbed runs; this one enables the network domain only, with no
// `Runtime.enable` and no injection.
//
//   node tools/netwatch.js <url> [ms]
//   PROXY=http://host:port node tools/netwatch.js <url>
//
// Read the `/fo/` response body length: ~846 000 is the trusted-client
// program, ~823 000 the suspicious one. The engine shows the same number in
// `nokk --load … --dump-requests`.
//
// Every run costs address reputation: after a few in a row even a real browser
// gets the untrusted program. Measure rarely, always next to a control run.
const { spawn } = require('child_process'); const http = require('http');
const PORT = 9336, URL_ = process.argv[2], WAIT = +(process.argv[3] || 30000);
const args = [`--remote-debugging-port=${PORT}`, '--user-data-dir=/tmp/cdp-net',
  '--no-first-run', '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.PROXY ? [`--proxy-server=${process.env.PROXY}`] : []), 'about:blank'];
const chrome = spawn('google-chrome', args, { env: {...process.env, DISPLAY: ':0'}, stdio: 'ignore' });
const get = (p) => new Promise((res, rej) => { const t = (n) => http.get({host:'127.0.0.1',port:PORT,path:p},
  (r)=>{let b='';r.on('data',d=>b+=d);r.on('end',()=>res(JSON.parse(b)));}).on('error',e=>n>0?setTimeout(()=>t(n-1),400):rej(e)); t(40); });
(async () => {
  const list = await get('/json/list'); const page = list.find(t => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl); let id = 0;
  const send = (m, p = {}, s) => ws.send(JSON.stringify({ id: ++id, method: m, params: p, ...(s?{sessionId:s}:{}) }));
  const urls = new Map(); const got = new Map(); const rows = []; const sent = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Network.requestWillBeSent') {
      const q = m.params.request;
      urls.set(m.params.requestId, q.url);
      // Request sizes matter as much as response sizes: compare both series.
      if (/challenge-platform/.test(q.url)) {
        const n = q.postData ? q.postData.length : (q.postDataEntries ? -1 : 0);
        sent.push([m.params.timestamp, q.method, n, q.url.replace(/^https:\/\//, '').slice(0, 62), m.params.requestId]);
        // `/pat/` headers too: a header difference there shows in the status code.
        const kind = /\/fo\//.test(q.url) && q.method === 'POST' ? 'first POST'
          : /\/pat\//.test(q.url) ? '/pat/ request' : null;
        // First POST body with `BODY=1`. It is sent before the program and
        // decides which program is served; diff it against the engine's [FIRST] tape.
        if (process.env.BODY && kind === 'first POST' && q.postData && !globalThis.__bodyShown) {
          globalThis.__bodyShown = 1;
          const b = String(q.postData);
          for (let i = 0; i < b.length; i += 250) {
            console.log('[FIRST ' + b.length + ':' + (i / 250) + '] ' + b.slice(i, i + 250));
          }
        }
        if (kind && !globalThis['__hdr' + kind]) {
          globalThis['__hdr' + kind] = 1;
          console.log('— headers of ' + kind + ':');
          for (const k of Object.keys(q.headers)) console.log('   ' + k + ': ' + String(q.headers[k]).slice(0, 90));
        }
      }
    }
    // Only ExtraInfo has the full header set; the request event shows script-set headers.
    if (m.method === 'Network.requestWillBeSentExtraInfo') {
      const u = urls.get(m.params.requestId) || '';
      const sa = m.params.headers['sec-fetch-storage-access'];
      const st = m.params.headers['sec-fetch-site'];
      if ((globalThis.__extraN = (globalThis.__extraN || 0) + 1) <= 40) {
        console.log('[storage] ' + (sa || '—') + ' | site=' + (st || '—') + ' | '
          + u.replace(/^https?:\/\//, '').slice(0, 58));
      }
    }
    if (m.method === 'Network.loadingFinished') {
      const u = urls.get(m.params.requestId) || '';
      if (/challenge-platform|turnstile/.test(u)) { got.set(m.params.requestId, m.params.encodedDataLength); rows.push([m.params.encodedDataLength, u.replace(/^https:\/\//,'').slice(0, 70)]); }
      // Fetched after loading finished, so the page is unaffected.
      if (/\/fo\//.test(u) && m.params.encodedDataLength > 100000) {
        send('Network.getResponseBody', { requestId: m.params.requestId }, m.sessionId);
      }
    }
    if (m.result && typeof m.result.body === 'string') {
      const n = m.result.body.length;
      console.log('/fo/ body:', n, '→ program approx.', Math.round(n * 3 / 4));
    }
    if (m.method === 'Target.attachedToTarget') {
      const s = m.params.sessionId;
      send('Network.enable', {}, s);
      send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, s);
      send('Runtime.runIfWaitingForDebugger', {}, s);
    }
  });
  ws.addEventListener('open', () => {
    send('Network.enable'); send('Page.enable');
    send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    setTimeout(() => send('Page.navigate', { url: URL_ }), 300);
    setTimeout(() => {
      const t0 = sent.length ? sent[0][0] : 0;
      console.log('— challenge exchange, in order:');
      for (const [t, meth, n, u, rid] of sent) {
        console.log('  ' + String(Math.round((t - t0) * 1000)).padStart(6) + 'ms ' +
                    meth.padEnd(5) + String(n).padStart(7) + ' bytes, response ' + (got.get(rid) === undefined ? '?' : got.get(rid)) + ' → ' + u.replace(/^challenges\.cloudflare\.com\/cdn-cgi\/challenge-platform\/h\/b\//, ''));
      }
      console.log('— largest responses:');
      for (const [n, u] of rows.sort((a,b)=>b[0]-a[0]).slice(0, 5)) console.log('  ' + String(n).padStart(9), u);
      ws.close(); chrome.kill(); process.exit(0);
    }, WAIT);
  });
})();
