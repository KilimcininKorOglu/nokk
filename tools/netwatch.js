#!/usr/bin/env node
// Что Cloudflare выдал браузеру, не трогая браузер.
//
// `chrome-compare.js` внедряет в страницу крючок — и этим меняет ответ: с ним
// Chrome получает программу челленджа на 617 КБ, без него, в ту же минуту и с
// того же адреса, на 635 КБ. Инструмент, который меняет измеряемое, годится
// только для сравнения двух одинаково испорченных прогонов; чтобы узнать, как
// обстоит дело на самом деле, нужен наблюдатель, который к странице не
// прикасается. Здесь включена только сеть: ни `Runtime.enable`, ни внедрения.
//
//   node tools/netwatch.js <url> [ms]
//   PROXY=http://host:port node tools/netwatch.js <url>
//
// Читается по длине тела ответа `/fo/`: около 846 000 — программа для
// доверенного клиента, около 823 000 — для подозрительного. У движка то же
// число видно в `nokk --load … --dump-requests`.
//
// Каждое обращение стоит репутации адреса: после нескольких попыток подряд
// недоверенную программу начинает получать и настоящий браузер. Меряйте редко
// и всегда рядом с контрольным прогоном.

// размера программу челленджа отдал Cloudflare.
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
      // Размер отправки тоже нужен: разговор с челленджем — это чередование
      // «сколько рассказали» и «что дали в ответ», и сравнивать надо оба ряда.
      if (/challenge-platform/.test(q.url)) {
        const n = q.postData ? q.postData.length : (q.postDataEntries ? -1 : 0);
        sent.push([m.params.timestamp, q.method, n, q.url.replace(/^https:\/\//, '').slice(0, 62), m.params.requestId]);
        // Заголовки показываются и у `/pat/`: там разговор о жетоне, и
        // отличие в заголовках видно сразу по коду ответа.
        const kind = /\/fo\//.test(q.url) && q.method === 'POST' ? 'первого POST'
          : /\/pat\//.test(q.url) ? 'запроса /pat/' : null;
        // Тело первого POST — с `BODY=1`. Оно уходит до программы, и по нему
        // челлендж решает, какую программу дать; сравнивать его надо знак в
        // знак с тем, что печатает движок ([ПЕРВЫЙ] в его тапе).
        if (process.env.BODY && kind === 'первого POST' && q.postData && !globalThis.__bodyShown) {
          globalThis.__bodyShown = 1;
          const b = String(q.postData);
          for (let i = 0; i < b.length; i += 250) {
            console.log('[ПЕРВЫЙ ' + b.length + ':' + (i / 250) + '] ' + b.slice(i, i + 250));
          }
        }
        if (kind && !globalThis['__hdr' + kind]) {
          globalThis['__hdr' + kind] = 1;
          console.log('— заголовки ' + kind + ':');
          for (const k of Object.keys(q.headers)) console.log('   ' + k + ': ' + String(q.headers[k]).slice(0, 90));
        }
      }
    }
    // Полный набор заголовков виден только в дополнении: сам запрос в CDP
    // показывает лишь то, что поставил скрипт.
    if (m.method === 'Network.requestWillBeSentExtraInfo') {
      const u = urls.get(m.params.requestId) || '';
      const sa = m.params.headers['sec-fetch-storage-access'];
      const st = m.params.headers['sec-fetch-site'];
      if ((globalThis.__extraN = (globalThis.__extraN || 0) + 1) <= 40) {
        console.log('[хранилище] ' + (sa || '—') + ' | site=' + (st || '—') + ' | '
          + u.replace(/^https?:\/\//, '').slice(0, 58));
      }
    }
    if (m.method === 'Network.loadingFinished') {
      const u = urls.get(m.params.requestId) || '';
      if (/challenge-platform|turnstile/.test(u)) { got.set(m.params.requestId, m.params.encodedDataLength); rows.push([m.params.encodedDataLength, u.replace(/^https:\/\//,'').slice(0, 70)]); }
      // Тело нужно целиком: по его длине видно, какую программу дали. Просят
      // его после завершения загрузки, страницы это не касается.
      if (/\/fo\//.test(u) && m.params.encodedDataLength > 100000) {
        send('Network.getResponseBody', { requestId: m.params.requestId }, m.sessionId);
      }
    }
    if (m.result && typeof m.result.body === 'string') {
      const n = m.result.body.length;
      console.log('тело /fo/:', n, '→ программа примерно', Math.round(n * 3 / 4));
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
      console.log('— разговор с челленджем, по порядку:');
      for (const [t, meth, n, u, rid] of sent) {
        console.log('  ' + String(Math.round((t - t0) * 1000)).padStart(6) + 'ms ' +
                    meth.padEnd(5) + String(n).padStart(7) + ' байт, ответ ' + (got.get(rid) === undefined ? '?' : got.get(rid)) + ' → ' + u.replace(/^challenges\.cloudflare\.com\/cdn-cgi\/challenge-platform\/h\/b\//, ''));
      }
      console.log('— самые крупные ответы:');
      for (const [n, u] of rows.sort((a,b)=>b[0]-a[0]).slice(0, 5)) console.log('  ' + String(n).padStart(9), u);
      ws.close(); chrome.kill(); process.exit(0);
    }, WAIT);
  });
})();
