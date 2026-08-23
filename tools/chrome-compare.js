#!/usr/bin/env node
// Put the same instrumentation into a real Chrome that `NOKK_TRACE_HOOKS=1` puts
// into the engine, and print the same tape of events: the challenge's callback
// tables as its program calls them, XHR sends with their sizes, blobs and
// workers as they are made. Two tapes side by side answer in a minute what
// otherwise costs an evening — where our run stops matching a browser's.
//
//   node tools/chrome-compare.js <url> [ms]
//   PROXY=http://host:port node tools/chrome-compare.js <url>   — через тот же
//   выход, что и `nokk --proxy`: иначе сравниваются разные адреса.
//   NOKK_TRACE_HOOKS=1 nokk --load <url> --solve-challenge 40 --eval 1
//
// Needs google-chrome, and DISPLAY for a visible window (a headless Chrome is
// blocked outright by some of the targets worth comparing on).
const { spawn } = require('child_process');
const http = require('http');

const PORT = 9333, URL_ = process.argv[2], WAIT = +(process.argv[3] || 40000);
const chrome = spawn('google-chrome', [
  `--remote-debugging-port=${PORT}`, '--user-data-dir=/tmp/cdp-profile', '--no-first-run',
  '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.UA ? [`--user-agent=${process.env.UA}`] : []),
  ...(process.env.CHROME_ARGS ? process.env.CHROME_ARGS.split(' ') : []),
  // Контроль должен выходить в сеть там же, где движок, иначе сравниваются
  // два разных адреса и вывод ничего не стоит.
  ...(process.env.PROXY ? [`--proxy-server=${process.env.PROXY}`] : []),
  'about:blank',
], { env: { ...process.env, DISPLAY: ':0' }, stdio: 'ignore' });

const get = (path) => new Promise((res, rej) => {
  const tryOnce = (n) => http.get({ host: '127.0.0.1', port: PORT, path }, (r) => {
    let b = ''; r.on('data', (d) => b += d); r.on('end', () => res(JSON.parse(b)));
  }).on('error', (e) => n > 0 ? setTimeout(() => tryOnce(n - 1), 500) : rej(e));
  tryOnce(40);
});

const HOOK = `(() => {
  globalThis.__JMIN = ${+(process.env.JMIN || 2000)};
  const tag = () => { try { return location.host + location.pathname.slice(0, 24); } catch (e) { return '?'; } };
  try {
    const S = XMLHttpRequest.prototype.send, O = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) { this.__u = String(u); return O.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function (b) {
      console.log('[send] ' + tag() + ' bytes=' + ((b && b.length) || 0) + ' url=' + String(this.__u || '').slice(-40));
      return S.apply(this, arguments);
    };
  } catch (e) {}
  try {
    const B = globalThis.Blob;
    if (B) globalThis.Blob = function (parts, opts) {
      let n = 0; try { for (const p of (parts || [])) n += (p && p.length) || (p && p.byteLength) || 0; } catch (e) {}
      console.log('[blob] ' + tag() + ' parts=' + ((parts || []).length) + ' bytes=' + n + ' type=' + ((opts && opts.type) || ''));
      return new B(parts, opts);
    };
    const W = globalThis.Worker;
    if (W) globalThis.Worker = function (u, o) { console.log('[worker] ' + tag() + ' ' + String(u).slice(0, 60)); return new W(u, o); };
    const P = globalThis.postMessage;
  } catch (e) {}
  // Отчёт целиком — то же, что печатает NOKK_DUMP_REPORT=1 у нас. Их
  // сериализация идёт через склейку массива, поэтому здесь виден текст до
  // сжатия и шифрования.
  try {
    const J = Array.prototype.join;
    Array.prototype.join = function (sep) {
      const out = J.apply(this, arguments);
      if (typeof out === 'string' && out.length > (globalThis.__JMIN || 2000)) {
        try {
          if (!globalThis.__ptJoinN) globalThis.__ptJoinN = 0;
          const n = globalThis.__ptJoinN++;
          let host = '?';
          try { host = location.host.slice(0, 12); } catch (e) {}
          // Из чего склеен отчёт: сколько кусков и какой длины. Сравнение
          // поэлементно показывает, какое именно поле у кого короче.
          if (out.length > 50000 && String(sep) === '' && this.length !== out.length && !globalThis.__ptPartsDone) {
            globalThis.__ptPartsDone = 1;
            try {
              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
              const big = lens.map((v, i) => [v, i]).sort((a, b) => b[0] - a[0]).slice(0, 25);
              console.log('[parts] n=' + lens.length + ' total=' + out.length +
                    ' крупнейшие: ' + big.map(([v, i]) => i + ':' + v).join(' '));
              const buckets = [0, 0, 0, 0, 0];
              for (const v of lens) buckets[v < 10 ? 0 : v < 100 ? 1 : v < 1000 ? 2 : v < 10000 ? 3 : 4]++;
              console.log('[parts] по размеру: <10=' + buckets[0] + ' <100=' + buckets[1] +
                    ' <1k=' + buckets[2] + ' <10k=' + buckets[3] + ' >=10k=' + buckets[4]);
            } catch (e) {}
          }
          if (String(sep) === '|' && out.length > 5000 && (globalThis.__ptCssN = (globalThis.__ptCssN || 0) + 1) <= 2) {
            for (let i = 0; i < out.length; i += 4000) {
              console.log('[C' + globalThis.__ptCssN + ' @' + i + '] ' + out.slice(i, i + 4000));
            }
            console.log('[C' + globalThis.__ptCssN + ' end ' + out.length + ']');
          }
          if (out.length > 500000 && !globalThis.__ptProgDone) {
            globalThis.__ptProgDone = 1;
            for (let i = 0; i < out.length; i += 4000) {
              console.log('[P @' + i + '] ' + out.slice(i, i + 4000));
            }
            console.log('[P end ' + out.length + ']');
          }
          console.log('[j ' + n + ' ' + host + ' ' + out.length + ' ' +
                      JSON.stringify(String(sep)) + '] ' +
                      out.slice(0, 90).replace(/\\n/g, ' '));
        } catch (e) {}
      }
      return out;
    };
  } catch (e) {}
  // Перепись вызовов: сколько раз челлендж позвал каждый из ходовых методов.
  // Наш собственный пробник считает то же самое, и разница в счётчиках
  // показывает, где сбор у нас обрывается, — это точнее, чем искать любые
  // расхождения подряд.
  try {
    const N = Object.create(null);
    const L = Object.create(null);
    const bump = (k) => { N[k] = (N[k] || 0) + 1; };
    // Сколько знаков всего вернул каждый метод: вызовы у нас с браузером
    // сходятся, значит разница в отчёте — в длине ответов.
    const grew = (k, v) => {
      try {
        const n = v == null ? 0 : (typeof v === 'string' ? v.length
          : (typeof v === 'number' || typeof v === 'boolean' ? String(v).length
          : (v.length !== undefined && typeof v.length === 'number' ? v.length : 0)));
        L[k] = (L[k] || 0) + n;
      } catch (e) {}
    };
    const wrapProto = (obj, label, names) => {
      if (!obj) return;
      for (const n of names) {
        let d;
        try { d = Object.getOwnPropertyDescriptor(obj, n); } catch (e) { continue; }
        if (!d) continue;
        if (typeof d.value === 'function') {
          const f = d.value;
          try {
            Object.defineProperty(obj, n, { ...d, value: function (...a) {
              bump(label + '.' + n);
              const r = f.apply(this, a);
              grew(label + '.' + n, r);
              return r;
            } });
          } catch (e) {}
        } else if (typeof d.get === 'function') {
          const g = d.get;
          try {
            Object.defineProperty(obj, n, { ...d, get: function () {
              bump(label + '.' + n);
              const r = g.call(this);
              grew(label + '.' + n, r);
              return r;
            } });
          } catch (e) {}
        }
      }
    };
    // Через TextEncoder.encode проходит сам отчёт: его куски видны здесь в
    // открытом виде, до сжатия и шифрования. Записываем длину каждого и начало.
    try {
      const TE = globalThis.TextEncoder && TextEncoder.prototype;
      const enc = TE && TE.encode;
      if (enc) {
        let n = 0;
        Object.defineProperty(TE, 'encode', { value: function (x) {
          const s = String(x == null ? '' : x);
          if (s.length > 200) {
            console.log('[enc ' + (n++) + '] ' + s.length + ' :: ' + s.slice(0, 120).replace(/\\n/g, ' '));
          }
          return enc.call(this, x);
        }, writable: true, configurable: true });
      }
    } catch (e) {}
    const C2 = globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
    wrapProto(C2, 'ctx2d', ['fillText','strokeText','measureText','fillRect','getImageData','putImageData',
      'drawImage','arc','ellipse','bezierCurveTo','beginPath','closePath','fill','stroke','createLinearGradient',
      'createRadialGradient','createPattern','getContextAttributes','setTransform','getTransform','isPointInPath']);
    for (const [gl, tag] of [[globalThis.WebGLRenderingContext, 'gl'], [globalThis.WebGL2RenderingContext, 'gl2']]) {
      wrapProto(gl && gl.prototype, tag, ['getParameter','getExtension','getSupportedExtensions',
        'getShaderPrecisionFormat','readPixels','getInternalformatParameter','createShader','shaderSource',
        'compileShader','linkProgram','drawArrays','drawElements','texImage2D','renderbufferStorage']);
    }
    wrapProto(Element.prototype, 'el', ['getAttribute','setAttribute','getBoundingClientRect','getClientRects',
      'querySelector','querySelectorAll','matches','closest','hasAttribute','removeAttribute','attachShadow']);
    wrapProto(HTMLElement.prototype, 'html', ['focus','blur','click']);
    wrapProto(Document.prototype, 'd', ['createElement','createElementNS','createTextNode','querySelector',
      'querySelectorAll','getElementById','createRange','elementFromPoint','elementsFromPoint']);
    wrapProto(Navigator.prototype, 'nav', ['getGamepads','javaEnabled','sendBeacon']);
    wrapProto(globalThis.HTMLMediaElement && HTMLMediaElement.prototype, 'media', ['canPlayType']);
    wrapProto(globalThis.SVGGraphicsElement && SVGGraphicsElement.prototype, 'svg', ['getBBox','getCTM','getScreenCTM']);
    wrapProto(globalThis.SVGGeometryElement && SVGGeometryElement.prototype, 'svg', ['getTotalLength','getPointAtLength','isPointInFill']);
    wrapProto(globalThis.RTCPeerConnection && RTCPeerConnection.prototype, 'rtc', ['createOffer','setLocalDescription','getStats','createDataChannel']);
    wrapProto(globalThis.AudioContext && AudioContext.prototype, 'audio', ['createOscillator','createAnalyser','createDynamicsCompressor','createGain']);
    wrapProto(globalThis.OfflineAudioContext && OfflineAudioContext.prototype, 'audio', ['startRendering']);
    wrapProto(globalThis.TextEncoder && TextEncoder.prototype, 'textEnc', ['encode']);
    for (const n of ['getComputedStyle', 'matchMedia', 'requestAnimationFrame', 'queueMicrotask', 'fetch', 'btoa', 'atob']) {
      const f = globalThis[n];
      if (typeof f !== 'function') continue;
      try { globalThis[n] = function (...a) { bump('win.' + n); return f.apply(this, a); }; } catch (e) {}
    }
    globalThis.__ptCounts = () => N;
    // Выгружаем на исходе прогона: печатаем по строке на имя.
    setTimeout(() => {
      const rows = Object.entries(N).sort((a, b) => (L[b[0]] || 0) - (L[a[0]] || 0));
      for (const [k, v] of rows) console.log('[count] ' + v + ' вызовов, ' + (L[k] || 0) + ' знаков — ' + k);
    }, 26000);
  } catch (e) {}

  for (const name of ['RItcy2', 'HuCI0']) {
    let store;
    try {
      Object.defineProperty(globalThis, name, { configurable: true,
        get() { return store; },
        set(v) {
          if (v && typeof v === 'object') {
            for (const k of Object.keys(v)) { const f = v[k];
              if (typeof f === 'function') v[k] = function () { console.log('[hook] ' + tag() + ' ' + name + '.' + k); return f.apply(this, arguments); }; }
          }
          store = v;
        } });
    } catch (e) {}
  }
})();`;

(async () => {
  const list = await get('/json/list');
  const page = list.find((t) => t.type === 'page');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0; const send = (method, params = {}, sessionId) =>
    ws.send(JSON.stringify({ id: ++id, method, params, ...(sessionId ? { sessionId } : {}) }));
  const lines = [];
  const t0 = Date.now();
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Runtime.consoleAPICalled') {
      const t = (m.params.args || []).map((a) => a.value).join(' ');
      if (/^\[(send|hook|hookerr|blob|worker|count)\]|^\[[jPC]\d* |^\[parts|^\[enc /.test(String(t)))
        lines.push(String(Date.now() - t0).padStart(6) + 'ms ' + t);
    }
    if (m.method === 'Target.attachedToTarget') {
      const s = m.params.sessionId;
      lines.push('[target] ' + (m.params.targetInfo && m.params.targetInfo.url || '').slice(0, 60));
      send('Runtime.enable', {}, s);
      send('Page.enable', {}, s);
      send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }, s);
      send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, s);
      send('Runtime.runIfWaitingForDebugger', {}, s);
    }
  });
  ws.addEventListener('open', async () => {
    send('Runtime.enable'); send('Page.enable');
    send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK });
    setTimeout(() => send('Page.navigate', { url: URL_ }), 400);
    setTimeout(async () => {
      console.log(lines.join('\n') || '(no instrumented output)');
      ws.close(); chrome.kill(); process.exit(0);
    }, WAIT);
  });
})();
