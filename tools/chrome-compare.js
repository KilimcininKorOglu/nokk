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
            let at = '';
            try {
              at = String(new Error().stack || '').split('\\n').slice(2, 5)
                .map((x) => x.trim().replace(/^at /, '').slice(0, 46)).join(' < ');
            } catch (e) {}
            console.log('[enc ' + (n++) + '] ' + s.length + ' | ненулевых=' + (() => { let n = 0, sum = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c) { n++; sum = (sum * 31 + c) >>> 0; } } return n + ' сумма=' + sum; })() + (s.length > 14000 ? ' текст: ' + s.slice(0, 90).replace(/[^\x20-\x7e]/g, '.') : ' коды: ') + Array.from(s.slice(0, 24)).map((c) => c.charCodeAt(0)).join(',') + ' | ' + Array.from(s.slice(Math.floor(s.length / 2), Math.floor(s.length / 2) + 12)).map((c) => c.charCodeAt(0)).join(','));
if (s.length > 15000 && s.length < 16000 && !(globalThis.__ptD = globalThis.__ptD || {})[s.length]) {
  globalThis.__ptD[s.length] = 1;
  for (let q = 0; q < s.length; q += 250) console.log('[кус ' + s.length + ':' + (q / 300) + '] ' + s.slice(q, q + 300));
}
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
    wrapProto(globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype, 'canvas',
      ['transferControlToOffscreen', 'toDataURL', 'toBlob', 'captureStream', 'getContext']);
    wrapProto(globalThis.OffscreenCanvas && OffscreenCanvas.prototype, 'off',
      ['convertToBlob', 'transferToImageBitmap']);
    // Какие именно контексты просят у офскрина и что получают.
    try {
          for (const N of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
            const W = globalThis[N] && globalThis[N].prototype;
            if (!W || !W.readPixels || W.__ptRp) continue;
            try { Object.defineProperty(W, '__ptRp', { value: 1 }); } catch (e) {}
            const rp = W.readPixels;
            W.readPixels = function (x, y, w, h, f, t, p) {
              console.log('[rp] ' + N + ' ' + w + 'x' + h);
              return rp.apply(this, arguments);
            };
          }
          const HC = globalThis.HTMLCanvasElement && globalThis.HTMLCanvasElement.prototype;
          if (HC && HC.getContext && !HC.__ptGc) {
            try { Object.defineProperty(HC, '__ptGc', { value: 1 }); } catch (e) {}
            const hg = HC.getContext;
            HC.getContext = function (ty, a) {
              const r = hg.apply(this, arguments);
              console.log('[ectx] ' + ty + ' ' + this.width + 'x' + this.height +
                  ' -> ' + (r ? 'ok' : String(r)));
              return r;
            };
          }
          const CG = globalThis.CanvasGradient && globalThis.CanvasGradient.prototype;
          if (CG && CG.addColorStop && !CG.__ptS) {
            try { Object.defineProperty(CG, '__ptS', { value: 1 }); } catch (e) {}
            const acs = CG.addColorStop;
            CG.addColorStop = function (o, c) { console.log('[stop] ' + o + ' ' + c); return acs.apply(this, arguments); };
          }
          if (!globalThis.__ptCvId) {
            const map = new WeakMap(); let seq = 0;
            globalThis.__ptCvId = (cv) => { if (!cv) return '?';
              if (!map.has(cv)) map.set(cv, ++seq); return map.get(cv); };
          }
          for (const N of ['CanvasRenderingContext2D', 'OffscreenCanvasRenderingContext2D']) {
            const C = globalThis[N] && globalThis[N].prototype;
            if (!C || C.__ptAll) continue;
            try { Object.defineProperty(C, '__ptAll', { value: 1 }); } catch (e) {}
            for (const k of Object.getOwnPropertyNames(C)) {
              let d;
              try { d = Object.getOwnPropertyDescriptor(C, k); } catch (e) { continue; }
              if (!d || typeof d.value !== 'function' || k === 'constructor' || k === 'getImageData') continue;
              const f = d.value;
              try {
                C[k] = function () {
                  const cv = this && this.canvas;
                  if (cv && ((cv.width === 48 && cv.height === 48) || (cv.width === 49 && cv.height === 44))) {
                    const a = [];
                    for (let i = 0; i < arguments.length; i++) {
                      const v = arguments[i];
                      if (v && typeof v === 'object') {
                        a.push((v.localName || (v.constructor && v.constructor.name) || 'об') +
                          '<' + (v.width !== undefined ? v.width + 'x' + v.height : '?') + '>' +
                          (typeof v.src === 'string' ? ' src=' + v.src.slice(0, 46) : ''));
                      } else a.push(String(v).slice(0, 40));
                    }
                    console.log('[c48] #' + globalThis.__ptCvId(cv) + ' ' + cv.width + ' ' + k + '(' + a.join(',') + ')' +
                      (cv.width !== 2 ? '' : (() => { try { const r = f.apply(this, arguments);
                        return ' -> ' + (r && typeof r === 'object' ? (r.data
                          ? Object.prototype.toString.call(r.data) + '[' + [].slice.call(r.data).join(',') + '] ' + r.colorSpace + '/' + r.pixelFormat
                          : JSON.stringify(r)) : String(r)); } catch (e) { return ' -> бросил ' + e.name; } })()));
                  }
                  return f.apply(this, arguments);
                };
              } catch (e) {}
            }
            for (const k of ['fillStyle', 'font', 'globalAlpha', 'globalCompositeOperation', 'strokeStyle',
              'lineWidth', 'lineCap', 'lineJoin', 'miterLimit', 'lineDashOffset', 'shadowBlur',
              'shadowColor', 'shadowOffsetX', 'shadowOffsetY', 'filter', 'textAlign', 'textBaseline',
              'imageSmoothingEnabled', 'imageSmoothingQuality', 'letterSpacing', 'wordSpacing',
              'direction', 'fontKerning', 'fontStretch', 'fontVariantCaps', 'textRendering']) {
              const d = Object.getOwnPropertyDescriptor(C, k);
              if (!d || !d.set) continue;
              try {
                Object.defineProperty(C, k, {
                  get: d.get,
                  set: function (v) {
                    const cv = this && this.canvas;
                    if (cv && ((cv.width === 48 && cv.height === 48) || (cv.width === 49 && cv.height === 44))) console.log('[c48] #' + globalThis.__ptCvId(cv) + ' ' + k + ' = ' + String(v).slice(0, 60));
                    return d.set.call(this, v);
                  },
                  enumerable: d.enumerable, configurable: true,
                });
              } catch (e) {}
            }
          }
          for (const N of ['CanvasRenderingContext2D', 'OffscreenCanvasRenderingContext2D']) {
            const C = globalThis[N] && globalThis[N].prototype;
            if (!C || !C.getImageData || C.__ptGid) continue;
            try { Object.defineProperty(C, '__ptGid', { value: 1 }); } catch (e) {}
            const gi = C.getImageData;
            C.getImageData = function (x, y, w, h) {
              const r = gi.apply(this, arguments);
              let show = '';
              if (w * h <= 4) {
                try {
                  show = ' -> ' + Object.prototype.toString.call(r.data) +
                    '[' + [].slice.call(r.data).join(',') + '] ' + r.colorSpace + '/' + r.pixelFormat +
                    ' настройки=' + JSON.stringify(arguments[4] || null) +
                    ' холст=' + JSON.stringify(this.getContextAttributes ? this.getContextAttributes() : null);
                } catch (e) { show = ' -> ' + e.name; }
              }
              console.log('[gid] #' + globalThis.__ptCvId(this.canvas) + ' ' + w + 'x' + h + ' на ' + (this.canvas ? this.canvas.width + 'x' + this.canvas.height : '?') + show);
              return r;
            };
          }
          // Полный след WebGPU: какие объекты и какие вызовы.
          if (!globalThis.__ptGpuTrace) {
            globalThis.__ptGpuTrace = 1;
            const names = Object.getOwnPropertyNames(globalThis).filter((n) => /^GPU/.test(n));
            for (const n of names) {
              const C = globalThis[n];
              const P = C && C.prototype;
              if (!P) continue;
              for (const k of Object.getOwnPropertyNames(P)) {
                let d;
                try { d = Object.getOwnPropertyDescriptor(P, k); } catch (e) { continue; }
                if (!d || typeof d.value !== 'function' || k === 'constructor') continue;
                const f = d.value;
                try {
                  P[k] = function (...args) {
                    const a = args.map((v) => {
                      if (v === null || v === undefined) return String(v);
                      if (typeof v === 'object') {
                        try { return JSON.stringify(v).slice(0, 1400); }
                        catch (e) { return (v.constructor && v.constructor.name) || 'об'; }
                      }
                      return String(v).slice(0, 40);
                    });
                    const r = f.apply(this, args);
                    const shown = r && typeof r === 'object'
                      ? ((r.constructor && r.constructor.name) || 'об') : String(r).slice(0, 30);
                    console.log('[gpu] ' + n + '.' + k + '(' + a.join(' | ') + ') -> ' + shown);
                    return r;
                  };
                } catch (e) {}
              }
            }
          }
          const gpu = globalThis.navigator && globalThis.navigator.gpu;
          if (gpu && !gpu.__ptG) {
            try { Object.defineProperty(gpu, '__ptG', { value: 1 }); } catch (e) {}
            for (const k of ['requestAdapter', 'getPreferredCanvasFormat']) {
              const f = gpu[k];
              if (typeof f !== 'function') continue;
              gpu[k] = function () {
                let r;
                try { r = f.apply(this, arguments); } catch (e) { console.log('[gpu] ' + k + ' бросил ' + e.name); throw e; }
                if (r && typeof r.then === 'function') {
                  return r.then((v) => { console.log('[gpu] ' + k + ' -> ' + (v ? 'объект' : String(v))); return v; },
                                (e) => { console.log('[gpu] ' + k + ' отказ ' + e); throw e; });
                }
                console.log('[gpu] ' + k + ' -> ' + String(r));
                return r;
              };
            }
          }
          const OP = globalThis.OffscreenCanvas && globalThis.OffscreenCanvas.prototype;
          const og = OP && OP.getContext;
          if (og) {
            let seq = 0;
            Object.defineProperty(OP, 'getContext', { value: function (ty, a) {
              let r, err = '';
              try { r = og.call(this, ty, a); } catch (e) { err = e.name; }
              const id = ++seq;
              console.log('[octx] #' + id + ' ' + ty + ' ' + this.width + 'x' + this.height +
                  ' настройки=' + (a ? JSON.stringify(a) : '-') + ' -> ' + (err || (r ? 'ok' : String(r))));
              // Для холста 49x44 — след первых операций: по нему видно, чем
              // третий отличается от первых двух.
              if (r && ty === '2d' && this.width * this.height === 2156) {
                let n = 0;
                const seen = Object.create(null);
                for (const k of Object.getOwnPropertyNames(Object.getPrototypeOf(r))) {
                  let d;
                  try { d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(r), k); } catch (e) { continue; }
                  if (!d || typeof d.value !== 'function') continue;
                  const f = d.value;
                  try {
                    r[k] = function (...args) {
                      if (n < 26 && !seen[k]) { seen[k] = 1; console.log('[cop] #' + id + ' ' + (n++) + ' ' + k); }
                      return f.apply(this, args);
                    };
                  } catch (e) {}
                }
              }
              if (err) throw new TypeError(err);
              return r;
            }, writable: true, configurable: true });
          }
    } catch (e) {}
    wrapProto(globalThis.Worker && Worker.prototype, 'worker', ['postMessage', 'terminate']);
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
      if (/^\[(send|hook|hookerr|blob|worker|count)\]|^\[[jPC]\d* |^\[parts|^\[кус |^\[enc |^\[octx\]|^\[cop\]|^\[rp\]|^\[gid\]|^\[c48\]|^\[stop\]|^\[c49\]|^\[gpu\]|^\[ectx\]/.test(String(t)))
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
