#!/usr/bin/env node
// Put the same instrumentation into a real Chrome that `NOKK_TRACE_HOOKS=1` puts
// into the engine, and print the same tape of events: the challenge's callback
// tables as its program calls them, XHR sends with their sizes, blobs and
// workers as they are made. Two tapes side by side answer in a minute what
// otherwise costs an evening — where our run stops matching a browser's.
//
//   node tools/chrome-compare.js <url> [ms]
//   PROXY=http://host:port node tools/chrome-compare.js <url>   (use the same
//   exit as `nokk --proxy`, otherwise two different addresses are compared)
//   NOKK_TRACE_HOOKS=1 nokk --load <url> --solve-challenge 40 --eval 1
//
// Needs google-chrome, and DISPLAY for a visible window (a headless Chrome is
// blocked outright by some of the targets worth comparing on).
const { spawn } = require('child_process');
const http = require('http');

const PORT = 9333, URL_ = process.argv[2], WAIT = +(process.argv[3] || 40000);
// Report chunk length range to dump in full, e.g. DUMPENC=30000-32000; use the
// same window as the engine's `NOKK_DUMP_ENC`.
const [DUMP_LO, DUMP_HI] = (process.env.DUMPENC || '15000-16000').split('-').map(Number);
const chrome = spawn('google-chrome', [
  `--remote-debugging-port=${PORT}`, '--user-data-dir=/tmp/cdp-profile', '--no-first-run',
  '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.UA ? [`--user-agent=${process.env.UA}`] : []),
  ...(process.env.CHROME_ARGS ? process.env.CHROME_ARGS.split(' ') : []),
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
  // Errors the challenge throws. Some are deliberate (it reads its own stack);
  // only diffing against the engine tells them apart. Engine side:
  // NOKK_TRACE_BEACON, tag [thrown].
  const t0 = Date.now();
  addEventListener('error', (e) => {
    try { console.log('[thrown] ' + (Date.now() - t0) + 'ms ' + String(e.message || '') + ' @ ' +
      String(e.filename || '').slice(-58) + ':' + e.lineno); } catch (x) {}
  });
  addEventListener('unhandledrejection', (e) => {
    try { console.log('[thrown] ' + (Date.now() - t0) + 'ms rejected: ' +
      String((e.reason && (e.reason.stack || e.reason.message)) || e.reason).slice(0, 150)); } catch (x) {}
  });
  try {
    const S = XMLHttpRequest.prototype.send, O = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u) {
      this.__u = String(u);
      // Serialization window: the body is built between open() and send().
      try {
        if (/\\/cdn-cgi\\/challenge-platform\\//.test(this.__u) && !globalThis.__ptCollected) {
          globalThis.__ptSerializing = 1;
        }
      } catch (e) {}
      return O.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (b) {
      console.log('[send] ' + tag() + ' bytes=' + ((b && b.length) || 0) + ' url=' + String(this.__u || '').slice(-40));
      // First POST body, sent before the program; dump it as text.
      try {
        if (/\\/cdn-cgi\\/challenge-platform\\//.test(this.__u || '') && b && b.length > 1000
            && b.length < 20000 && !globalThis.__ptFirstBody) {
          globalThis.__ptFirstBody = 1;
          // Numbers collected so far (later ones belong to the report). Also
          // print whether our hook is still installed: an empty vector and a
          // removed hook look the same.
          globalThis.__ptCollected = 1;
          globalThis.__ptSerializing = 0;
          try {
            const strs = globalThis.__ptStrings || [];
            const s2 = JSON.stringify(strs);
            console.log('[strings] total=' + strs.length);
            for (let q = 0; q < s2.length; q += 250) {
              console.log('[strings ' + strs.length + ':' + (q / 250) + '] ' + s2.slice(q, q + 250));
            }
          } catch (e) {}
          try {
            const series = globalThis.__ptNumbers || [];
            console.log('[numbers] total=' + series.length
                  + ' hook=' + (globalThis.isFinite && globalThis.isFinite.__ptOurs ? 'ours' : 'foreign')
                  + ' name=' + (globalThis.isFinite && globalThis.isFinite.name));
            const s1 = JSON.stringify(series);
            for (let q = 0; q < s1.length; q += 250) {
              console.log('[numbers ' + series.length + ':' + (q / 250) + '] ' + s1.slice(q, q + 250));
            }
          } catch (e) {}
          const s0 = String(b);
          for (let q = 0; q < s0.length; q += 250) {
            console.log('[FIRST ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
          }
        }
      } catch (e) {}
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
  // Messages from the page to the widget frame: part of the first POST body
  // arrives this way (extraParams: stack, step timings, page snapshot).
  // Engine side: tag [postmsg].
  try {
    const inChallenge0 = () => { try { return /challenges\\.cloudflare/.test(location.host); } catch (e) { return false; } };
    const AL = EventTarget.prototype.addEventListener;
    const asNative0 = (f, src) => {
      try {
        Object.defineProperty(f, 'name', { value: src.name, configurable: true });
        Object.defineProperty(f, 'length', { value: src.length, configurable: true });
      } catch (e) {}
      return f;
    };
    EventTarget.prototype.addEventListener = asNative0(function (type, fn, opts) {
      if (inChallenge0() && String(type) === 'message' && typeof fn === 'function') {
        const wrapped = function (ev) {
          try {
            if ((globalThis.__ptMsgN = (globalThis.__ptMsgN || 0) + 1) < 25) {
              const d = ev && ev.data;
              let t;
              if (typeof d === 'string') t = d;
              else { try { t = JSON.stringify(d); } catch (e) { t = String(d); } }
              t = String(t);
              if (t.length <= 220) console.log('[postmsg] ' + t);
              else for (let q = 0; q < Math.min(t.length, 4000); q += 220) {
                console.log('[postmsg ' + t.length + ':' + (q / 220) + '] ' + t.slice(q, q + 220));
              }
            }
          } catch (e) {}
          return fn.apply(this, arguments);
        };
        return AL.call(this, type, wrapped, opts);
      }
      return AL.apply(this, arguments);
    }, AL);
  } catch (e) {}

  // The challenge runs its whole collected vector through isFinite before
  // sending: the only place values are visible one by one. The engine prints
  // the same series under NOKK_TRACE_PROBES.
  try {
    const inChallenge = () => { try { return /challenges\\.cloudflare/.test(location.host); } catch (e) { return false; } };
    const IF = globalThis.isFinite;
    const series = [];
    globalThis.__ptNumbers = series;
    const asNative = (f, src) => {
      try {
        Object.defineProperty(f, 'name', { value: src.name, configurable: true });
        Object.defineProperty(f, 'length', { value: src.length, configurable: true });
      } catch (e) {}
      return f;
    };
    globalThis.isFinite = asNative(function (x) {
      if (inChallenge() && series.length < 4000) series.push(typeof x === 'number' ? x : String(x).slice(0, 20));
      return IF.call(this, x);
    }, IF);
    try { globalThis.isFinite.__ptOurs = true; } catch (e) {}
    if (inChallenge()) console.log('[numbers] hook installed');
    // Printed at the first POST; later values belong to the report.
    const S = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = asNative(function (b) {
      try {
        if (inChallenge() && b && b.length > 1000 && b.length < 20000 && !globalThis.__ptNumbersShown) {
          globalThis.__ptNumbersShown = 1;
          const s0 = JSON.stringify(series);
          for (let q = 0; q < s0.length; q += 250) {
            console.log('[numbers ' + series.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
          }
        }
      } catch (e) {}
      return S.apply(this, arguments);
    }, S);
  } catch (e) {}

  // Plaintext read char by char (compression, stack parsing). Hot path, so
  // only index 0 and only in the challenge frame.
  try {
    const inChallenge = () => { try { return /challenges\\.cloudflare/.test(location.host); } catch (e) { return false; } };
    const CCA = String.prototype.charCodeAt;
    const seen = Object.create(null);
    const asNative = (f, src) => {
      try {
        Object.defineProperty(f, 'name', { value: src.name, configurable: true });
        Object.defineProperty(f, 'length', { value: src.length, configurable: true });
      } catch (e) {}
      return f;
    };
    String.prototype.charCodeAt = asNative(function (i) {
      if (i === 0 && this.length > 0 && this.length < 120 && globalThis.__ptSerializing && inChallenge()) {
        const series = globalThis.__ptStrings || (globalThis.__ptStrings = []);
        if (series.length < 400) series.push(String(this));
      }
      if (i === 0 && this.length > 300 && this.length < 40000 && inChallenge()) {
        const n = this.length;
        if (!seen[n] && Object.keys(seen).length < 30) {
          seen[n] = 1;
          const s0 = String(this);
          console.log('[source ' + n + '] ' + Math.round(performance.now()) + 'ms');
          for (let q = 0; q < s0.length; q += 250) {
            console.log('[source ' + n + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
          }
        }
      }
      return CCA.call(this, i);
    }, CCA);
  } catch (e) {}

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
          // First POST body is joined the same way; part lengths show which one differs.
          if (out.length > 3000 && out.length < 6000 && String(sep) === ''
              && this.length > 1 && !globalThis.__ptFirstParts) {
            globalThis.__ptFirstParts = 1;
            try {
              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
              console.log('[first parts] total=' + out.length + ' n=' + lens.length +
                    ' lengths=' + lens.join(','));
            } catch (e) {}
          }
          // Report parts and their lengths, for a per-field diff.
          if (out.length > 50000 && String(sep) === '' && this.length !== out.length && !globalThis.__ptPartsDone) {
            globalThis.__ptPartsDone = 1;
            try {
              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
              const big = lens.map((v, i) => [v, i]).sort((a, b) => b[0] - a[0]).slice(0, 25);
              console.log('[parts] n=' + lens.length + ' total=' + out.length +
                    ' largest: ' + big.map(([v, i]) => i + ':' + v).join(' '));
              const buckets = [0, 0, 0, 0, 0];
              for (const v of lens) buckets[v < 10 ? 0 : v < 100 ? 1 : v < 1000 ? 2 : v < 10000 ? 3 : 4]++;
              console.log('[parts] by size: <10=' + buckets[0] + ' <100=' + buckets[1] +
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
  // Call counts per method; the engine's probe counts the same, so a count
  // difference shows where our collection stops.
  try {
    const N = Object.create(null);
    const L = Object.create(null);
    const bump = (k) => { N[k] = (N[k] || 0) + 1; };
    // Total length of what each method returned.
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
    // The report passes through TextEncoder.encode in plaintext, before
    // compression and encryption: log each chunk's length and head.
    globalThis.__ptDumpLo = ${DUMP_LO};
    globalThis.__ptDumpHi = ${DUMP_HI};
    try {
      const TE = globalThis.TextEncoder && TextEncoder.prototype;
      const enc = TE && TE.encode;
      if (enc) {
        let n = 0;
        Object.defineProperty(TE, 'encode', { value: function (x) {
          const s = String(x == null ? '' : x);
          if (s.length > 30 && (globalThis.__encN = (globalThis.__encN || 0) + 1) < 70) {
            let at = '';
            try {
              at = String(new Error().stack || '').split('\\n').slice(2, 5)
                .map((x) => x.trim().replace(/^at /, '').slice(0, 46)).join(' < ');
            } catch (e) {}
            console.log('[enc ' + (n++) + '] ' + Math.round(performance.now()) + 'ms ' + (() => { try { return location.host.slice(0, 18) + ' '; } catch (e) { return '? '; } })() + s.length + ' | nonzero=' + (() => { let n = 0, sum = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c) { n++; sum = (sum * 31 + c) >>> 0; } } return n + ' sum=' + sum; })() + (s.length < 2000 || s.length > 14000 ? ' text: ' + s.slice(0, 400).replace(/[^\x20-\x7e]/g, '.') : ' codes: ') + Array.from(s.slice(0, 24)).map((c) => c.charCodeAt(0)).join(',') + ' | ' + Array.from(s.slice(Math.floor(s.length / 2), Math.floor(s.length / 2) + 12)).map((c) => c.charCodeAt(0)).join(','));
if (s.length >= (globalThis.__ptDumpLo || 15000) && s.length <= (globalThis.__ptDumpHi || 16000) && !(globalThis.__ptD = globalThis.__ptD || {})[s.length]) {
  globalThis.__ptD[s.length] = 1;
  for (let q = 0; q < s.length; q += 250) console.log('[chunk ' + s.length + ':' + (q / 300) + '] ' + s.slice(q, q + 300));
  console.log('[tail ' + s.length + '] parts=' + s.split('|').length + ' last=' + JSON.stringify(s.split('|').slice(-3).map((x) => x.slice(-40))));
}
          }
          return enc.call(this, x);
        }, writable: true, configurable: true });
      }
    } catch (e) {}
    // Which node's computed style is enumerated (ours came out ~300 chars
    // longer than Chrome's). Light hook: node traits, first 20 calls only.
    try {
      const G = globalThis.getComputedStyle;
      if (G && !G.__ptSaid) {
        const V = function getComputedStyle(el, ps) {
          const r = G.apply(this, arguments);
          try {
            if ((globalThis.__ptCsN = (globalThis.__ptCsN || 0) + 1) <= 20) {
              const who = (n) => !n ? '-' : (n.nodeName || '?') +
                (n.id ? '#' + n.id : '') +
                (n.className && n.className.baseVal === undefined && typeof n.className === 'string' && n.className ? '.' + n.className.slice(0, 24) : '');
              let chain = '', p = el;
              for (let i = 0; i < 4 && p; i++) { chain += (i ? ' < ' : '') + who(p); p = p.parentNode; }
              console.log('[cs] ' + who(el) + ' chain ' + chain +
                ' connected=' + (el && el.isConnected) +
                ' pseudo=' + String(ps) +
                ' doc=' + (el && el.ownerDocument === document) +
                ' color=' + (r && r.color) + ' fontSize=' + (r && r.fontSize) +' children=' + (el && el.children ? Array.prototype.map.call(el.children, (k) => k.nodeName + (k.getAttribute && k.getAttribute('style') ? '[' + k.getAttribute('style').slice(0, 40) + ']' : '')).join(',').slice(0, 160) : '?') + ' text=' + JSON.stringify(String((el && el.textContent) || '').slice(0, 40)) + ' from=' + (() => { try { return String(new Error().stack || '').split('\\n').slice(2, 4).map((x) => x.trim().replace(/^at /, '').slice(0, 60)).join(' < '); } catch (e) { return '?'; } })());
            }
          } catch (e) {}
          return r;
        };
        V.__ptSaid = 1;
        globalThis.getComputedStyle = V;
      }
    } catch (e) {}
    // SVG text metrics: used on emoji to see which sequences render as one glyph.
    try {
      const P = globalThis.SVGTextContentElement && SVGTextContentElement.prototype;
      for (const name of ['getComputedTextLength', 'getSubStringLength', 'getNumberOfChars',
          'getExtentOfChar', 'getStartPositionOfChar', 'getEndPositionOfChar']) {
        const f = P && P[name];
        if (!f || f.__ptSaid) continue;
        const V = function (...a) {
          const r = f.apply(this, a);
          try {
            if ((globalThis.__ptSvgN = (globalThis.__ptSvgN || 0) + 1) <= 40) {
              const show = (v) => (v && typeof v === 'object'
                ? '{' + ['x', 'y', 'width', 'height'].map((k) => k + '=' + (v[k] === undefined ? '?' : v[k])).join(',') + '}'
                : String(v));
              console.log('[svg] ' + name + '(' + a.join(',') + ') font=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' text=' +
                JSON.stringify(String(this.textContent || '').slice(0, 70)) + ' -> ' + show(r));
            }
          } catch (e) {}
          return r;
        };
        V.__ptSaid = 1;
        try { Object.defineProperty(V, 'name', { value: name }); } catch (e) {}
        Object.defineProperty(P, name, { value: V, writable: true, configurable: true });
      }
      const G = globalThis.SVGGraphicsElement && SVGGraphicsElement.prototype;
      const bb = G && G.getBBox;
      if (bb && !bb.__ptSaid) {
        const V = function getBBox(...a) {
          const r = bb.apply(this, a);
          try {
            if ((globalThis.__ptBBoxN = (globalThis.__ptBBoxN || 0) + 1) <= 40) {
              console.log('[svg] getBBox font=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' text=' +
                JSON.stringify(String(this.textContent || '').slice(0, 70)) +
                ' -> {' + [r.x, r.y, r.width, r.height].join(',') + '}');
            }
          } catch (e) {}
          return r;
        };
        V.__ptSaid = 1;
        Object.defineProperty(G, 'getBBox', { value: V, writable: true, configurable: true });
      }
    } catch (e) {}
    // JSON.stringify and btoa inputs: the initial payload is built this way.
    try {
      const J = JSON.stringify;
      if (!J.__ptSaid) {
        const V = function stringify(...a) {
          const r = J.apply(this, a);
          try {
            if (typeof r === 'string' && r.length > 300
                && (globalThis.__ptJsonN = (globalThis.__ptJsonN || 0) + 1) <= 6) {
              for (let q = 0; q < Math.min(r.length, 4000); q += 250) {
                console.log('[json ' + r.length + ':' + (q / 250) + '] ' + r.slice(q, q + 250));
              }
            }
          } catch (e) {}
          return r;
        };
        V.__ptSaid = 1;
        JSON.stringify = V;
      }
      const B = globalThis.btoa;
      if (B && !B.__ptSaid) {
        const V = function btoa(x) {
          const s0 = String(x);
          try {
            if (s0.length > 300 && (globalThis.__ptBtoaN = (globalThis.__ptBtoaN || 0) + 1) <= 4) {
              for (let q = 0; q < Math.min(s0.length, 4000); q += 250) {
                console.log('[btoa ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
              }
            }
          } catch (e) {}
          return B.call(this, x);
        };
        V.__ptSaid = 1;
        globalThis.btoa = V;
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
    // Which canvas contexts are requested and what comes back.
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
                        a.push((v.localName || (v.constructor && v.constructor.name) || 'obj') +
                          '<' + (v.width !== undefined ? v.width + 'x' + v.height : '?') + '>' +
                          (typeof v.src === 'string' ? ' src=' + v.src.slice(0, 46) : ''));
                      } else a.push(String(v).slice(0, 40));
                    }
                    console.log('[c48] #' + globalThis.__ptCvId(cv) + ' ' + cv.width + ' ' + k + '(' + a.join(',') + ')' +
                      (cv.width !== 2 ? '' : (() => { try { const r = f.apply(this, arguments);
                        return ' -> ' + (r && typeof r === 'object' ? (r.data
                          ? Object.prototype.toString.call(r.data) + '[' + [].slice.call(r.data).join(',') + '] ' + r.colorSpace + '/' + r.pixelFormat
                          : JSON.stringify(r)) : String(r)); } catch (e) { return ' -> threw ' + e.name; } })()));
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
                    ' options=' + JSON.stringify(arguments[4] || null) +
                    ' canvas=' + JSON.stringify(this.getContextAttributes ? this.getContextAttributes() : null);
                } catch (e) { show = ' -> ' + e.name; }
              }
              console.log('[gid] #' + globalThis.__ptCvId(this.canvas) + ' ' + w + 'x' + h + ' on ' + (this.canvas ? this.canvas.width + 'x' + this.canvas.height : '?') + show);
              return r;
            };
          }
          // Full WebGPU trace.
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
                        catch (e) { return (v.constructor && v.constructor.name) || 'obj'; }
                      }
                      return String(v).slice(0, 40);
                    });
                    const r = f.apply(this, args);
                    const shown = r && typeof r === 'object'
                      ? ((r.constructor && r.constructor.name) || 'obj') : String(r).slice(0, 30);
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
                try { r = f.apply(this, arguments); } catch (e) { console.log('[gpu] ' + k + ' threw ' + e.name); throw e; }
                if (r && typeof r.then === 'function') {
                  return r.then((v) => { console.log('[gpu] ' + k + ' -> ' + (v ? 'object' : String(v))); return v; },
                                (e) => { console.log('[gpu] ' + k + ' rejected ' + e); throw e; });
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
                  ' options=' + (a ? JSON.stringify(a) : '-') + ' -> ' + (err || (r ? 'ok' : String(r))));
              // 49x44 canvas: trace the first ops to see how the third differs from the first two.
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
    setTimeout(() => {
      const rows = Object.entries(N).sort((a, b) => (L[b[0]] || 0) - (L[a[0]] || 0));
      for (const [k, v] of rows) console.log('[count] ' + v + ' calls, ' + (L[k] || 0) + ' chars — ' + k);
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
      if (/^\[(send|hook|hookerr|blob|worker|count|thrown|time|first|source|numbers|postmsg)\]|^\[[jPC]\d* |^\[cs\]|^\[strings |^\[postmsg |^\[numbers |^\[source |^\[FIRST |^\[svg\]|^\[tail |^\[parts|^\[audio |^\[json |^\[btoa |^\[chunk |^\[enc |^\[octx\]|^\[cop\]|^\[rp\]|^\[gid\]|^\[c48\]|^\[stop\]|^\[c49\]|^\[gpu\]|^\[ectx\]/.test(String(t)))
        lines.push(String(Date.now() - t0).padStart(6) + 'ms ' + t);
    }
    // A failing hook injection is only visible here; otherwise the tape is silently empty.
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails || {};
      lines.push('[hook failed] ' + (d.text || '') + ' ' +
        ((d.exception && (d.exception.description || d.exception.value)) || '').slice(0, 200));
    }
    if (m.method === 'Target.attachedToTarget') {
      const s = m.params.sessionId;
      lines.push('[target] ' + (m.params.targetInfo && m.params.targetInfo.url || '').slice(0, 60));
      send('Runtime.enable', {}, s);
      send('Page.enable', {}, s);
      send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }, s);
      // Also inject into the existing document: the widget frame may already
      // be created at attach time, too late for addScriptToEvaluateOnNewDocument.
      send('Runtime.evaluate', { expression: HOOK, includeCommandLineAPI: false }, s);
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
