//! `nokk` — CLI entry point.
//!
//! Wires up configuration, logging and the engine, then dispatches on the flags:
//! one-shot `--fetch`/`--eval`/`--load` modes, or (the default) a CDP WebSocket
//! server on `--port` that Puppeteer can attach to.

use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use nokk::{BrowserContext, Engine, EngineConfig, PoolConfig};
use nokk_net::ClientConfig;

/// Headless browser-emulation engine with a Chrome-compatible fingerprint.
#[derive(Debug, Parser)]
#[command(name = "nokk", version, about)]
struct Cli {
    /// CDP WebSocket port. With no one-shot flag, nokk runs as a CDP server on
    /// this port for Puppeteer to connect to.
    #[arg(long, env = "NOKK_PORT", default_value_t = 9222)]
    port: u16,

    /// Address the CDP server binds to. Defaults to loopback; set `0.0.0.0` to
    /// accept connections from other hosts (e.g. inside a Docker container).
    #[arg(long, env = "NOKK_HOST", default_value = "127.0.0.1")]
    host: std::net::IpAddr,

    /// Number of isolate worker threads. Defaults to available parallelism.
    #[arg(long, env = "NOKK_WORKERS")]
    workers: Option<usize>,

    /// Maximum number of simultaneously live contexts (memory backpressure).
    #[arg(long, env = "NOKK_MAX_CONTEXTS")]
    max_contexts: Option<usize>,

    /// Cap each worker isolate's JS heap, in MB (shared across that worker's
    /// contexts). Total JS heap is bounded by roughly `workers * this`. A page
    /// that exceeds it fails with an out-of-memory error instead of the process
    /// growing unbounded. Unset = V8 default.
    #[arg(long, env = "NOKK_MAX_HEAP_MB")]
    max_heap_mb: Option<usize>,

    /// Log filter, e.g. `info`, `nokk_pool=debug`.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,

    /// One-shot: fetch this URL through the Chrome-fingerprinted HTTP client
    /// (JA3/JA4 + HTTP/2), print the response, and exit.
    #[arg(long, value_name = "URL")]
    fetch: Option<String>,

    /// One-shot: evaluate this JavaScript, print the result, and exit. Runs in a
    /// fresh stealth context, or — combined with `--load` — against the loaded
    /// page's DOM. E.g. `--eval navigator.webdriver`, or
    /// `--load <url> --eval 'document.title'`.
    #[arg(long, value_name = "JS")]
    eval: Option<String>,

    /// One-shot: navigate to this URL (fetch, build the DOM, run page scripts,
    /// fire DOMContentLoaded/load), print a summary, and exit. Enables real
    /// networking. Pair with `--eval` to probe the resulting DOM.
    #[arg(long, value_name = "URL")]
    load: Option<String>,

    /// Wait for a challenge widget to finish, pressing whatever it puts up —
    /// a checkbox, a switch — the way a person would. The engine can reach the
    /// control (widgets keep it in a closed shadow root inside a cross-origin
    /// frame, where page script cannot); a driver only says how long to wait, in
    /// seconds. Stops early once a `cf_clearance` is in the jar.
    #[arg(long, value_name = "SECONDS", num_args = 0..=1, default_missing_value = "60")]
    solve_challenge: Option<u64>,

    /// Route all requests through a proxy, e.g.
    /// `http://user:pass@host:port` or `socks5://host:port`. Essential for
    /// IP rotation against WAFs like Cloudflare (a burned IP gets an instant 403).
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Directory for persistent, named sessions. When set, a Puppeteer browser
    /// context named via `createBrowserContext` persists its cookie jar (login
    /// state, `cf_clearance`, …) to `<dir>/<name>.json`, so you can warm a session
    /// once and resume it in a later run. Unset = sessions are in-memory only.
    #[arg(long, env = "NOKK_SESSION_STORE", value_name = "DIR")]
    session_store: Option<std::path::PathBuf>,

    /// For `--load`: bind the navigation to a named session (its cookie jar is
    /// reused). Pair with `--import-cookies` to preload a harvested clearance.
    #[arg(long, value_name = "NAME")]
    session: Option<String>,

    /// For `--load`: import cookies from a JSON file into the `--session` jar
    /// before navigating — e.g. a `cf_clearance.json` harvested by nokk-cf
    /// (`{ "cookies": { name: value, … }, "domain": "…", "url": "…" }`). Replay
    /// only works if this engine's Chrome emulation + exit IP match the harvester.
    #[arg(long, value_name = "FILE")]
    import_cookies: Option<std::path::PathBuf>,

    /// Load ad/analytics/tracker scripts instead of dropping them. Tracker
    /// blocking is on by default (trims the passive-fingerprinting surface and
    /// speeds loads); pass this to disable it.
    #[arg(long, env = "NOKK_ALLOW_TRACKERS")]
    allow_trackers: bool,

    /// Give each browser context its own coherent fingerprint (OS, UA, screen,
    /// WebGL, and a matching TLS emulation), selected deterministically from the
    /// context's identity. Off by default; useful when driving many isolated
    /// contexts that should each look like a different machine.
    #[arg(long, env = "NOKK_ROTATE_FINGERPRINT")]
    rotate_fingerprint: bool,

    /// Derive each context's timezone and locale from its proxy's exit IP, so the
    /// reported `Intl` timezone and `navigator.languages` match where the traffic
    /// comes from. Costs one geolocation request per distinct proxy (cached),
    /// made through that proxy. Best-effort; no effect without a proxy.
    #[arg(long, env = "NOKK_GEOIP_TIMEZONE")]
    geoip_timezone: bool,

    /// Chrome major version to emulate (TLS fingerprint + JS UA together), e.g.
    /// `148`. Defaults to current stable; set it to match the browser a reused
    /// `cf_clearance` was minted under. Bounded by what wreq-util ships — an
    /// unavailable version falls back to the default.
    #[arg(long, env = "NOKK_CHROME_VERSION", value_name = "MAJOR")]
    chrome_version: Option<u32>,

    /// For `--load`: retry up to N extra times if the response is a Cloudflare
    /// "Just a moment…" challenge (the pass is probabilistic).
    #[arg(long, default_value_t = 0)]
    retries: u32,

    /// For `--load`: after loading, print every network request the page made
    /// (document + scripts + fetch/XHR) as `[type] METHOD url → status (N bytes)`.
    #[arg(long)]
    dump_requests: bool,

    /// For `--load`: print the response *body* of the first captured request
    /// whose URL contains this substring (e.g. an `/api/...` JSON call).
    #[arg(long, value_name = "URL_SUBSTR")]
    dump_request: Option<String>,
}

/// Parse a `scheme://[user:pass@]host:port` proxy URL into a `ProxyConfig`.
fn parse_proxy(s: &str) -> Option<nokk_net::ProxyConfig> {
    let u = url::Url::parse(s).ok()?;
    let scheme = match u.scheme() {
        "http" | "https" => nokk_net::ProxyScheme::Http,
        "socks5" | "socks5h" => nokk_net::ProxyScheme::Socks5,
        _ => return None,
    };
    Some(nokk_net::ProxyConfig {
        scheme,
        host: u.host_str()?.to_string(),
        port: u.port()?,
        username: (!u.username().is_empty()).then(|| u.username().to_string()),
        password: u.password().map(|p| p.to_string()),
    })
}

/// Import cookies from a harvested-clearance JSON file into a named session.
///
/// Expects the shape nokk-cf writes: `{ "cookies": { name: value, … }, "domain":
/// "…", "url": "…" }`. Each cookie is stored as if the origin had set it for the
/// domain, so the session's next request replays them.
fn import_cookies_file(engine: &Engine, session: &str, path: &std::path::Path) -> Result<()> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&data)?;
    let domain = v
        .get("domain")
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"domain\""))?;
    let origin = v
        .get("url")
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"url\""))?;
    let cookies = v
        .get("cookies")
        .and_then(|c| c.as_object())
        .ok_or_else(|| anyhow::anyhow!("cookie file missing \"cookies\" object"))?;
    let mut n = 0;
    for (name, value) in cookies {
        let Some(value) = value.as_str() else {
            continue;
        };
        let set_cookie = format!("{name}={value}; Domain={domain}; Path=/; Secure");
        engine
            .import_session_cookie(session, &set_cookie, origin)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        n += 1;
    }
    eprintln!("imported {n} cookies into session '{session}' for {domain}");
    Ok(())
}

/// Render an eval result for the terminal: unwrap a JSON string to its raw text
/// (so newlines/quotes render naturally); print other values as-is.
fn render(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Evaluate `js`, then drive the event loop so any `fetch`/timers it starts
/// complete, and print the result. If the expression is (or resolves to) a
/// Promise, the *resolved* value is printed; otherwise the value itself.
async fn eval_and_print(ctx: &BrowserContext, js: &str) -> Result<()> {
    // Route both sync values and Promise resolutions through `__out`.
    let wrapped = format!(
        "(() => {{ globalThis.__outDone = false; const v = ({js}); \
           if (v && typeof v.then === 'function') {{ \
             v.then(x => {{ globalThis.__out = x; globalThis.__outDone = true; }}, \
                    e => {{ globalThis.__out = 'ERR: ' + e; globalThis.__outDone = true; }}); \
           }} else {{ globalThis.__out = v; globalThis.__outDone = true; }} \
           return undefined; }})()"
    );
    if let Err(e) = ctx.evaluate(&wrapped).await {
        eprintln!("eval error: {e}");
        std::process::exit(1);
    }
    // Один оборот круга доводит микрозадачи — но не таймер и не воркера, а
    // всякая интересная проба ждёт именно их: `undefined` вместо ответа было
    // свойством измерителя, а не измеряемого. Крутим, пока обещание не решится.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        ctx.run_event_loop().await.ok();
        // `evaluate` отдаёт результат строкой, а не логическим значением, и
        // сравнение с `Bool(true)` не совпадало никогда — каждый `--eval` ждал
        // все пятнадцать секунд до упора, даже когда ответ был готов сразу.
        let done = ctx.evaluate("globalThis.__outDone === true").await;
        let ready = matches!(&done, Ok(serde_json::Value::Bool(true)))
            || matches!(&done, Ok(serde_json::Value::String(s)) if s == "true");
        if ready || Instant::now() > deadline {
            break;
        }
        // Миллисекунда, а не десять: на десяти кадры анимации ложатся на
        // чужую сетку, и `requestAnimationFrame` отбивает то двенадцать
        // миллисекунд, то двадцать четыре вместо ровных 16,7.
        tokio::time::sleep(Duration::from_micros(500)).await;
    }
    let out = ctx
        .evaluate(
            "globalThis.__out === undefined ? 'undefined' \
             : (typeof globalThis.__out === 'object' ? JSON.stringify(globalThis.__out) : String(globalThis.__out))",
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", render(&out));
    Ok(())
}

impl Cli {
    fn engine_config(&self) -> EngineConfig {
        let mut pool = PoolConfig::default();
        if let Some(w) = self.workers {
            pool.workers = w.max(1);
        }
        if let Some(m) = self.max_contexts {
            pool.max_live_contexts = m.max(1);
        }
        if let Some(mb) = self.max_heap_mb {
            pool.max_heap_mb = Some(mb.max(16)); // a tiny cap would fail instantly
        }
        let mut client = ClientConfig::default();
        if let Some(spec) = &self.proxy {
            match parse_proxy(spec) {
                Some(p) => client.proxy = Some(p),
                None => eprintln!("warning: could not parse --proxy '{spec}', ignoring"),
            }
        }
        EngineConfig {
            pool,
            client,
            // The CLI always drives real traffic (one-shot fetch/load/eval or the
            // CDP server); only the library test harness stays offline.
            use_real_network: true,
            session_store: self.session_store.clone(),
            block_trackers: !self.allow_trackers,
            rotate_fingerprint: self.rotate_fingerprint,
            geoip_timezone: self.geoip_timezone,
            chrome_major: self
                .chrome_version
                .unwrap_or(nokk_net::DEFAULT_CHROME_MAJOR),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log))
        .with_target(true)
        .init();

    let started = Instant::now();
    let engine = Engine::new(cli.engine_config())?;
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        workers = engine.worker_count(),
        "engine ready"
    );

    // One-shot fetch mode: prove the network path end-to-end.
    if let Some(url) = &cli.fetch {
        let t = Instant::now();
        let resp = engine.fetch(url).await?;
        let body = String::from_utf8_lossy(&resp.body);
        tracing::info!(
            status = resp.status,
            bytes = resp.body.len(),
            elapsed_ms = t.elapsed().as_millis(),
            "fetch complete"
        );
        println!("HTTP {} — {}", resp.status, url);
        println!("{body}");
        return Ok(());
    }

    // One-shot load mode: navigate to a URL, then optionally probe the DOM.
    if let Some(url) = &cli.load {
        let t = Instant::now();
        let session = cli.session.clone();
        let proxy = cli.proxy.as_deref().and_then(parse_proxy);
        // Preload a harvested clearance (cf_clearance.json) into the session so the
        // navigation carries it — cookie replay for a Cloudflare-gated site.
        if let Some(path) = &cli.import_cookies {
            let name = session
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--import-cookies requires --session"))?;
            import_cookies_file(&engine, name, path)?;
        }
        // Retry on a Cloudflare challenge (the pass is probabilistic). Without a
        // session each try is a fresh context so a poisoned session doesn't carry
        // over; a named session deliberately reuses its (imported) jar.
        let mut ctx = None;
        for attempt in 0..=cli.retries {
            let c = match &session {
                Some(name) => {
                    engine
                        .new_context_with_session(name.clone(), proxy.clone())
                        .await?
                }
                None => engine.new_context().await?,
            };
            // Узкий инструмент: только конструктор `Error`, и только чтобы
            // прочитать, на чём споткнулась чужая программа. Всё, что шире —
            // подмена `JSON.stringify`, `Array.join`, `String.fromCharCode` —
            // меняет ход челленджа и рассказывает про измеритель, а не про
            // измеряемое. Этот же виден только через `toString`, а он замаскирован.
            if std::env::var("NOKK_TRACE_THROWS").is_ok() {
                let probe = r#"(() => {
                  // Заодно — кто и с чем зовёт раскодировщик: пустой буфер там,
                  // где у браузера данные, виден только так.
                  // И кто просит пиксели: пустой ответ у нас против данных у
                  // браузера означает холст нулевого размера.
                  try {
                    const C = globalThis.CanvasRenderingContext2D;
                    if (C && C.prototype && C.prototype.getImageData) {
                      const G = C.prototype.getImageData;
                      C.prototype.getImageData = function (x, y, w, h) {
                        try {
                          const c = this.canvas || {};
                          console.error('[pixels] просят ' + w + 'x' + h + ' у холста ' +
                                        c.width + 'x' + c.height + ' (' + (c.id || c.className || '') + ')');
                        } catch (e) {}
                        return G.apply(this, arguments);
                      };
                    }
                  } catch (e) {}
                  globalThis.__pt_decodeSpy = (buf) => {
                    try {
                      if (Object.prototype.toString.call(buf) !== '[object ArrayBuffer]') return;
                      // Челлендж занижает `stackTraceLimit` и подменяет
                      // `prepareStackTrace`, чтобы спрятать свои кадры;
                      // снимаем поверх этого.
                      const lim = Error.stackTraceLimit;
                      const prep = Error.prepareStackTrace;
                      try { Error.stackTraceLimit = 30; Error.prepareStackTrace = undefined; } catch (e) {}
                      const snap = String(new Error().stack || '');
                      try { Error.stackTraceLimit = lim; Error.prepareStackTrace = prep; } catch (e) {}
                      const st = snap.split('\n').slice(2, 8)
                        .map((l) => l.trim()).join(' | ');
                      console.error('[decode] ArrayBuffer ' + buf.byteLength + ' байт @ ' + st.slice(0, 330));
                    } catch (e) {}
                  };
                  const E = globalThis.Error;
                  const seen = [];
                  globalThis.__pt_throwTail = (n) => seen.slice(-(n || 12)).join('\n');
                  const Wrapped = function Error(...a) {
                    const e = new E(...a);
                    try {
                      const where = String(e.stack || '').split('\n').slice(1, 3)
                        .map((l) => l.trim()).join(' | ');
                      seen.push(String(a[0] === undefined ? '' : a[0]).slice(0, 160) + ' @ ' + where.slice(0, 200));
                      if (seen.length > 400) seen.shift();
                    } catch (e2) {}
                    return e;
                  };
                  Wrapped.prototype = E.prototype;
                  for (const k of Object.getOwnPropertyNames(E)) {
                    if (k === 'prototype' || k === 'name' || k === 'length') continue;
                    try { Wrapped[k] = E[k]; } catch (e2) {}
                  }
                  try { Object.defineProperty(E.prototype, 'constructor', { value: Wrapped, writable: true, configurable: true }); } catch (e2) {}
                  globalThis.Error = globalThis.__pt_native ? __pt_native(Wrapped) : Wrapped;
                })();"#;
                c.add_frame_init_script(probe.to_string());
                c.add_init_script(probe.to_string());
            }
            // Откуда шлют маяк ошибки. Челлендж стучит на `/eb/`, когда у него
            // что-то не сложилось, — а браузер на том же месте не стучит вовсе.
            // Тело маяка зашифровано, но место, откуда его отправили, читается
            // из стека. Пробник нарочно узкий: один крючок на отправку и ничего
            // больше — всякая лишняя подмена меняет то, что мы измеряем.
            if std::env::var("NOKK_TRACE_BEACON").is_ok() {
                let probe = r#"(() => {
                  globalThis.__ptEncMin = __ENCMIN__;
                  try {
                    const S = XMLHttpRequest.prototype.send;
                    const O = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) {
                      this.__ptU = String(u);
                      return O.apply(this, arguments);
                    };
                    XMLHttpRequest.prototype.send = function (b) {
                      try {
                        // Отчёт уходит — значит сбор закончен, самое время
                        // высыпать счётчики.
                        if (/\/fo\//.test(this.__ptU || '') && b && b.length > 50000) {
                          try { globalThis.__ptDumpCounts && __ptDumpCounts(); } catch (e) {}
                          try {
                            const T = globalThis.__ptTime || {};
                            const rows = Object.keys(T).map((k) => [k, T[k]]).sort((x, y) => y[1] - x[1]).slice(0, 14);
                            for (const [k, v] of rows) {
                              console.error('[время] ' + Math.round(v) + 'мс — ' + k);
                            }
                          } catch (e) {}
                        }
                        // Оракул по размерам: какая программа пришла в ответ на
                        // первый POST и чем ответили на отчёт. Расшифрованная
                        // длина, а не сжатая, — сравнивать с Chrome через
                        // `tools/netwatch.js`.
                        // Тело первого POST — то, что уходит до программы. У нас оно
                        // на полсотни знаков короче хромовского, и разница видна только
                        // текстом.
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU || '') && b && b.length > 1000
                            && b.length < 20000 && !globalThis.__ptFirstBody) {
                          globalThis.__ptFirstBody = 1;
                          const s0 = String(b);
                          for (let q = 0; q < s0.length; q += 250) {
                            console.error('[ПЕРВЫЙ ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
                          }
                        }
                        if (/\/cdn-cgi\/challenge-platform\//.test(this.__ptU || '')) {
                          const url = this.__ptU, t0 = Math.round(performance.now());
                          const sent = (b && b.length) || 0;
                          this.addEventListener('loadend', () => {
                            let got = 0;
                            try { got = (this.responseText || '').length; } catch (e) {}
                            console.error('[xhr] ' + t0 + 'мс тело=' + sent + ' → ' + this.status +
                                          ' ответ=' + got + ' за ' + (Math.round(performance.now()) - t0) +
                                          'мс ' + url.slice(-46));
                          });
                        }
                        if (/\/eb\//.test(this.__ptU || '')) {
                          const at = String(new Error().stack || '(без стека)');
                          for (const line of at.split('\n').slice(0, 14)) {
                            console.error('[beacon] ' + line.trim().slice(0, 220));
                          }
                          console.error('[beacon] размер=' + ((b && b.length) || 0));
                        }
                      } catch (e) {}
                      return S.apply(this, arguments);
                    };
                    // Счётчик обращений к тому, чего наш обычный пробник не
                    // видит: сборщик у браузера зовёт эти вещи, и надо знать,
                    // доходит ли до них наш прогон.
                    const N = Object.create(null);
                    const L = Object.create(null);
                    const bump = (k) => { N[k] = (N[k] || 0) + 1; };
                    const grew = (k, v) => {
                      try {
                        const n = v == null ? 0 : (typeof v === 'string' ? v.length
                          : (typeof v === 'number' || typeof v === 'boolean' ? String(v).length
                          : (v.length !== undefined && typeof v.length === 'number' ? v.length : 0)));
                        L[k] = (L[k] || 0) + n;
                      } catch (e) {}
                    };
                    const count = (obj, label, names) => {
                      if (!obj) return;
                      for (const n of names) {
                        const f = obj[n];
                        if (typeof f !== 'function') continue;
                        try {
                          Object.defineProperty(obj, n, {
                            value: function (...a) {
                              bump(label + '.' + n);
                              const t0 = performance.now();
                              const r = f.apply(this, a);
                              // Сколько времени ушло на каждый вызов: челлендж
                              // меряет себя сам, и медленный ответ виден ему
                              // не хуже неправильного.
                              try {
                                const key = label + '.' + n;
                                const T = (globalThis.__ptTime = globalThis.__ptTime || {});
                                T[key] = (T[key] || 0) + (performance.now() - t0);
                              } catch (e) {}
                              grew(label + '.' + n, r);
                              return r;
                            },
                            writable: true, enumerable: false, configurable: true,
                          });
                        } catch (e) {}
                      }
                    };
                    // Отчёт проходит через `TextEncoder.encode` до сжатия и
                    // шифрования: его куски видны здесь в открытом виде. Крючок
                    // ставится с повтором — сам кодировщик появляется позже
                    // пробника.
                    {
                      let en = 0;
                      const arm = () => {
                        const TE = globalThis.TextEncoder && globalThis.TextEncoder.prototype;
                        const enc = TE && TE.encode;
                        if (!enc || enc.__ptWrapped) return !!enc;
                        const wrapped = function (x) {
                          const s = String(x == null ? '' : x);
                          if (s.length > (globalThis.__ptEncMin || 30) && (globalThis.__encN = (globalThis.__encN || 0) + 1) < 70) {
                            let at = '';
                            try {
                              at = String(new Error().stack || '').split('\n').slice(2, 5)
                                .map((x) => x.trim().replace(/^at /, '').slice(0, 46)).join(' < ');
                            } catch (e) {}
                            console.error('[enc ' + (en++) + '] ' + Math.round(performance.now()) + 'мс ' + (() => { try { return location.host.slice(0, 18) + ' '; } catch (e) { return '? '; } })() + s.length + ' | ненулевых=' + (() => { let n = 0, sum = 0; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c) { n++; sum = (sum * 31 + c) >>> 0; } } return n + ' сумма=' + sum; })() + (s.length < 2000 || s.length > 14000 ? ' текст: ' + s.slice(0, 400).replace(/[^\x20-\x7e]/g, '.') : ' коды: ') + Array.from(s.slice(0, 24)).map((c) => c.charCodeAt(0)).join(',') + ' | ' + Array.from(s.slice(Math.floor(s.length / 2), Math.floor(s.length / 2) + 12)).map((c) => c.charCodeAt(0)).join(','));
if (s.length >= __DUMPLO__ && s.length <= __DUMPHI__ && !(globalThis.__ptD = globalThis.__ptD || {})[s.length]) {
  globalThis.__ptD[s.length] = 1;
  for (let q = 0; q < s.length; q += 250) console.error('[кус ' + s.length + ':' + (q / 300) + '] ' + s.slice(q, q + 300));
  console.error('[хвост ' + s.length + '] куски=' + s.split('|').length + ' последние=' + JSON.stringify(s.split('|').slice(-3).map((x) => x.slice(-40))));
}
                          }
                          return enc.call(this, x);
                        };
                        wrapped.__ptWrapped = true;
                        try {
                          Object.defineProperty(TE, 'encode', { value: wrapped, writable: true, configurable: true });
                          return true;
                        } catch (e) { return false; }
                      };
                      if (!arm()) {
                        let tries = 0;
                        const t = setInterval(() => { if (arm() || ++tries > 40) clearInterval(t); }, 25);
                      }
                    }
                    // Чей стиль перечисляют. Челлендж высыпает весь
                    // вычисленный стиль одного узла, и у нас он выходит на
                    // триста знаков длиннее хромовского: значит меряется не
                    // тот узел или не в том окружении. Крючок лёгкий —
                    // только приметы узла, по двадцать первых вызовов.
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
                              console.error('[cs] ' + who(el) + ' в цепочке ' + chain +
                                ' связан=' + (el && el.isConnected) +
                                ' псевдо=' + String(ps) +
                                ' док=' + (el && el.ownerDocument === document) +
                                ' цвет=' + (r && r.color) + ' кегль=' + (r && r.fontSize) +' дети=' + (el && el.children ? Array.prototype.map.call(el.children, (k) => k.nodeName + (k.getAttribute && k.getAttribute('style') ? '[' + k.getAttribute('style').slice(0, 40) + ']' : '')).join(',').slice(0, 160) : '?') + ' текст=' + JSON.stringify(String((el && el.textContent) || '').slice(0, 40)) + ' откуда=' + (() => { try { return String(new Error().stack || '').split('\n').slice(2, 4).map((x) => x.trim().replace(/^at /, '').slice(0, 60)).join(' < '); } catch (e) { return '?'; } })());
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        globalThis.getComputedStyle = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                    } catch (e) {}
                    // Чем меряют надписи в SVG: у эмодзи это способ узнать,
                    // какие последовательности браузер сводит в один знак.
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
                              console.error('[svg] ' + name + '(' + a.join(',') + ') шрифт=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' текст=' +
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
                              console.error('[svg] getBBox шрифт=' + (() => { try { const cs = getComputedStyle(this); return cs.fontSize + '/' + cs.fontFamily.slice(0, 20); } catch (e) { return '?'; } })() + ' текст=' +
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
                    // Что страница склеивает в JSON и что кодирует в base64:
                    // начальная посылка собирается именно так, и её содержимое
                    // видно только здесь.
                    try {
                      const J = JSON.stringify;
                      if (!J.__ptSaid) {
                        const V = function stringify(...a) {
                          const r = J.apply(this, a);
                          try {
                            if (typeof r === 'string' && r.length > 300
                                && (globalThis.__ptJsonN = (globalThis.__ptJsonN || 0) + 1) <= 6) {
                              for (let q = 0; q < Math.min(r.length, 4000); q += 250) {
                                console.error('[json ' + r.length + ':' + (q / 250) + '] ' + r.slice(q, q + 250));
                              }
                            }
                          } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        JSON.stringify = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                      const B = globalThis.btoa;
                      if (B && !B.__ptSaid) {
                        const V = function btoa(x) {
                          const s0 = String(x);
                          try {
                            if (s0.length > 300 && (globalThis.__ptBtoaN = (globalThis.__ptBtoaN || 0) + 1) <= 4) {
                              for (let q = 0; q < Math.min(s0.length, 4000); q += 250) {
                                console.error('[btoa ' + s0.length + ':' + (q / 250) + '] ' + s0.slice(q, q + 250));
                              }
                            }
                          } catch (e) {}
                          return B.call(this, x);
                        };
                        V.__ptSaid = 1;
                        globalThis.btoa = globalThis.__pt_native ? __pt_native(V) : V;
                      }
                    } catch (e) {}
                    count(globalThis.OfflineAudioContext && OfflineAudioContext.prototype, 'audio',
                          ['startRendering', 'createOscillator', 'createDynamicsCompressor']);
                    count(globalThis.HTMLMediaElement && HTMLMediaElement.prototype, 'media', ['canPlayType']);
                    // Что именно спрашивают про кодеки и что мы ответили:
                    // Chrome на том же списке даёт другие слова, а список
                    // нужен целиком, чтобы сверить его offline.
                    try {
                      const M = globalThis.HTMLMediaElement && HTMLMediaElement.prototype;
                      const C = M && M.canPlayType;
                      if (C && !C.__ptSaid) {
                        const V = function canPlayType(t) {
                          const r = C.apply(this, arguments);
                          try { console.error('[кодек] ' + String(t) + ' -> ' + String(r)); } catch (e) {}
                          return r;
                        };
                        V.__ptSaid = 1;
                        Object.defineProperty(M, 'canPlayType',
                          { value: globalThis.__pt_native ? __pt_native(V) : V,
                            writable: true, enumerable: false, configurable: true });
                      }
                    } catch (e) {}
                    count(globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype, 'canvas',
                          ['transferControlToOffscreen', 'toDataURL', 'toBlob', 'captureStream', 'getContext']);
                    count(globalThis.OffscreenCanvas && OffscreenCanvas.prototype, 'off',
                          ['convertToBlob', 'transferToImageBitmap']);
                    try {
                        for (const N of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
                          const W = globalThis[N] && globalThis[N].prototype;
                          if (!W || !W.readPixels || W.__ptRp) continue;
                          try { Object.defineProperty(W, '__ptRp', { value: 1 }); } catch (e) {}
                          const rp = W.readPixels;
                          W.readPixels = function (x, y, w, h, f, t, p) {
                            console.error('[rp] ' + N + ' ' + w + 'x' + h);
                            return rp.apply(this, arguments);
                          };
                        }
                        const HC = globalThis.HTMLCanvasElement && globalThis.HTMLCanvasElement.prototype;
                        if (HC && HC.getContext && !HC.__ptGc) {
                          try { Object.defineProperty(HC, '__ptGc', { value: 1 }); } catch (e) {}
                          const hg = HC.getContext;
                          HC.getContext = function (ty, a) {
                            const r = hg.apply(this, arguments);
                            console.error('[ectx] ' + ty + ' ' + this.width + 'x' + this.height +
                                ' -> ' + (r ? 'ok' : String(r)));
                            return r;
                          };
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
                                show = ' -> ' + Object.prototype.toString.call(r.data) + '[' + [].slice.call(r.data).join(',') + '] ' +
                                  r.colorSpace + '/' + r.pixelFormat + ' настройки=' + JSON.stringify(arguments[4] || null) +
                                  ' холст=' + JSON.stringify(this.getContextAttributes ? this.getContextAttributes() : null);
                              } catch (e) { show = ' -> ' + e.name; }
                            }
                            console.error('[gid] ' + w + 'x' + h + ' на ' + (this.canvas ? this.canvas.width + 'x' + this.canvas.height : '?') + show);
                            return r;
                            
                          };
                        }
                        // Челлендж ловит свои исключения сам и докладывает о них
                        // на `/eb/`. Ловушка на самом рождении ошибки — самое
                        // лёгкое, что можно поставить: конструктор, а не метод.
                        // Маяк `/eb/` уходит зашифрованным, но перед шифром
                        // челлендж сериализует пойманную ошибку сам —
                        // `JSON.stringify(err, Object.getOwnPropertyNames(err))`.
                        // Здесь она видна открытым текстом. Крючок срабатывает
                        // только на ошибке: всё прочее идёт мимо него нетронутым.
                        if (!globalThis.__ptJsonHook) {
                          globalThis.__ptJsonHook = 1;
                          const S = JSON.stringify;
                          JSON.stringify = function (v, ...rest) {
                            try {
                              if (v instanceof Error) {
                                console.error('[пойман] ' + Math.round(performance.now()) + 'мс ' +
                                  String(v.name) + ': ' + String(v.message).slice(0, 200) + ' | поля: ' +
                                  Object.getOwnPropertyNames(v).join(',') + ' | ' +
                                  String(v.stack || '').split(String.fromCharCode(10)).slice(0, 5)
                                    .map((l) => l.trim()).join(' <- ').slice(0, 300));
                              }
                            } catch (x) {}
                            return S.call(this, v, ...rest);
                          };
                        }
                        if (!globalThis.__ptErrHook) {
                          globalThis.__ptErrHook = 1;
                          let shown = 0;
                          const E0 = globalThis.Error;
                          for (const N of ['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError']) {
                            const C = globalThis[N];
                            if (typeof C !== 'function') continue;
                            const W = function (...a) {
                              const e = new C(...a);
                              // Челлендж занижает `stackTraceLimit` и ставит свой
                              // `prepareStackTrace`: прочитанный поверх них стек —
                              // его пересказ, а не наш. Снимаем на время чтения,
                              // иначе имена скриптов подменяются на `<anonymous>`
                              // и путь до кода читается неверно.
                              const lim = E0.stackTraceLimit, prep = E0.prepareStackTrace;
                              try { E0.stackTraceLimit = 30; E0.prepareStackTrace = undefined; } catch (x) {}
                              const snap = String(e.stack || '');
                              try { E0.stackTraceLimit = lim; E0.prepareStackTrace = prep; } catch (x) {}
                              if (shown++ < 120) {
                                try {
                                  // Шесть кадров, а не три: своя ошибка у
                                  // челленджа без сообщения, и единственное, что
                                  // о ней говорит, — кто её строил и из какого
                                  // шага сбора.
                                  console.error('[бросок] ' + Math.round(performance.now()) + 'мс ' + N + ': ' + String(a[0]).slice(0, 90) +
                                    ' | ' + snap.split(String.fromCharCode(10)).slice(1, 8)
                                      .map((l) => l.trim().replace(/^at /, '')).join(' <- ').slice(0, 460));
                                } catch (x) {}
                              }
                              return e;
                            };
                            W.prototype = C.prototype;
                            try { Object.defineProperty(W, 'name', { value: N }); } catch (x) {}
                            try { globalThis[N] = W; } catch (x) {}
                          }
                        }
                        // Задержка цикла событий в этом кадре: если страница-хозяин
                        // занимает поток, челлендж просто ждёт, и его собственные
                        // часы показывают секунды там, где у браузера доли.
                        if (!globalThis.__ptLagProbe) {
                          globalThis.__ptLagProbe = 1;
                          let last = performance.now(), worst = 0, ticks = 0;
                          const tick = () => {
                            const now = performance.now();
                            const lag = now - last - 4;
                            if (lag > worst) worst = lag;
                            if (lag > 400) {
                              console.error('[стоп] с ' + Math.round(last) + 'мс по ' + Math.round(now) +
                                            'мс, простой ' + Math.round(lag) + 'мс');
                            }
                            last = now;
                            if (++ticks % 100 === 0) {
                              console.error('[лаг] ' + Math.round(now) + 'мс тиков=' + ticks +
                                            ' худшая задержка=' + Math.round(worst) + 'мс');
                              worst = 0;
                            }
                            setTimeout(tick, 4);
                          };
                          setTimeout(tick, 4);
                        }
                        const gpu = globalThis.navigator && globalThis.navigator.gpu;
                        if (gpu && !gpu.__ptG) {
                          try { Object.defineProperty(gpu, '__ptG', { value: 1 }); } catch (e) {}
                          for (const k of ['requestAdapter', 'getPreferredCanvasFormat']) {
                            const f = gpu[k];
                            if (typeof f !== 'function') continue;
                            gpu[k] = function () {
                              let r;
                              try { r = f.apply(this, arguments); } catch (e) { console.error('[gpu] ' + k + ' бросил ' + e.name); throw e; }
                              if (r && typeof r.then === 'function') {
                                return r.then((v) => { console.error('[gpu] ' + k + ' -> ' + (v ? 'объект' : String(v))); return v; },
                                              (e) => { console.error('[gpu] ' + k + ' отказ ' + e); throw e; });
                              }
                              console.error('[gpu] ' + k + ' -> ' + String(r));
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
                            console.error('[octx] #' + id + ' ' + ty + ' ' + this.width + 'x' + this.height +
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
                                    if (n < 26 && !seen[k]) { seen[k] = 1; console.error('[cop] #' + id + ' ' + (n++) + ' ' + k); }
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
                    count(globalThis.Worker && Worker.prototype, 'worker', ['postMessage', 'terminate']);
                    count(globalThis.Navigator && Navigator.prototype, 'nav', ['getGamepads']);
                    count(globalThis, 'win', ['atob', 'btoa', 'matchMedia', 'getComputedStyle',
                                              'setTimeout', 'requestAnimationFrame', 'queueMicrotask']);
                    // Что ещё может быть медленным: измерения, разметка, картинки.
                    count(globalThis.Document && Document.prototype, 'd',
                          ['createElement', 'createElementNS', 'querySelector', 'querySelectorAll', 'getElementById']);
                    count(globalThis.Element && Element.prototype, 'el',
                          ['getBoundingClientRect', 'getClientRects', 'querySelector', 'querySelectorAll',
                           'setAttribute', 'getAttribute', 'attachShadow', 'closest', 'matches']);
                    count(globalThis.Node && Node.prototype, 'node', ['appendChild', 'insertBefore', 'removeChild', 'cloneNode']);
                    count(globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype, 'ctx2d',
                          ['measureText', 'fillText', 'strokeText', 'getImageData', 'putImageData', 'drawImage',
                           'fill', 'stroke', 'createRadialGradient', 'createLinearGradient']);
                    count(globalThis.SVGTextContentElement && SVGTextContentElement.prototype, 'svgText',
                          ['getComputedTextLength', 'getNumberOfChars', 'getSubStringLength']);
                    count(globalThis.SVGGraphicsElement && SVGGraphicsElement.prototype, 'svg', ['getBBox']);
                    count(globalThis.FontFaceSet && FontFaceSet.prototype, 'fonts', ['check', 'load']);
                    count(globalThis.RTCPeerConnection && RTCPeerConnection.prototype, 'rtc', ['getStats']);
                    // Выгрузка в момент отправки отчёта, а не по таймеру: кадр
                    // виджета к сроку успевает исчезнуть, и счётчики пропадали
                    // вместе с ним.
                    globalThis.__ptDumpCounts = () => {
                      for (const k of Object.keys(N).sort((a, b) => (L[b] || 0) - (L[a] || 0))) {
                        console.error('[count] ' + N[k] + ' вызовов, ' + (L[k] || 0) + ' знаков — ' + k);
                      }
                    };
                    setTimeout(() => { try { __ptDumpCounts(); } catch (e) {} }, 24000);
                    // Заодно то, что челлендж сам считает ошибкой: он зовёт
                    // `console.error` перед маяком далеко не всегда, но своё
                    // отклонённое обещание отдаёт в общий обработчик.
                    addEventListener('unhandledrejection', (e) => {
                      try { console.error('[beacon] отклонено: ' + String((e.reason && e.reason.stack) || e.reason).slice(0, 300)); } catch (x) {}
                    });
                    addEventListener('error', (e) => {
                      try { console.error('[beacon] ошибка: ' + String(e.message || '') + ' @ ' + String(e.filename || '').slice(-40) + ':' + e.lineno); } catch (x) {}
                    });
                  } catch (e) {}
                })();"#;
                // Порог, ниже которого куски отчёта в лог не идут: мелочь
                // топит вывод, но иногда именно короткий кусок и отличается
                // (список шрифтов у Chrome — 71 знак).
                let probe = probe.replace(
                    "__ENCMIN__",
                    &std::env::var("NOKK_ENC_MIN").unwrap_or_else(|_| "30".into()),
                );
                // Какой кусок высыпать целиком: `NOKK_DUMP_ENC=30000-32000`.
                // По умолчанию — звуковой блок, его сверяли чаще всего. Тот же
                // разброс задаётся Chrome через `DUMPENC` у `chrome-compare`,
                // иначе сравнивать нечего.
                let window = std::env::var("NOKK_DUMP_ENC").unwrap_or_else(|_| "15000-16000".into());
                let (lo, hi) = window.split_once('-').unwrap_or(("15000", "16000"));
                let probe = probe.replace("__DUMPLO__", lo.trim()).replace("__DUMPHI__", hi.trim());
                c.add_frame_init_script(probe.clone());
                c.add_init_script(probe);
            }
            // Исходник чужой программы. Её строят `new Function`, и это
            // единственное место, где она видна текстом: то, что приходит по
            // сети, — шифр, а стек внутри неё указывает смещением, немым без
            // исходника. Крючок один, на конструкторе, и снимается вместе с
            // `NOKK_DUMP_VM`.
            if std::env::var("NOKK_DUMP_VM").is_ok() {
                let probe = r#"(() => {
                  try {
                    const F = globalThis.Function;
                    const keep = (a) => {
                      try {
                        const t = String(a.length ? a[a.length - 1] : '');
                        if (t.length > (globalThis.__ptVmMin || 20000) &&
                            (!globalThis.__pt_vmSrc || t.length > globalThis.__pt_vmSrc.length)) {
                          globalThis.__pt_vmSrc = t;
                          console.error('[vmsrc] ' + Math.round(performance.now()) + 'мс ' + t.length + ' знаков');
                        }
                      } catch (e) {}
                    };
                    const mask = (f) => (globalThis.__pt_native ? __pt_native(f) : f);
                    const wrap = (host) => {
                      // Маяк `/eb/` уходит зашифрованным, но пойманную ошибку
                      // челлендж сериализует до шифра — и `JSON` для этого
                      // берёт не наш, а чистый, из области. Здесь она видна
                      // открытым текстом. Жалуемся в консоль кадра: своей у
                      // области нет, её никто не вычитывает.
                      try {
                        const J = host.JSON;
                        if (J && typeof J.stringify === 'function' && !J.stringify.__ptSeen) {
                          const S = J.stringify;
                          const V = function stringify(v) {
                            try {
                              if (v && typeof v === 'object' && typeof v.stack === 'string') {
                                console.error('[пойман] ' + Math.round(performance.now()) + 'мс ' +
                                  String(v.name) + ': ' + String(v.message).slice(0, 200) +
                                  ' | поля: ' + Object.getOwnPropertyNames(v).join(',') + ' | ' +
                                  String(v.stack).split(String.fromCharCode(10)).slice(0, 6)
                                    .map((l) => l.trim()).join(' <- ').slice(0, 320));
                              }
                            } catch (e) {}
                            return S.apply(this, arguments);
                          };
                          V.__ptSeen = 1;
                          J.stringify = mask(V);
                        }
                      } catch (e) {}
                      // Чем зовут подмену узла. Чистые ссылки челлендж берёт
                      // из области, поэтому крючок ставится там же; соседние
                      // `appendChild`/`insertBefore` не трогаем — они на
                      // горячем пути, и обёртка на них меняет ход сбора.
                      try {
                        // Кольцо последних обращений к тем местам, откуда
                        // берут узлы: когда подмена получает пустоту, надо
                        // знать, что её родило.
                        if (!globalThis.__ptRing) globalThis.__ptRing = [];
                        const ring = globalThis.__ptRing;
                        const note = (what, got) => {
                          try {
                            ring.push(Math.round(performance.now()) + 'мс ' + what + ' -> ' +
                              (got === undefined ? 'undefined' : got === null ? 'null'
                                : (typeof got === 'object' ? String(got.nodeName || Object.prototype.toString.call(got)) : typeof got)));
                            if (ring.length > 16) ring.shift();
                          } catch (e) {}
                        };
                        const watch = (obj, label, names) => {
                          if (!obj) return;
                          for (const n of names) {
                            try {
                              const F = obj[n];
                              if (typeof F !== 'function' || F.__ptSeen) continue;
                              const V = function (...a) {
                                const r = F.apply(this, a);
                                note(label + '.' + n + '(' + a.map((x) => typeof x === 'string' ? x.slice(0, 24) : typeof x).join(',') + ')', r);
                                return r;
                              };
                              V.__ptSeen = 1;
                              Object.defineProperty(obj, n,
                                { value: mask(V), writable: true, enumerable: false, configurable: true });
                            } catch (e) {}
                          }
                        };
                        const D = host.Document && host.Document.prototype;
                        watch(D, 'doc', ['createElement', 'createElementNS', 'createTextNode', 'createComment',
                                         'createDocumentFragment', 'importNode', 'adoptNode', 'getElementById',
                                         'querySelector', 'createRange', 'getElementsByTagName', 'write']);
                        watch(host.Node && host.Node.prototype, 'node', ['cloneNode']);
                        watch(host.Element && host.Element.prototype, 'el', ['attachShadow', 'closest', 'querySelector']);
                        watch(host.DOMParser && host.DOMParser.prototype, 'parser', ['parseFromString']);
                        const P = host.Node && host.Node.prototype;
                        if (P && typeof P.replaceChild === 'function' && !P.replaceChild.__ptSeen) {
                          const F = P.replaceChild;
                          const V = function replaceChild(...a) {
                            try {
                              console.error('[замена] ' + Math.round(performance.now()) + 'мс на ' +
                                (this && this.nodeName) + ' аргументов=' + a.length + ' [' +
                                a.map((x) => x === undefined ? 'undefined' : x === null ? 'null'
                                  : (typeof x === 'object' ? String(x.nodeName) : typeof x + ':' + String(x).slice(0, 20))).join(', ') + ']');
                              if (a[0] === undefined || a[0] === null) {
                                for (const line of (globalThis.__ptRing || [])) console.error('[до замены] ' + line);
                              }
                            } catch (e) {}
                            return F.apply(this, a);
                          };
                          V.__ptSeen = 1;
                          Object.defineProperty(P, 'replaceChild',
                            { value: mask(V), writable: true, enumerable: false, configurable: true });
                        }
                      } catch (e) {}
                      const G = host.Function;
                      if (typeof G !== 'function' || G.__ptSeen) return;
                      const W = function Function(...a) { keep(a); return new G(...a); };
                      W.__ptSeen = 1;
                      W.prototype = G.prototype;
                      try {
                        Object.defineProperty(G.prototype, 'constructor',
                          { value: W, writable: true, configurable: true });
                      } catch (e) {}
                      try { host.Function = mask(W); } catch (e) {}
                      // Тем же именем зовут и родню `Function`: тело кода
                      // компилируют через конструктор асинхронной функции или
                      // генератора ровно так же, а глаз на них никто не держит.
                      // Родню берём у самой области, а не у себя, — иначе
                      // подменишь свою и не заметишь чужую.
                      let kin = [];
                      try {
                        kin = new G('return [Object.getPrototypeOf(async function(){}).constructor,' +
                                    ' Object.getPrototypeOf(function*(){}).constructor]')();
                      } catch (e) {}
                      for (const C of kin) {
                        try {
                          if (typeof C !== 'function' || C.__ptSeen) continue;
                          const V = function (...a) { keep(a); return new C(...a); };
                          V.__ptSeen = 1;
                          V.prototype = C.prototype;
                          Object.defineProperty(C.prototype, 'constructor',
                            { value: mask(V), writable: true, configurable: true });
                        } catch (e) {}
                      }
                    };
                    globalThis.__ptVmMin = __VMMIN__;
                    wrap(globalThis);
                    console.error('[vmsrc] крючок стоит, порог ' + globalThis.__ptVmMin);
                    // Чужая программа берёт `Function` не у нас, а из чистой
                    // области — пустого однородного кадра, за `contentWindow`.
                    // Там наши правки ещё не стояли; ставим их на самом выходе
                    // области, пока её никому не отдали.
                    const R = globalThis.__pt_makeRealm;
                    if (typeof R === 'function') {
                      globalThis.__pt_makeRealm = mask(function __pt_makeRealm() {
                        const g = R.apply(this, arguments);
                        try { if (g) wrap(g); } catch (e) {}
                        return g;
                      });
                    }
                  } catch (e) {}
                })();"#;
                // Порог — чтобы не топить лог в мелочи страницы; своим числом
                // его опускают, когда ищут, чем вообще компилируют.
                let probe = probe.replace(
                    "__VMMIN__",
                    &std::env::var("NOKK_VM_MIN").unwrap_or_else(|_| "20000".into()),
                );
                c.add_frame_init_script(probe.clone());
                c.add_init_script(probe);
            }
            // Наблюдение за крючками челленджа: программа, пришедшая с сервера,
            // зовёт виджет через его же таблицу колбэков, и увидеть, какие из
            // них она позвала, — единственный способ прочитать её решение.
            if std::env::var("NOKK_TRACE_HOOKS").is_ok() {
                let hook = r#"(() => {
                  try { console.error('[hook] installed'); } catch (e) {}
                  globalThis.__pt_streamHooks = __STREAM__;
                  // Опыт: недостижимый хост в браузере не отвечает вовсе —
                  // запрос висит. У нас соединение падает сразу, и челлендж
                  // получает отказ там, где Chrome не получает ничего.
                  if (__HANG__) {
                    try {
                      const F = globalThis.fetch;
                      globalThis.fetch = function (r, o) {
                        const u = String((r && r.url) || r || '');
                        if (/brunhild\./.test(u)) {
                          try { console.error('[hang] ' + u.slice(0, 90)); } catch (e) {}
                          return new Promise(() => {});
                        }
                        return F.apply(this, arguments);
                      };
                    } catch (e) {}
                  }
                  // Собранный отпечаток уходит через JSON.stringify до того, как
                  // его сожмут и зашифруют — это единственная точка, где видно,
                  // что именно мы про себя рассказали.
                  try {
                    const S_ = XMLHttpRequest.prototype.send, O_ = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) { this.__ptU = String(u); return O_.apply(this, arguments); };
                    XMLHttpRequest.prototype.send = function (b) {
                      try {
                        const size = b == null ? 0
                          : (typeof b === 'string' ? b.length
                          : (b.byteLength !== undefined ? b.byteLength
                          : (b.size !== undefined ? b.size : (b.length || 0))));
                        console.error('[send] ' + Math.round(performance.now()) + 'мс bytes=' + size + ' kind=' + Object.prototype.toString.call(b) +
                                      ' url=' + String(this.__ptU || '').slice(-40));
                      } catch (e) {}
                      // Маяк `/eb/` — единственное место, где челлендж сам
                      // рассказывает, что у него не так. Тело собирается мимо
                      // JSON.stringify и btoa, поэтому берём его прямо здесь.
                      try {
                        if (/\/eb\//.test(String(this.__ptU || ''))) {
                          const t = typeof b === 'string' ? b : Object.prototype.toString.call(b);
                          for (let i = 0; i < Math.min(t.length, 1600); i += 200) {
                            console.error('[eb ' + i + '] ' + t.slice(i, i + 200));
                          }
                        }
                      } catch (e) {}
                      return S_.apply(this, arguments);
                    };
                  } catch (e) {}
                  try {
                    // Их сериализация не идёт через JSON — но строка где-то
                    // собирается: из массива, конкатенацией или из кодов.
                    let seen = 0, dumped = 0;
                    const J = Array.prototype.join;
                    Array.prototype.join = function (sep) {
                      const out = J.apply(this, arguments);
                      if (typeof out === 'string' && out.length > 1500 && seen++ < 3) {
                        try { console.error('[join ' + out.length + '] ' + out.slice(0, 700)); } catch (e) {}
                      }
                      // Перепись склеек. Отчёт уходит склейкой массива, но
                      // на этом стыке он уже зашифрован — длина совпадает с
                      // длиной отправки. Значит открытый текст собирается
                      // раньше, другой склейкой, и найти её можно только по
                      // ряду: чем и в каком порядке страница склеивала.
                      // Сами строки остаются в кадре, их забирает
                      // NOKK_EVAL_FRAMES.
                      if (__REPORT__ && typeof out === 'string' && out.length > __JMIN__) {
                        try {
                          if (!globalThis.__ptJoins) globalThis.__ptJoins = [];
                          if (!globalThis.__ptJoinN) globalThis.__ptJoinN = 0;
                          const n = globalThis.__ptJoinN++;
                          // Держать сами строки дорого: часть из них — мегабайты,
                          // и удержание меняет то, что мы измеряем (Chrome под
                          // таким крючком начинает перезапускать челлендж). Храним
                          // только те, что по размеру похожи на отчёт.
                          if (out.length < 200000) {
                            __ptJoins.push([n, out]);
                            if (__ptJoins.length > 12) __ptJoins.shift();
                          } else if (out.length > 500000) {
                            // Программа челленджа. Её выдают в двух размерах —
                            // короткую подозрительным, длинную доверенным, — и
                            // разница между ними и есть то, чего нам не дают
                            // сделать. Забирают через NOKK_EVAL_FRAMES.
                            globalThis.__ptProg = out;
                          }
                          let host = '?';
                          try { host = location.host.slice(0, 12); } catch (e) {}
                          // Из чего склеен отчёт: длины кусков по порядку.
                          if (out.length > 50000 && String(sep) === '' && this.length !== out.length && !globalThis.__ptPartsDone) {
            globalThis.__ptPartsDone = 1;
            try {
              const lens = Array.prototype.map.call(this, (x) => String(x == null ? '' : x).length);
              const big = lens.map((v, i) => [v, i]).sort((a, b) => b[0] - a[0]).slice(0, 25);
              console.error('[parts] n=' + lens.length + ' total=' + out.length +
                    ' крупнейшие: ' + big.map(([v, i]) => i + ':' + v).join(' '));
              const buckets = [0, 0, 0, 0, 0];
              for (const v of lens) buckets[v < 10 ? 0 : v < 100 ? 1 : v < 1000 ? 2 : v < 10000 ? 3 : 4]++;
              console.error('[parts] по размеру: <10=' + buckets[0] + ' <100=' + buckets[1] +
                    ' <1k=' + buckets[2] + ' <10k=' + buckets[3] + ' >=10k=' + buckets[4]);
            } catch (e) {}
          }
                          // Перечисление стилей — целиком: сравнивать его с
                          // браузером надо построчно, а кадр к концу прогона
                          // уже снесён, файлом не забрать.
                          if (String(sep) === '|' && out.length > 5000 &&
                              (globalThis.__ptCssN = (globalThis.__ptCssN || 0) + 1) <= 2) {
                            for (let i = 0; i < out.length; i += 4000) {
                              console.error('[C' + globalThis.__ptCssN + ' @' + i + '] ' + out.slice(i, i + 4000));
                            }
                            console.error('[C' + globalThis.__ptCssN + ' end ' + out.length + ']');
                          }
                          console.error('[j ' + n + ' ' + host + ' ' + out.length + ' ' +
                                        JSON.stringify(String(sep)) + '] ' +
                                        out.slice(0, 90).replace(/\n/g, ' '));
                        } catch (e) {}
                      }
                      return out;
                    };
                    const FCC = String.fromCharCode;
                    let fccBuf = 0;
                    String.fromCharCode = function () { fccBuf += arguments.length; return FCC.apply(this, arguments); };
                    globalThis.__pt_fccCount = () => fccBuf;
                  } catch (e) {}
                  try {
                    let n = 0, biggest = '';
                    const S = JSON.stringify;
                    JSON.stringify = function (v) {
                      const out = S.apply(this, arguments);
                      if (typeof out === 'string' && out.length > biggest.length) biggest = out;
                      if (typeof out === 'string' && out.length > 300 && n++ < 6) {
                        try { console.error('[payload ' + out.length + '] ' + out.slice(0, 900)); } catch (e) {}
                        // Отчёт об ошибке — единственное место, где их код сам
                        // называет, что у него сломалось. Печатаем рядом наш
                        // список промахов чтения: имя недостающего члена почти
                        // всегда там, последним.
                        if (out.indexOf('\"stack\"') >= 0 || out.indexOf('is not a function') >= 0) {
                          try {
                            const tail = (globalThis.__pt_missTail && __pt_missTail(24)) || '(none)';
                            for (let i = 0; i < tail.length; i += 200) {
                              console.error('[misses@err ' + i + '] ' + tail.slice(i, i + 200));
                            }
                          } catch (e2) {}
                        }
                      }
                      return out;
                    };
                    globalThis.__pt_biggestPayload = () => biggest.slice(0, 4000);
                    // Их собственная сериализация: у бандла есть свой сборщик строк,
                    // и отпечаток может уйти мимо JSON. Ловим и это.
                    const A = globalThis.btoa;
                    if (typeof A === 'function') {
                      globalThis.btoa = function (x) {
                        if (typeof x === 'string' && x.length > 300) {
                          try { console.error('[b64 ' + x.length + '] ' + x.slice(0, 600)); } catch (e) {}
                        }
                        return A.apply(this, arguments);
                      };
                    }
                  } catch (e) {}
                  // Их отправка сообщения кадру читает `contentWindow` раньше,
                  // чем проверяет целевой origin, — и молча уходит ни с чем,
                  // если origin пуст. Значит по чтению видно, дошёл ли тик до
                  // отправки вообще, даже когда сообщение потерялось.
                  try {
                    const d = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
                    if (d && d.get) {
                      let n = 0;
                      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                        configurable: true,
                        get() {
                          if (n++ < 40) {
                            try {
                              const at = String(new Error().stack || '').split('\n').slice(2, 4)
                                .map(x => x.trim().replace(/^at /, '')).join(' | ').slice(0, 150);
                              console.error('[cw] read #' + n + ' on #' + (this.id || '?') + ' @ ' + at);
                            } catch (e) {}
                          }
                          const win = d.get.call(this);
                          // И сам вызов: их `Cr` роняет сообщение молча, если
                          // целевой origin пуст, — значит надо видеть, дошло ли
                          // дело до postMessage и с чем.
                          try {
                            if (win && !win.__ptLogged) {
                              const P = win.postMessage;
                              win.postMessage = function (data, origin) {
                                try {
                                  const ev = data && data.event;
                                  console.error('[pm] → frame event=' + ev + ' origin=' + JSON.stringify(origin));
                                } catch (e) {}
                                return P.apply(this, arguments);
                              };
                              win.__ptLogged = true;
                            }
                          } catch (e) {}
                          return win;
                        },
                      });
                    }
                  } catch (e) {}
                  // Всё, что VM собирает на лету: стек внутри такого кода
                  // указывает смещением, а исходник иначе взять негде.
                  try {
                    globalThis.__ptBuilt = [];
                    const F0 = globalThis.Function;
                    const FN = function Function() {
                      const src = Array.prototype.join.call(arguments, ',');
                      try { if (src.length > 200) __ptBuilt.push(src); } catch (e) {}
                      return F0.apply(this, arguments);
                    };
                    FN.prototype = F0.prototype;
                    globalThis.Function = FN;
                    const E0 = globalThis.eval;
                    globalThis.eval = function (src) {
                      try { if (typeof src === 'string' && src.length > 200) __ptBuilt.push(src); } catch (e) {}
                      return E0.apply(this, arguments);
                    };
                  } catch (e) {}
                  // Чего кадр ждёт, когда стоит: раз в две секунды печатаем
                  // всё, что могло бы его разбудить, — незавершённые запросы,
                  // ближайший таймер и обещания, которые висят дольше пяти
                  // секунд (с местом, где их создали). Виджет замирает молча,
                  // и другого способа спросить «чего ты ждёшь» у нас нет.
                  try {
                    const inflight = new Map();
                    let reqId = 0;
                    const F = globalThis.fetch;
                    if (typeof F === 'function') {
                      globalThis.fetch = function (r, o) {
                        const id = ++reqId;
                        const u = String((r && r.url) || r || '').slice(-60);
                        inflight.set(id, { kind: 'fetch', url: u, at: Date.now() });
                        const done = () => inflight.delete(id);
                        let p;
                        try { p = F.apply(this, arguments); } catch (e) { done(); throw e; }
                        return p && p.then ? p.then((v) => { done(); return v; }, (e) => { done(); throw e; }) : p;
                      };
                    }
                    const XS = XMLHttpRequest.prototype.send, XO = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function (m, u) { this.__ptURL = String(u); return XO.apply(this, arguments); };
                    XMLHttpRequest.prototype.send = function () {
                      const id = ++reqId;
                      inflight.set(id, { kind: 'xhr', url: String(this.__ptURL || '').slice(-60), at: Date.now() });
                      this.addEventListener('loadend', () => inflight.delete(id));
                      return XS.apply(this, arguments);
                    };
                    // Обещания: считаем только те, что создала не наша обвязка.
                    const pending = new Map();
                    let pid = 0;
                    const P0 = globalThis.Promise;
                    const Wrapped = function Promise(executor) {
                      const id = ++pid;
                      let at = '';
                      try { at = String(new Error().stack || '').split('\n').slice(2, 9).map((x) => x.trim()).join(' | ').slice(0, 400); } catch (e) {}
                      let did = '';
                      const p = new P0(function (res, rej) {
                        // Что исполнитель успел спросить у хоста, пока
                        // выполнялся: обещание висит именно из-за этого — оно
                        // ждёт того, о чём здесь договорилось.
                        let before = 0;
                        try { before = (globalThis.__pt_probeTail ? JSON.parse(__pt_probeTail(400)).length : 0); } catch (e) {}
                        try {
                          return executor(function (v) { pending.delete(id); return res(v); },
                                          function (e) { pending.delete(id); return rej(e); });
                        } finally {
                          try {
                            const tail = globalThis.__pt_probeTail ? JSON.parse(__pt_probeTail(400)) : [];
                            did = tail.slice(Math.max(0, before)).map((r) => r[1] + '→' + String(r[2]).slice(0, 24)).join(' ; ').slice(0, 400);
                          } catch (e) {}
                        }
                      });
                      // Исходник самого исполнителя: место рождения указывает
                      // внутрь сгенерированного кода, которого у нас нет, а вот
                      // тело функции читается всегда.
                      let body = '';
                      try {
                        body = String(executor).replace(/\s+/g, ' ').slice(0, 300)
                             + ' | name=' + (executor && executor.name) + ' arity=' + (executor && executor.length);
                      } catch (e) {}
                      pending.set(id, { at, born: Date.now(), body, did });
                      return p;
                    };
                    Wrapped.prototype = P0.prototype;
                    Object.setPrototypeOf(Wrapped, P0);
                    for (const k of ['resolve', 'reject', 'all', 'allSettled', 'race', 'any', 'try', 'withResolvers']) {
                      if (typeof P0[k] === 'function') Wrapped[k] = P0[k].bind(P0);
                    }
                    globalThis.Promise = Wrapped;
                    // Какие задачи вообще будят кадр: кадры и микрозадачи,
                    // порт канала сообщений, простой таймер. Если программа
                    // ждёт одну из них, а она не приходит, — это и есть стоп.
                    let raf = 0, micro = 0, port = 0, idleCb = 0;
                    try { (function tick() { raf++; requestAnimationFrame(tick); })(); } catch (e) {}
                    // Не по кругу: цепочка микрозадач сама себя кормит и
                    // задушит всё остальное — считаем по несколько штук за раз,
                    // ставя новую партию на таймер.
                    let chan = null;
                    try {
                      chan = new MessageChannel();
                      chan.port1.onmessage = () => { port++; };
                      chan.port1.start && chan.port1.start();
                    } catch (e) {}
                    globalThis.setInterval(function () {
                      try { queueMicrotask(() => { micro++; }); } catch (e) {}
                      try { if (chan) chan.port2.postMessage(1); } catch (e) {}
                      try { requestIdleCallback(() => { idleCb++; }); } catch (e) {}
                    }, 500);
                    globalThis.setTimeout(function idle() {
                      try {
                        const now = Date.now();
                        const reqs = [...inflight.values()].map((r) => r.kind + ':' + r.url + ' (' + (now - r.at) + 'ms)');
                        const old = [...pending.values()].filter((p) => now - p.born > 5000);
                        console.error('[idle] запросов в полёте=' + reqs.length +
                                      ' таймер через=' + (globalThis.__pt_nextTimerDelay ? __pt_nextTimerDelay() : '?') +
                                      ' таймеров=' + (globalThis.__pt_pendingTimers ? __pt_pendingTimers() : '?') +
                                      ' обещаний висит>5с=' + old.length +
                                      ' | кадров=' + raf + ' микрозадач=' + micro + ' порт=' + port + ' idle=' + idleCb +
                                      (reqs.length ? ' :: ' + reqs.join(' ; ') : ''));
                        for (const p of old.slice(-3)) {
                          console.error('[idle] обещание с ' + Math.round((now - p.born) / 1000) + 'с @ ' + p.at);
                          console.error('[idle] его тело: ' + p.body);
                          console.error('[idle] исполнитель спросил: ' + (p.did || '(ничего)'));
                          // Ищем место рождения по имени функции из стека: у
                          // сгенерированного кода нет адреса, но есть текст.
                          try {
                            const m = /at ([\w$.]+) \(<anonymous>:\d+:(\d+)\)/.exec(p.at);
                            const fname = m ? m[1].split('.').pop() : '';
                            if (fname) {
                              for (const src of (globalThis.__ptBuilt || [])) {
                                const k = src.indexOf(fname + ':function');
                                const k2 = k >= 0 ? k : src.indexOf(fname + '=function');
                                if (k2 >= 0) {
                                  console.error('[idle] ' + fname + ' найдена в сборке ' + src.length + ' байт: ' +
                                                src.slice(k2, k2 + 320).replace(/\s+/g, ' '));
                                  break;
                                }
                              }
                            }
                          } catch (e) {}
                        }
                      } catch (e) { try { console.error('[idle] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(idle, 2000);
                    }, 2000);
                  } catch (e) {}
                  // Что кот видит на каждом тике: его проверки идут по теневому
                  // корню виджета и по его обёртке, и любая из них молча
                  // пропускает ход. Снимаем их сами — раз в две секунды.
                  try {
                    const shadows = [];
                    const AS = Element.prototype.attachShadow;
                    Element.prototype.attachShadow = function (init) {
                      const sh = AS.apply(this, arguments);
                      try {
                        shadows.push([this, sh]);
                        console.error('[shadow] host=' + this.localName + '#' + (this.id || '') +
                                      ' mode=' + (init && init.mode));
                      } catch (e) {}
                      return sh;
                    };
                    globalThis.setTimeout(function report() {
                      try {
                        for (const [host, sh] of shadows) {
                          const kids = [];
                          try { for (const k of sh.children) kids.push(k.localName + '#' + (k.id || '')); } catch (e) {}
                          console.error('[watchcat] host=' + host.localName + '#' + (host.id || '') +
                                        ' connected=' + host.isConnected +
                                        ' isShadowRoot=' + (sh instanceof ShadowRoot) +
                                        ' kids=' + kids.join(',') +
                                        ' qsWidget=' + kids.map(k => k.split('#')[1])
                                            .filter(Boolean)
                                            .map(id => id + ':' + !!sh.querySelector('#' + id)).join(' '));
                          // Сам ход кота: он берёт найденный элемент и шлёт в
                          // него сообщение с целевым origin. Если это бросает,
                          // их цикл гасит исключение и молчит.
                          for (const k of sh.children) {
                            if (k.localName !== 'iframe') continue;
                            let win = 'n/a', posted = 'n/a';
                            try { win = String(!!k.contentWindow); } catch (e) { win = 'threw ' + e; }
                            try {
                              const origin = new URL(k.src || 'https://challenges.cloudflare.com').origin;
                              k.contentWindow.postMessage({ event: 'probe' }, origin);
                              posted = 'ok';
                            } catch (e) { posted = 'threw ' + String(e).slice(0, 90); }
                            console.error('[watchcat] send to ' + k.id + ': contentWindow=' + win + ' post=' + posted);
                          }
                        }
                      } catch (e) { try { console.error('[watchcat] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(report, 2000);
                    }, 2000);
                  } catch (e) {}
                  // Повторяющиеся таймеры: сторожевой кот Turnstile — это
                  // setInterval на 900 мс в контексте страницы, и молчание кота
                  // видно только так — заведён он или заведён, но не тикает.
                  try {
                    const SI = globalThis.setInterval;
                    let ivId = 0;
                    globalThis.setInterval = function (fn, ms) {
                      const id = ++ivId;
                      let fired = 0;
                      try { console.error('[interval] set #' + id + ' every ' + ms + 'ms'); } catch (e) {}
                      const wrapped = typeof fn !== 'function' ? fn : function () {
                        fired++;
                        if (fired <= 3 || fired % 10 === 0) {
                          try { console.error('[interval] #' + id + ' tick ' + fired + ' (' + ms + 'ms)'); } catch (e) {}
                        }
                        return fn.apply(this, arguments);
                      };
                      return SI.call(this, wrapped, ms);
                    };
                  } catch (e) {}
                  // Ошибку челлендж ловит сам и уносит в свой маяк зашифрованной
                  // — но создаёт он её здесь, обычным конструктором. Один
                  // перехват даёт то, ради чего иначе расшифровывают маяк.
                  try {
                    for (const nm of ['Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError']) {
                      const E = globalThis[nm];
                      if (typeof E !== 'function') continue;
                      const Wrapped = function (...a) {
                        const e = new E(...a);
                        try {
                          const at = String(e.stack || '').split('\n').slice(1, 3).join(' | ').slice(0, 220);
                          console.error('[throw] ' + nm + ': ' + String(a[0]).slice(0, 160) + ' @ ' + at);
                        } catch (x) {}
                        return e;
                      };
                      Wrapped.prototype = E.prototype;
                      Object.setPrototypeOf(Wrapped, E);
                      Object.defineProperty(Wrapped, 'name', { value: nm, configurable: true });
                      globalThis[nm] = Wrapped;
                    }
                  } catch (e) {}
                  // Их собственные хлебные крошки: код усыпан вызовами
                  // UpvLO0(<метка>) и eVARP2(<метка>) на каждом шаге. Метки
                  // уникальны, поэтому последовательность вызовов — это трасса
                  // их машины состояний, и её можно сравнить с браузерной.
                  for (const name of ['UpvLO0', 'eVARP2']) {
                    try {
                      let held;
                      Object.defineProperty(globalThis, name, {
                        configurable: true,
                        get() { return held; },
                        set(v) {
                          held = typeof v !== 'function' ? v : function (tag) {
                            // Метка зашифрована на каждую выдачу, а место вызова
                            // — нет: строка в их бандле одна и та же и у нас, и
                            // в Chrome, поэтому сравнивать трассы можно по ней.
                            let at = '';
                            try {
                              const f = String(new Error().stack || '').split('\n').slice(2);
                              at = (f.find(s => s.indexOf('cloudflare.com') >= 0) || f[0] || '')
                                     .replace(/^\s*at\s*/, '').replace(/^.*\/(?=[^/]*:)/, '');
                            } catch (e) {}
                            try { console.error('[crumb] ' + name + ' ' + String(tag).slice(0, 24) + ' @ ' + at); } catch (e) {}
                            return v.apply(this, arguments);
                          };
                        },
                      });
                    } catch (e) {}
                  }

                  // Что VM успела потрогать перед броском. Стек внутри их
                  // интерпретатора ничего не говорит: там один диспетчер опкодов,
                  // а вот последние обращения к хостовым таблицам — говорят.
                  // Каждое чтение свойства, которого нет: их интерпретатор
                  // падает на `fn.call(obj, …)`, где fn — метод, взятый с
                  // хостового объекта, и имя этого метода больше взять негде.
                  // Дно цепочки прототипов — единственное место, где промах
                  // виден: ставим туда Proxy и записываем, что спросили.
                  // Снимок глобалей до первого скрипта: всё сверх него объявил
                  // сам челлендж, и сравнение с Chrome показывает, чья ступень
                  // у нас не отработала.
                  let baseGlobals = [];
                  try { baseGlobals = Object.getOwnPropertyNames(globalThis); } catch (e) {}
                  // Счётчик шагов их машины. Имена в бандле меняются с каждой
                  // выдачей, поэтому ловим не имя, а поведение: после сборки
                  // программы берём все функции, которых на окне не было, и
                  // считаем вызовы. Диспетчер опкодов выдаст себя частотой —
                  // сравнивать с браузером можно именно её.
                  try {
                    globalThis.__ptSteps = new Map();
                    globalThis.__ptLastArgs = new Map();
                    globalThis.__ptCountVM = () => {
                      let wrapped = 0;
                      for (const name of Object.getOwnPropertyNames(globalThis)) {
                        if (name.lastIndexOf('__pt', 0) === 0) continue;
                        if (baseGlobals.indexOf(name) >= 0) continue;
                        let v;
                        try { v = globalThis[name]; } catch (e) { continue; }
                        if (typeof v !== 'function' || v.__ptCounted) continue;
                        const counter = { n: 0 };
                        __ptSteps.set(name, counter);
                        const wrap = function (...args) {
                          counter.n++;
                          if (counter.n % 5000 === 0 || counter.n < 3) {
                            try { __ptLastArgs.set(name, args.map((a) => String(a).slice(0, 18)).join(',').slice(0, 60)); } catch (e) {}
                          }
                          return v.apply(this, args);
                        };
                        wrap.__ptCounted = true;
                        try { Object.defineProperty(globalThis, name, { value: wrap, writable: true, configurable: true }); wrapped++; } catch (e) {}
                      }
                      return wrapped;
                    };
                    // Считать начинаем, когда программа собрана, и печатаем итог
                    // раз в две секунды.
                    globalThis.setTimeout(function counter() {
                      try {
                        const added = __ptCountVM();
                        const top = [...__ptSteps.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 4);
                        if (top.length && top[0][1].n > 0) {
                          console.error('[vmsteps] ' + top.map(([k, c]) => k + '=' + c.n).join(' ') +
                                        (added ? ' (+' + added + ' новых)' : ''));
                        }
                      } catch (e) { try { console.error('[vmsteps] threw ' + e); } catch (x) {} }
                      globalThis.setTimeout(counter, 2000);
                    }, 1500);
                  } catch (e) {}

                  const addedGlobals = () => {
                    try {
                      const b = new Set(baseGlobals);
                      return Object.getOwnPropertyNames(globalThis)
                        .filter((n) => !b.has(n) && n.lastIndexOf('__pt', 0) !== 0)
                        .map((n) => { let t = '?'; try { t = typeof globalThis[n]; } catch (e) {} return n + ':' + t; })
                        .join(' ');
                    } catch (e) { return '(failed)'; }
                  };
                  const misses = [];
                  globalThis.__pt_missTail = (n) => misses.slice(-(n || 24)).join(' ');
                  try {
                    const toStr = Object.prototype.toString;
                    const describe = (r) => {
                      if (r === globalThis) return 'window';
                      if (r === document) return 'document';
                      const t = toStr.call(r).slice(8, -1);
                      let extra = '';
                      try {
                        if (r && ('nodeType' in r) && r.nodeType === 1) extra = '<' + String(r.localName) + (r.id ? '#' + r.id : '') + '>';
                      } catch (e) {}
                      return t + extra;
                    };
                    // Object.prototype неизменяем, поэтому ловушку ставим
                    // ступенью выше — между корневым интерфейсом и им.
                    const sink = () => new Proxy(Object.prototype, {
                      get(t, p, r) {
                        if (typeof p === 'string' && !(p in t) && p.lastIndexOf('__pt', 0) !== 0) {
                          let who = '?';
                          try { who = describe(r); } catch (e) {}
                          misses.push(who + '.' + p);
                          if (misses.length > 60) misses.shift();
                          // Индексы и `toJSON` — шум сериализации, десятки тысяч
                          // строк за прогон; в кольце они остаются, в поток не идут.
                          if (globalThis.__pt_streamHooks && !/^(-?\d+|toJSON)$/.test(p)) {
                            try { console.error('[m] ' + who + '.' + p); } catch (e) {}
                          }
                        }
                        return Reflect.get(t, p, r);
                      },
                    });
                    let hooked = 0;
    for (const name of ['EventTarget', 'Navigator', 'Screen', 'Location', 'History',
                                        'Performance', 'Crypto', 'Storage', 'CSSStyleDeclaration',
                                        'DOMTokenList', 'NodeList', 'HTMLCollection', 'NamedNodeMap',
                                        'PerformanceEntry', 'MessagePort', 'Event', 'URL',
                                        'Function', 'Array', 'String', 'Number', 'Boolean', 'Symbol',
                                        'Error', 'Date', 'RegExp', 'Map', 'Set', 'WeakMap', 'WeakSet',
                                        'Promise', 'ArrayBuffer', 'DataView', 'Uint8Array', 'Blob',
                                        'Worker', 'MessageEvent', 'XMLHttpRequest', 'Response', 'Headers']) {
                      const C = globalThis[name], proto = C && C.prototype;
                      if (proto && Object.getPrototypeOf(proto) === Object.prototype) {
                        Object.setPrototypeOf(proto, sink());
                        hooked++;
                      }
                    }
                    void document.__pt_sinkSelfTest;
                    console.error('[vm] miss-sink on ' + hooked + ' roots, self-test ' + (misses.length > 0));
                    misses.length = 0;
                  } catch (e) { console.error('[vm] miss-sink failed: ' + e); }
                  const recent = [];
                  const stream = !!globalThis.__pt_streamHooks;
                  const remember = (s) => {
                    recent.push(s);
                    if (recent.length > 24) recent.shift();
                    if (stream) { try { console.error('[t] ' + String(s).slice(0, 150)); } catch (e) {} }
                  };
                  // Разговор с воркером сбора: кто кому и что послал.
                  try {
                    const WP = Worker.prototype.postMessage;
                    const peek = (v) => {
                      try {
                        if (typeof v === 'string') return 'str' + v.length + ':' + v.slice(0, 90);
                        if (v && typeof v === 'object') {
                          return 'obj{' + Object.keys(v).map((k) => {
                            const x = v[k];
                            return k + '=' + (typeof x === 'string' ? 's' + x.length + ':' + x.slice(0, 40)
                                              : x && typeof x === 'object' ? Object.prototype.toString.call(x)
                                              : String(x).slice(0, 20));
                          }).join(' ').slice(0, 200) + '}';
                        }
                        return String(v).slice(0, 60);
                      } catch (e) { return '?'; }
                    };
                    Worker.prototype.postMessage = function (data) {
                      remember('worker.postMessage ' + peek(data));
                      return WP.apply(this, arguments);
                    };
                    const WA = Worker.prototype.addEventListener;
                    const wrapHandler = (h) => (typeof h !== 'function' ? h : function (e) {
                      remember('worker→frame ' + (e && e.type) + ' ' + peek(e && e.data));
                      return h.apply(this, arguments);
                    });
                    Worker.prototype.addEventListener = function (t, h) {
                      remember('worker.on ' + t);
                      return WA.call(this, t, wrapHandler(h), arguments[2]);
                    };
                    // Ответ воркера приходит и через свойство-обработчик.
                    const OM = new WeakMap();
                    Object.defineProperty(Worker.prototype, 'onmessage', {
                      configurable: true, enumerable: true,
                      get() { return OM.get(this) || null; },
                      set(h) { OM.set(this, h); this.addEventListener('message', h); },
                    });
                  } catch (e) {}
                  globalThis.__pt_recent = () => recent.join(' → ');
                  // Вторая стадия сбора у них ставится таймером и молчит, если
                  // внутри что-то бросило: браузер такое печатает, мы — нет.
                  try {
                    addEventListener('error', (e) => {
                      try { console.error('[err] ' + (e && e.message) + ' @ ' + (e && e.filename) + ':' + (e && e.lineno)); } catch (x) {}
                    });
                    addEventListener('unhandledrejection', (e) => {
                      try {
                        const r = e && e.reason;
                        console.error('[reject] ' + String((r && r.stack) || r).split('\n').join(' | ').slice(0, 300));
                      } catch (x) {}
                    });
                  } catch (e) {}
                  try {
                    const D = EventTarget.prototype.dispatchEvent;
                    const show = (v) => {
                      if (v === null || v === undefined) return String(v);
                      if (typeof v === 'string') return 'str(' + v.length + '):' + v.slice(0, 60);
                      if (typeof v !== 'object') return typeof v + ':' + String(v).slice(0, 30);
                      try {
                        return 'obj{' + Object.keys(v).map((k) => {
                          const x = v[k];
                          return k + '=' + (typeof x === 'string' ? 's' + x.length + ':' + x.slice(0, 24)
                                            : x && typeof x === 'object' ? 'o{' + Object.keys(x).slice(0, 4).join(',') + '}'
                                            : String(x).slice(0, 18));
                        }).join(' ') + '}';
                      } catch (x) { return 'obj?'; }
                    };
                    EventTarget.prototype.dispatchEvent = function (e) {
                      remember('dispatch:' + (e && e.type) +
                               (e && e.type === 'message' ? '[' + show(e.data) + ']' : ''));
                      return D.apply(this, arguments);
                    };
                  } catch (e) {}
                  const wrap = (obj, label) => {
                    for (const k of Object.keys(obj)) {
                      const v = obj[k];
                      if (typeof v !== 'function') continue;
                      obj[k] = function () {
                        // Один раз: их метка времени против наших часов. Челлендж
                        // объявляет `fail`, если расхождение больше 12 часов.
                        if (!globalThis.__pt_clockLogged) {
                          globalThis.__pt_clockLogged = true;
                          try {
                            const o = globalThis._cf_chl_opt || {};
                            const theirs = Object.keys(o)
                              .filter((n) => /^\d{10}$/.test(String(o[n])))
                              .map((n) => n + '=' + o[n]);
                            const now = Math.floor(Date.now() / 1000);
                            console.error('[clock] ours=' + now + ' theirs=[' + theirs.join(' ') +
                                          '] skew=' + theirs.map((t) => now - Number(t.split('=')[1])).join(','));
                          } catch (e) {}
                        }
                        remember(label + '.' + k);
                        try { console.error('[hook] ' + label + '.' + k); } catch (e) {}
                        try {
                          return v.apply(this, arguments);
                        } catch (err) {
                          // Их код ловит такие броски сам, и наружу они не выходят —
                          // а именно они обрывают цепочку на полпути.
                          try { console.error('[hookerr] ' + label + '.' + k + ': ' + ((err && err.stack) || err)); } catch (e) {}
                          throw err;
                        }
                      };
                    }
                    return obj;
                  };
                  // Их интерпретатор: программа с сервера приходит байткодом и
                  // исполняется через window.runProgram. Сколько она работала и
                  // чем кончила — половина ответа на «почему нет второго круга».
                  try {
                    let rp;
                    Object.defineProperty(globalThis, 'runProgram', {
                      configurable: true,
                      get() { return rp; },
                      set(v) {
                        rp = typeof v !== 'function' ? v : function (src) {
                          const t0 = Date.now();
                          let fn;
                          try { fn = v.apply(this, arguments); }
                          catch (e) { console.error('[vm] build threw after ' + (Date.now() - t0) + 'ms: ' + e); throw e; }
                          console.error('[vm] built in ' + (Date.now() - t0) + 'ms from ' +
                                        ((src && src.length) || 0) + ' bytes → ' + typeof fn);
                          // Текст программы держим под рукой: стек внутри неё
                          // указывает смещением, и без исходника оно немое.
                          // Держим самую большую из собранных: главная программа
                          // приходит первой, а следом идут мелкие куски, и
                          // «последняя» затирала её.
                          try {
                            const t = String(src || '');
                            if (!globalThis.__pt_vmSrc || t.length > globalThis.__pt_vmSrc.length) {
                              globalThis.__pt_vmSrc = t;
                            }
                          } catch (e) {}
                          if (typeof fn !== 'function') return fn;
                          return function () {
                            const t1 = Date.now();
                            try { globalThis.__pt_probeMark && __pt_probeMark('program start ' + ((src && src.length) || 0)); } catch (e) {}
                            try {
                              const out = fn.apply(this, arguments);
                              try { globalThis.__pt_probeMark && __pt_probeMark('program end'); } catch (e) {}
                              console.error('[vm] ran ' + (Date.now() - t1) + 'ms → ' + typeof out);
                              return out;
                            } catch (e) {
                              try { globalThis.__pt_probeMark && __pt_probeMark('program threw'); } catch (e2) {}
                              console.error('[vm] threw after ' + (Date.now() - t1) + 'ms: ' +
                                            String((e && e.stack) || e).split('\n').join(' | '));
                              try {
                                const line = recent.join(' → ');
                                for (let i = 0; i < line.length; i += 200) {
                                  console.error('[vm] before ' + i + ': ' + line.slice(i, i + 200));
                                }
                              } catch (e2) {}
                              try {
                                const ss = document.scripts;
                                let sizes = [];
                                for (let i = 0; i < ss.length; i++) {
                                  sizes.push((ss[i].src ? 'src:' + String(ss[i].src).slice(-24) : 'inline') +
                                             '=' + String(ss[i].text || '').length);
                                }
                                console.error('[vm] scripts: ' + sizes.join(' ') +
                                              ' | doc ' + document.documentElement.outerHTML.length);
                              } catch (e2) {}
                              try {
                                const g = addedGlobals();
                                for (let i = 0; i < g.length; i += 220) {
                                  console.error('[vm] globals ' + i + ': ' + g.slice(i, i + 220));
                                }
                              } catch (e2) {}
                              try {
                                const tail = misses.slice(-24);
                                for (let i = 0; i < tail.length; i += 6) {
                                  console.error('[vm] missed reads ' + i + ': ' + tail.slice(i, i + 6).join(' '));
                                }
                              } catch (e2) {}
                              throw e;
                            }
                          };
                        };
                      },
                    });
                  } catch (e) {}
                  for (const name of ['RItcy2', 'HuCI0']) {
                    let store;
                    try {
                      Object.defineProperty(globalThis, name, {
                        configurable: true,
                        get() { return store; },
                        set(v) { store = (v && typeof v === 'object') ? wrap(v, name) : v; },
                      });
                    } catch (e) {}
                  }
                })();"#;
                // Потоковый лог событий: включается NOKK_TRACE_STREAM=1, иначе
                // кольцо печатается только при броске.
                let stream = std::env::var("NOKK_TRACE_STREAM").is_ok();
                let hook = hook.replace("__STREAM__", if stream { "true" } else { "false" });
                let hook = hook.replace(
                    "__JMIN__",
                    &std::env::var("NOKK_JOIN_MIN").unwrap_or_else(|_| "2000".into()),
                );
                let hook = hook.replace(
                    "__REPORT__",
                    if std::env::var("NOKK_DUMP_REPORT").is_ok() { "true" } else { "false" },
                );
                let hook = hook.replace(
                    "__HANG__",
                    if std::env::var("NOKK_HANG_UNREACHABLE").is_ok() { "true" } else { "false" },
                );
                c.add_frame_init_script(hook.clone());
                c.add_init_script(hook);
            }
            c.navigate(url).await?;
            let title = c.evaluate("document.title").await.unwrap_or_default();
            let challenged =
                matches!(&title, serde_json::Value::String(s) if s.contains("Just a moment"));
            ctx = Some(c);
            if !challenged || attempt == cli.retries {
                if challenged && cli.retries > 0 {
                    eprintln!("(still challenged after {} attempt(s))", attempt + 1);
                }
                break;
            }
            tracing::info!(attempt = attempt + 1, "Cloudflare challenge, retrying");
        }
        let ctx = ctx.expect("retry loop runs at least once");
        tracing::info!(elapsed_ms = t.elapsed().as_millis(), "page loaded");

        if let Some(seconds) = cli.solve_challenge {
            let deadline = Instant::now() + Duration::from_secs(seconds);
            /// A widget asks once or twice; more than this is a loop, not a user.
            const MAX_PRESSES: usize = 3;
            let mut pressed = 0usize;
            let mut seen_controls = std::collections::HashSet::new();
            loop {
                let phase = Instant::now();
                let worked = ctx.run_event_loop().await.unwrap_or(0);
                let looped = phase.elapsed();
                let cleared = ctx.cookies(&[]).iter().any(|c| c.name == "cf_clearance");
                if cleared {
                    tracing::info!(
                        elapsed_ms = t.elapsed().as_millis(),
                        presses = pressed,
                        "challenge cleared"
                    );
                    break;
                }
                if Instant::now() >= deadline {
                    tracing::warn!(presses = pressed, "challenge did not clear in time");
                    break;
                }
                // Press only what is offered; a widget still verifying offers
                // nothing, and pressing nothing is the correct thing to do.
                // One press per control that appears. A widget that ignores it is
                // not asking to be pressed again — a person would not keep
                // clicking either, and a flurry of clicks is its own signature.
                let before_press = Instant::now();
                if pressed < MAX_PRESSES {
                    if let Ok(Some(what)) = ctx.press_widget_control().await {
                        if seen_controls.insert(what.clone()) {
                            pressed += 1;
                            tracing::info!(control = %what, "pressed the challenge widget");
                            // Полторы секунды после нажатия — не сон, а работа:
                            // спящий движок не качает ни страницу, ни кадры, а
                            // виджет как раз в эти полторы секунды и считает.
                            // Его собственные часы видели здесь провал, какого
                            // у браузера не бывает.
                            let until = Instant::now() + Duration::from_millis(1_500);
                            while Instant::now() < until {
                                let _ = ctx.run_event_loop().await;
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                    }
                }
                // Чей таймер держит паузу: страницы или кадра виджета.
                let raw = ctx
                    .evaluate("typeof __pt_nextTimerDelay === 'function' ? String(__pt_nextTimerDelay()) : 'nofn'")
                    .await;
                let pending = match &raw {
                    Ok(v) => v.as_str().unwrap_or("notstr").to_string(),
                    Err(e) => format!("err:{e}"),
                };
                let frame_pending = match ctx.frame_list().first() {
                    Some(f) => match ctx
                        .evaluate_in_frame(
                            f.id,
                            "typeof __pt_nextTimerDelay === 'function' ? String(__pt_nextTimerDelay()) : 'nofn'",
                        )
                        .await
                    {
                        Ok(v) => v.as_str().unwrap_or("notstr").to_string(),
                        Err(e) => format!("err:{e}"),
                    },
                    None => "noframe".to_string(),
                };
                tracing::debug!(
                    loop_ms = looped.as_millis(),
                    press_ms = before_press.elapsed().as_millis(),
                    worked,
                    pending,
                    frame_pending,
                    "solve turn"
                );
                // Пока в странице или её воркерах идёт работа, ждать нечего:
                // виток кончается по внутреннему пределу ожидания, а не потому
                // что всё сделано. Сон в 400 мс на каждом витке отдавал сборщику
                // отпечатка меньше трети реального времени, и он не поспевал за
                // собственным таймаутом.
                // Пауза здесь — это задержка для всякого таймера, который стал
                // срочным внутри неё. Виджет разложен на цепочку из десятков
                // шагов по таймеру, и четверть секунды на каждом растягивала
                // четыре секунды работы в одиннадцать — ровно за его порог.
                let idle = worked == 0;
                // Работающей странице — миллисекунда между прокачками: на пяти
                // таймеры опаздывают, и это видно по частоте кадров.
                if idle {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                } else {
                    tokio::time::sleep(Duration::from_micros(500)).await;
                }
            }
        }

        // With the probe tracer on, say what the page asked us — in the page and
        // in every frame, since a widget interrogates from inside its own.
        if std::env::var("NOKK_TRACE_PROBES").is_ok() {
            let dump = |where_: String, v: serde_json::Value| {
                if let Some(text) = v.as_str() {
                    if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
                        eprintln!("# probes {where_}: {} distinct", rows.len());
                        for row in rows.iter().take(3000) {
                            eprintln!(
                                "#   {:>5}x {} -> {}",
                                row[1].as_u64().unwrap_or(0),
                                row[0].as_str().unwrap_or(""),
                                row[2].as_str().unwrap_or("")
                            );
                        }
                    }
                }
            };
            if let Ok(v) = ctx.evaluate("__pt_probeLog()").await {
                dump("page".into(), v);
            }
            // Workers are where a challenge does its collecting, and a worker's
            // context is reachable from nothing on the page — so ask each live one
            // directly. A collector usually posts its result and hangs up long
            // before this runs; the engine leaves what it was asked with the
            // document that started it, so read that too.
            for (url, v) in ctx
                .evaluate_in_workers("typeof __pt_probeLog === 'function' ? __pt_probeLog() : ''")
                .await
            {
                dump(format!("worker {url}"), v);
            }
            // То же — про саму страницу: интерстишал рисует свой интерфейс в
            // закрытом shadow root не хуже виджета.
            if let Ok(serde_json::Value::String(t)) = ctx
                .evaluate("(() => { const ids = [];                    for (const el of document.querySelectorAll('*')) if (el.id) ids.push(el.localName + '#' + el.id);                    const root = (globalThis._cf_chl_opt || {}).wTgF5;                    return JSON.stringify({ids: ids.slice(0, 20),                      renderRoot: root ? (root.nodeName || 'shadow') : null,                      rootKids: root && root.childNodes ? root.childNodes.length : -1}); })()")
                .await
            {
                eprintln!("# page ids: {t}");
            }
            if let Ok(serde_json::Value::String(t)) = ctx.evaluate("(() => { const seen = []; const walk = (root) => {                            for (const el of root.querySelectorAll('*')) {                              const tag = el.localName;                              if (tag === 'input' || tag === 'button' || el.getAttribute('role'))                                seen.push(tag + (el.type ? '[' + el.type + ']' : '') +                                          (el.getAttribute('role') ? '{' + el.getAttribute('role') + '}' : ''));                              const sr = el.shadowRoot || el.__ptShadow; if (sr) walk(sr); } };                          const root = document.body && (document.body.shadowRoot || document.body.__ptShadow);                          try { walk(document); if (root) walk(root); } catch (e) {}                          return JSON.stringify({controls: seen.slice(0, 12),                            events: (globalThis._cf_chl_opt && _cf_chl_opt.FELcX1) ? _cf_chl_opt.FELcX1.length : -1, bodyShadow: !!root,                            shadowKids: root ? root.childNodes.length : -1,                            shadowText: root ? String(root.textContent || '').trim().slice(0, 60) : '',                            bodyKids: document.body ? document.body.childNodes.length : -1,                            view: [innerWidth, innerHeight],                            html: (document.documentElement ? document.documentElement.outerHTML : '').length}); })()").await {
                eprintln!("# page widget: {t}");
            }
            // Что виджет в итоге нарисовал: интерактивный контрол — то, чего
            // движок ждёт от него, и его отсутствие видно только так.
            for f in ctx.frame_list() {
                if let Ok(serde_json::Value::String(t)) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "(() => { const seen = []; const walk = (root) => {                            for (const el of root.querySelectorAll('*')) {                              const tag = el.localName;                              if (tag === 'input' || tag === 'button' || el.getAttribute('role'))                                seen.push(tag + (el.type ? '[' + el.type + ']' : '') +                                          (el.getAttribute('role') ? '{' + el.getAttribute('role') + '}' : ''));                              const sr = el.shadowRoot || el.__ptShadow; if (sr) walk(sr); } };                          const root = document.body && (document.body.shadowRoot || document.body.__ptShadow);                          try { walk(document); if (root) walk(root); } catch (e) {}                          return JSON.stringify({controls: seen.slice(0, 12),                            events: (globalThis._cf_chl_opt && _cf_chl_opt.FELcX1) ? _cf_chl_opt.FELcX1.length : -1, bodyShadow: !!root,                            shadowKids: root ? root.childNodes.length : -1,                            shadowText: root ? String(root.textContent || '').trim().slice(0, 60) : '',                            bodyKids: document.body ? document.body.childNodes.length : -1,                            view: [innerWidth, innerHeight],                            html: (document.documentElement ? document.documentElement.outerHTML : '').length}); })()",
                    )
                    .await
                {
                    eprintln!("# widget frame {}: {t}", f.id);
                }
            }
            // Ключи челленджа этого прогона: без них ответ сервера не расшифровать
            // задним числом (ключ выводится из ray самого виджета).
            for f in ctx.frame_list() {
                if let Ok(serde_json::Value::String(t)) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "JSON.stringify({ray: (globalThis._cf_chl_opt||{}).wxfI5 || null,                          sitekey: (globalThis._cf_chl_opt||{}).ZSOv1 || null})",
                    )
                    .await
                {
                    if t.contains("\"ray\":\"") {
                        eprintln!("# chl frame {}: {t}", f.id);
                    }
                }
            }
            let tail = match std::env::var("NOKK_TRACE_HEAD") {
                Ok(_) => "typeof __pt_probeHead === 'function' ? __pt_probeHead(400000) : ''",
                Err(_) => "typeof __pt_probeTail === 'function' ? __pt_probeTail(40) : ''",
            };
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(tail).await,
                    Some(id) => ctx.evaluate_in_frame(id, tail).await,
                };
                if let Ok(serde_json::Value::String(text)) = out {
                    if let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                        if !rows.is_empty() {
                            let label = slot
                                .map(|i| format!("frame {i}"))
                                .unwrap_or_else(|| "page".to_string());
                            eprintln!("# tail {label}:");
                            for row in rows {
                                eprintln!("#   {:>6}ms {} -> {}", row[0].as_i64().unwrap_or(0),
                                          row[1].as_str().unwrap_or(""), row[2].as_str().unwrap_or(""));
                            }
                        }
                    }
                }
            }
            let trace = "JSON.stringify(globalThis.__pt_workerTrace || [])";
            let mut traces = vec![ctx.evaluate(trace).await];
            for f in ctx.frame_list() {
                traces.push(ctx.evaluate_in_frame(f.id, trace).await);
            }
            for v in traces.into_iter().flatten() {
                let rows: Vec<(String, String)> = v
                    .as_str()
                    .and_then(|t| serde_json::from_str(t).ok())
                    .unwrap_or_default();
                for (url, log) in rows {
                    dump(format!("worker {url} (ended)"), serde_json::Value::String(log));
                }
            }
            for f in ctx.frame_list() {
                if let Ok(v) = ctx
                    .evaluate_in_frame(
                        f.id,
                        "typeof __pt_probeLog === 'function' ? __pt_probeLog() : ''",
                    )
                    .await
                {
                    dump(format!("frame {} {}", f.id, f.url), v);
                }
            }
        }

        // Три инструмента ниже — свои собственные: каждый включается своей
        // переменной. Раньше они стояли внутри ветки трассировщика проб и
        // молча ничего не делали без неё — а она сама меняет то, что мерят.
        // Хвост: чем страница и каждый фрейм занимались последними, по порядку.
        // Исходник программы челленджа — по требованию: 600+ КБ в лог не
        // кладут, а для чтения стека он нужен целиком.
        if let Ok(path) = std::env::var("NOKK_DUMP_VM") {
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            // Две большие строки, а не одна: источник, который отдают
            // `Function`, и та, что склеивается из ответа `/fo/`. Они
            // разные — начала не совпадают, — и сравнивать с браузером надо
            // обе, иначе легко сличить не то с тем.
            for (js, tag) in [
                ("typeof __pt_vmSrc === 'string' ? __pt_vmSrc : ''", "js"),
                // Самый большой встроенный скрипт документа: у кадра виджета
                // там и толкователь, и сам сбор — то место, куда указывают
                // смещения в стеке чужих ошибок.
                (
                    "(() => { let big = ''; for (const e of document.scripts) \
                       if (!e.src && e.textContent && e.textContent.length > big.length) \
                         big = e.textContent; \
                     return big; })()",
                    "doc",
                ),
                ("typeof __ptProg === 'string' ? __ptProg : ''", "join"),
                // Склейки помельче — отчёт, перечисление стилей — по одной
                // на файл: сравнивать их с браузером построчно можно только
                // целиком.
                ("(globalThis.__ptJoins||[]).map(j => j[0] + '\\u0000' + j[1]).join('\\u0001')", "joins"),
            ] {
            for slot in where_.clone() {
                let out = match slot {
                    None => ctx.evaluate(js).await,
                    Some(id) => ctx.evaluate_in_frame(id, js).await,
                };
                if let Ok(serde_json::Value::String(src)) = out {
                    if src.len() > 1000 {
                        let name = match slot {
                            None => format!("{path}.page.{tag}"),
                            Some(id) => format!("{path}.frame{id}.{tag}"),
                        };
                        if tag == "joins" {
                            for part in src.split('\u{1}') {
                                let Some((n, body)) = part.split_once('\u{0}') else {
                                    continue;
                                };
                                let name = format!("{name}.{n}");
                                if std::fs::write(&name, body).is_ok() {
                                    eprintln!("# склейка сохранена: {name} ({} байт)", body.len());
                                }
                            }
                        } else if std::fs::write(&name, &src).is_ok() {
                            eprintln!("# программа сохранена: {name} ({} байт)", src.len());
                        }
                    }
                }
            }
            }
        }
        // Спросить одно и то же у страницы и у каждого её кадра. Кадр
        // челленджа чужого происхождения, со страницы в него не заглянуть, а
        // движок ходит туда сам — и без этого половина сравнений с браузером
        // невозможна.
        if let Ok(js) = std::env::var("NOKK_EVAL_FRAMES") {
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(&js).await,
                    Some(id) => ctx.evaluate_in_frame(id, &js).await,
                };
                let label = slot
                    .map(|i| format!("frame {i}"))
                    .unwrap_or_else(|| "page".to_string());
                match out {
                    Ok(v) => eprintln!("# {label}: {}", render(&v)),
                    Err(e) => eprintln!("# {label}: ошибка: {e}"),
                }
            }
        }
        // Ошибки, которые чужая программа построила у себя в кадре: их не
        // прочитать со страницы — кадр чужого происхождения, — но движок
        // ходит в него сам.
        if std::env::var("NOKK_TRACE_THROWS").is_ok() {
            let js = "typeof __pt_throwTail === 'function' ? __pt_throwTail(20) : ''";
            let mut where_: Vec<Option<u32>> = vec![None];
            where_.extend(ctx.frame_list().iter().map(|f| Some(f.id)));
            for slot in where_ {
                let out = match slot {
                    None => ctx.evaluate(js).await,
                    Some(id) => ctx.evaluate_in_frame(id, js).await,
                };
                if let Ok(serde_json::Value::String(text)) = out {
                    if text.is_empty() {
                        continue;
                    }
                    let label = slot
                        .map(|i| format!("frame {i}"))
                        .unwrap_or_else(|| "page".to_string());
                    eprintln!("# броски {label}:");
                    for line in text.lines() {
                        eprintln!("#   {line}");
                    }
                }
            }
        }

        // Run `--eval` first — it may trigger further requests (fetch/beacon/img)
        // that should then appear in the interception log.
        if let Some(js) = &cli.eval {
            eval_and_print(&ctx, js).await?;
        }

        // Print the response body of a specific captured request (e.g. an API).
        if let Some(needle) = &cli.dump_request {
            match ctx.requests().into_iter().find(|r| r.url.contains(needle)) {
                Some(r) => {
                    eprintln!(
                        "# {} {} → {} ({} bytes)",
                        r.method,
                        r.url,
                        r.status,
                        r.body.len()
                    );
                    // Половина разговора — то, что ушло наверх. Маячок ошибки
                    // челленджа отвечает пустотой, а всё, что он рассказывает о
                    // нас, лежит в теле запроса; без него дамп молчит о главном.
                    if !r.request_body.is_empty() {
                        eprintln!("# отправлено ({} байт):", r.request_body.len());
                        println!("{}", String::from_utf8_lossy(&r.request_body));
                        eprintln!("# получено ({} байт):", r.body.len());
                    }
                    println!("{}", String::from_utf8_lossy(&r.body));
                }
                None => eprintln!("no captured request matching '{needle}'"),
            }
            return Ok(());
        }
        // List every request the page made (the built-in interception log).
        if cli.dump_requests {
            let reqs = ctx.requests();
            println!("{} requests for {url}", reqs.len());
            for r in &reqs {
                // Размер тела запроса виден только здесь, а он — половина
                // ответа на «что мы про себя рассказали».
                let sent = if r.request_body.is_empty() {
                    String::new()
                } else {
                    format!(" [отправлено {} байт]", r.request_body.len())
                };
                println!(
                    "[{:<8}] {:<4} {} → {} ({} bytes){sent}",
                    r.resource_type,
                    r.method,
                    r.url,
                    r.status,
                    r.body.len()
                );
            }
            return Ok(());
        }

        if cli.eval.is_none() {
            // Default summary: title + a count of elements in the built DOM.
            let title = ctx.evaluate("document.title").await.unwrap_or_default();
            let count = ctx
                .evaluate("document.querySelectorAll('*').length")
                .await
                .unwrap_or_default();
            println!("loaded {url}");
            println!("title: {title}");
            println!("elements: {count}");
        }
        return Ok(());
    }

    // One-shot eval mode: run JS in a stealth-patched context and print it
    // (driving the event loop so fetch/timers can complete).
    if let Some(js) = &cli.eval {
        let ctx = engine.new_context().await?;
        eval_and_print(&ctx, js).await?;
        return Ok(());
    }

    // Default: run the CDP server so Puppeteer/Playwright can drive the engine.
    let addr = std::net::SocketAddr::new(cli.host, cli.port);
    // Advertise a connectable host: 0.0.0.0 isn't dialable, so point clients at
    // loopback (the common `-p` / local case).
    let advertise = if cli.host.is_unspecified() {
        std::net::IpAddr::from([127, 0, 0, 1])
    } else {
        cli.host
    };
    println!(
        "CDP server on ws://{advertise}:{}/devtools/browser/nokk",
        cli.port
    );
    println!("  Puppeteer: puppeteer.connect({{ browserWSEndpoint: 'ws://{advertise}:{}/devtools/browser/nokk' }})", cli.port);
    nokk_cdp::serve(engine, nokk_cdp::ServerConfig { addr }).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nokk_net::ProxyScheme;

    #[test]
    fn parse_proxy_http_with_credentials() {
        let p = parse_proxy("http://user:pass@10.0.0.1:8080").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Http);
        assert_eq!(p.host, "10.0.0.1");
        assert_eq!(p.port, 8080);
        assert_eq!(p.username.as_deref(), Some("user"));
        assert_eq!(p.password.as_deref(), Some("pass"));
    }

    #[test]
    fn parse_proxy_socks5_without_credentials() {
        let p = parse_proxy("socks5://127.0.0.1:1080").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn parse_proxy_socks5h_maps_to_socks5() {
        let p = parse_proxy("socks5h://host.example:1081").expect("should parse");
        assert_eq!(p.scheme, ProxyScheme::Socks5);
    }

    #[test]
    fn parse_proxy_rejects_unsupported_scheme() {
        assert!(parse_proxy("ftp://host:21").is_none());
        assert!(parse_proxy("not a url").is_none());
    }

    #[test]
    fn parse_proxy_requires_explicit_port() {
        // No default-port inference — the proxy port must be given.
        assert!(parse_proxy("http://host.example").is_none());
    }

    #[test]
    fn render_unwraps_json_string_to_raw_text() {
        let v = serde_json::Value::String("line1\nline2".to_string());
        assert_eq!(render(&v), "line1\nline2");
    }

    #[test]
    fn render_leaves_non_strings_as_json() {
        let v = serde_json::json!({ "a": 1 });
        assert_eq!(render(&v), "{\"a\":1}");
    }
}
