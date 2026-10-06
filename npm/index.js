// nokk — launch the undetectable browser-engine CDP server and connect to it.
//
//   const nokk = require("nokk");
//   const puppeteer = require("puppeteer");
//   const server = await nokk.launch({ autoSolve: true });
//   const browser = await puppeteer.connect({ browserWSEndpoint: server.wsEndpoint });
//   const page = await browser.newPage();
//   await page.goto("https://www.scrapingcourse.com/cloudflare-challenge");
//   // a Cloudflare challenge on the way was solved before goto resolved
//   await server.close();
"use strict";

const { spawn } = require("child_process");
const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");

const EXE = process.platform === "win32" ? "nokk.exe" : "nokk";
const BUNDLED = path.join(__dirname, "vendor", EXE);

/** Absolute path to the bundled `nokk` binary (override with NOKK_BINARY). */
function binaryPath() {
  const override = process.env.NOKK_BINARY;
  if (override) {
    if (fs.existsSync(override)) return override;
    throw new Error(`NOKK_BINARY points at a missing file: ${override}`);
  }
  if (fs.existsSync(BUNDLED)) return BUNDLED;
  throw new Error(
    "the bundled `nokk` binary was not found — reinstall (`npm install nokk`). " +
      "Prebuilt binaries are currently Linux x64 only."
  );
}

function freePort(host) {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, host, () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function ready(host, port, query) {
  return new Promise((resolve) => {
    const req = http.get(`http://${host}:${port}/json/version${query || ""}`, (r) => {
      r.resume();
      resolve(r.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(1000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A running nokk CDP server. Returned by {@link launch}. */
class NokkServer {
  constructor(proc, host, port, token) {
    this._proc = proc;
    this.host = host;
    this.port = port;
    this._query = token ? `?token=${token}` : "";
  }
  /** browserWSEndpoint for puppeteer.connect / chromium.connectOverCDP. */
  get wsEndpoint() {
    return `ws://${this.host}:${this.port}/devtools/browser/nokk${this._query}`;
  }
  get httpEndpoint() {
    return `http://${this.host}:${this.port}`;
  }
  get pid() {
    return this._proc.pid;
  }
  /** Stop the server. Idempotent. */
  async close() {
    const p = this._proc;
    if (p.exitCode !== null || p.signalCode) return;
    p.kill("SIGTERM");
    await new Promise((resolve) => {
      const t = setTimeout(() => {
        try {
          p.kill("SIGKILL");
        } catch (_) {}
        resolve();
      }, 5000);
      p.once("exit", () => {
        clearTimeout(t);
        resolve();
      });
    });
  }
}

/**
 * Start a `nokk` CDP server and resolve to a {@link NokkServer}.
 *
 * @param {object} [opts]
 * @param {string}  [opts.host="127.0.0.1"]
 * @param {number}  [opts.port=0]                 0 = pick a free port
 * @param {number}  [opts.workers]
 * @param {number}  [opts.maxContexts]
 * @param {string}  [opts.proxy]                  e.g. "socks5://host:1080"
 * @param {string}  [opts.sessionStore]
 * @param {boolean} [opts.rotateFingerprint]
 * @param {boolean} [opts.geoipTimezone]
 * @param {boolean} [opts.allowTrackers]
 * @param {number}  [opts.chromeVersion]          e.g. 148
 * @param {boolean|number} [opts.autoSolve]       solve Cloudflare challenges on every
 *                                                 navigation before it reports the load;
 *                                                 `true` = 30 s budget, a number = seconds
 * @param {string[]}[opts.args]                    extra raw CLI args
 * @param {object}  [opts.env]
 * @param {number}  [opts.timeout=30000]          ms to wait for readiness
 */
async function launch(opts = {}) {
  const host = opts.host || "127.0.0.1";
  const port = opts.port || (await freePort(host));
  const args = ["--host", host, "--port", String(port)];
  if (opts.workers != null) args.push("--workers", String(opts.workers));
  if (opts.maxContexts != null) args.push("--max-contexts", String(opts.maxContexts));
  if (opts.proxy) args.push("--proxy", opts.proxy);
  if (opts.sessionStore) args.push("--session-store", String(opts.sessionStore));
  if (opts.rotateFingerprint) args.push("--rotate-fingerprint");
  if (opts.geoipTimezone) args.push("--geoip-timezone");
  if (opts.allowTrackers) args.push("--allow-trackers");
  if (opts.chromeVersion != null) args.push("--chrome-version", String(opts.chromeVersion));
  if (opts.autoSolve === true) args.push("--auto-solve");
  else if (typeof opts.autoSolve === "number") args.push("--auto-solve", String(opts.autoSolve));
  if (opts.args) args.push(...opts.args);

  const env = { ...process.env, ...(opts.env || {}) };
  const proc = spawn(binaryPath(), args, { stdio: opts.stdio || "inherit", env });
  // A NOKK_TOKEN in the child's environment guards its CDP port: carry it along.
  const server = new NokkServer(proc, host, port, env.NOKK_TOKEN || "");

  const timeout = opts.timeout != null ? opts.timeout : 30000;
  const deadline = Date.now() + timeout;
  const killOnExit = () => {
    try {
      proc.kill();
    } catch (_) {}
  };
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(`nokk exited before becoming ready (code ${proc.exitCode})`);
    }
    if (await ready(host, port, server._query)) {
      process.once("exit", killOnExit); // safety net
      return server;
    }
    await sleep(50);
  }
  await server.close();
  throw new Error(`nokk did not become ready within ${timeout}ms`);
}

// ---------------------------------------------------------------------------
// Challenges. nokk answers two non-standard CDP commands on a page's session —
// `Nokk.solveChallenge` and `Nokk.challengeState` — and sends a `Nokk.challenge`
// event when a navigation lands on a gate. These helpers take whatever the
// caller has: a Puppeteer Page, a Playwright Page, or a raw CDP session.

const _sessions = new WeakMap();

/** A CDP session bound to `target`'s page (cached per page). */
async function _session(target) {
  if (!target) throw new TypeError("expected a Puppeteer/Playwright Page or a CDP session");
  if (_sessions.has(target)) return _sessions.get(target);
  let s;
  if (typeof target.createCDPSession === "function") {
    s = await target.createCDPSession(); // Puppeteer Page
  } else if (typeof target.context === "function" && typeof target.context().newCDPSession === "function") {
    s = await target.context().newCDPSession(target); // Playwright Page
  } else if (typeof target.send === "function") {
    s = target; // already a CDP session
  } else {
    throw new TypeError("expected a Puppeteer/Playwright Page or a CDP session");
  }
  _sessions.set(target, s);
  return s;
}

/**
 * Solve the challenge the page shows now — a Cloudflare interstitial or a
 * Turnstile widget — pressing its checkbox if it puts one up. Resolves to
 * `{ status, solved, presses, elapsedMs, remaining, title, url, cleared, token }`.
 *
 * @param {object} page              Puppeteer Page, Playwright Page or CDP session
 * @param {object} [opts]
 * @param {number} [opts.timeout]    budget in ms (default: the server's, else 30000)
 */
async function solveChallenge(page, opts = {}) {
  const s = await _session(page);
  const params = opts.timeout != null ? { timeoutMs: opts.timeout } : {};
  return s.send("Nokk.solveChallenge", params);
}

/**
 * What gate the page shows: `{ kind, title, url, cleared, token, solvable }`, where
 * `kind` is "none", "cloudflare-interstitial", "turnstile-widget" or another
 * vendor's gate that nokk recognises but does not solve.
 */
async function challengeState(page) {
  const s = await _session(page);
  return s.send("Nokk.challengeState");
}

module.exports = { launch, binaryPath, NokkServer, solveChallenge, challengeState };
