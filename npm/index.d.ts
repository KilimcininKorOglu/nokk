export interface LaunchOptions {
  /** Address to bind (default "127.0.0.1"). */
  host?: string;
  /** TCP port; 0 (default) picks a free one. */
  port?: number;
  /** Isolate worker threads. */
  workers?: number;
  /** Cap on concurrent live contexts before backpressure. */
  maxContexts?: number;
  /** Upstream proxy, e.g. "socks5://host:1080" or "http://user:pass@host:port". */
  proxy?: string;
  /** Directory for persistent named-session cookie jars. */
  sessionStore?: string;
  /** Give each browser context its own coherent fingerprint. */
  rotateFingerprint?: boolean;
  /** Derive each context's timezone/locale from its proxy's exit IP. */
  geoipTimezone?: boolean;
  /** Load ad/analytics/tracker subresources (blocked by default). */
  allowTrackers?: boolean;
  /** Chrome major version to emulate (TLS + JS together), e.g. 148. */
  chromeVersion?: number;
  /**
   * Solve Cloudflare challenges (interstitial or Turnstile widget) on every
   * navigation before it reports the load. `true` = 30 s budget; a number =
   * seconds. A browser context created with `autoSolve: false` opts out.
   */
  autoSolve?: boolean | number;
  /** Extra raw CLI arguments passed to the binary. */
  args?: string[];
  /** Extra environment variables for the server process. */
  env?: Record<string, string>;
  /** stdio option for the child process (default "inherit"). */
  stdio?: any;
  /** Milliseconds to wait for the server to become ready (default 30000). */
  timeout?: number;
}

export declare class NokkServer {
  readonly host: string;
  readonly port: number;
  /** browserWSEndpoint for puppeteer.connect / chromium.connectOverCDP. */
  readonly wsEndpoint: string;
  readonly httpEndpoint: string;
  readonly pid: number;
  /** Stop the server. Idempotent. */
  close(): Promise<void>;
}

/** Start a nokk CDP server and resolve to a NokkServer. */
export declare function launch(options?: LaunchOptions): Promise<NokkServer>;

/** Absolute path to the bundled `nokk` binary (override with NOKK_BINARY). */
export declare function binaryPath(): string;

/** The gate a page shows. Only the Cloudflare kinds are solvable. */
export type ChallengeKind =
  | "none"
  | "cloudflare-interstitial"
  | "turnstile-widget"
  | "datadome";

export type ChallengeStatus = "cleared" | "token-issued" | "cleared-but-stuck" | "timeout";

export interface ChallengeState {
  kind: ChallengeKind;
  title: string;
  url: string;
  /** A `cf_clearance` cookie is in the jar for this site. */
  cleared: boolean;
  /** A Turnstile widget on the page has issued its token. */
  token: boolean;
  solvable: boolean;
}

export interface ChallengeOutcome {
  status: ChallengeStatus;
  /** `status` is "cleared" or "token-issued". */
  solved: boolean;
  /** Checkbox presses it took (0 for a non-interactive challenge). */
  presses: number;
  elapsedMs: number;
  /** The gate still on the page afterwards ("none" when through). */
  remaining: ChallengeKind;
  title: string;
  url: string;
  cleared: boolean;
  token: boolean;
}

/** Anything the helpers can reach a page's CDP session through. */
export type PageLike =
  | { createCDPSession(): Promise<{ send(method: string, params?: object): Promise<any> }> }
  | { context(): { newCDPSession(page: any): Promise<{ send(method: string, params?: object): Promise<any> }> } }
  | { send(method: string, params?: object): Promise<any> };

/**
 * Solve the challenge the page shows now, pressing its checkbox if it puts
 * one up. Accepts a Puppeteer Page, a Playwright Page or a raw CDP session.
 */
export declare function solveChallenge(
  page: PageLike,
  options?: { /** Budget in ms (default: the server's, else 30000). */ timeout?: number }
): Promise<ChallengeOutcome>;

/** What gate the page shows right now. */
export declare function challengeState(page: PageLike): Promise<ChallengeState>;
