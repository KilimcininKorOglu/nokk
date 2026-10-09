//! Client hints a site asks for with `Accept-CH`, sent the way Chrome 151 sends
//! them (captured from Chrome against a local server, and from Blink's
//! `FrameFetchContext::AddClientHintsIfNecessary`).
//!
//! - A navigation response's `Accept-CH` replaces the origin's set (empty
//!   clears it); the document's own subresources already carry it.
//! - Only the requested hints go out, and only to the same origin.
//! - `Critical-CH` naming a hint that was not sent restarts the navigation
//!   once, with it.
//! - A navigation lists hints in the browser's fixed order. A subresource's
//!   headers come out of Blink's `HTTPHeaderMap`, a hash table, so their order
//!   is the table's slot order and changes with the set of names.

use std::collections::HashMap;
use std::sync::Mutex;

/// The values the hints report. They must agree with what the page reads from
/// `navigator.userAgentData`, `deviceMemory`, `innerWidth` and the rest.
#[derive(Debug, Clone)]
pub struct HintValues {
    pub full_version: String,
    pub arch: String,
    pub bitness: String,
    pub model: String,
    pub platform_version: String,
    pub device_memory: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
}

impl Default for HintValues {
    fn default() -> Self {
        Self {
            full_version: "151.0.7922.173".into(),
            arch: "x86".into(),
            bitness: "64".into(),
            model: String::new(),
            platform_version: String::new(),
            device_memory: 8,
            viewport_width: 1920,
            viewport_height: 969,
        }
    }
}

/// The three a request always carries.
pub(crate) const BASE: [&str; 3] = ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];

/// Order on a navigation (the browser process adds them).
pub(crate) const NAVIGATION_ORDER: [&str; 24] = [
    "device-memory",
    "sec-ch-device-memory",
    "dpr",
    "sec-ch-dpr",
    "viewport-width",
    "sec-ch-viewport-width",
    "sec-ch-viewport-height",
    "rtt",
    "downlink",
    "ect",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-full-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-form-factors",
    "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-reduced-transparency",
];

/// Order Blink inserts them into a subresource's header map.
pub(crate) const BLINK_INSERT_ORDER: [&str; 24] = [
    "device-memory",
    "sec-ch-device-memory",
    "rtt",
    "downlink",
    "ect",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-form-factors",
    "sec-ch-prefers-reduced-transparency",
    "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-color-scheme",
    "dpr",
    "sec-ch-dpr",
    "viewport-width",
    "sec-ch-viewport-width",
    "sec-ch-viewport-height",
];

/// A hint name we send, as it appears in `NAVIGATION_ORDER`; `None` for names
/// Chrome would not send here (`save-data` is off, `width` needs `sizes`).
fn known(name: &str) -> Option<&'static str> {
    let lower = name.trim().to_ascii_lowercase();
    NAVIGATION_ORDER.iter().copied().find(|n| *n == lower)
}

/// The hints an `Accept-CH` value asks for, beyond the three always sent.
pub(crate) fn parse(value: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for part in value.split(',') {
        if let Some(n) = known(part) {
            if !BASE.contains(&n) && !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

impl HintValues {
    /// The header value for `name`.
    pub(crate) fn value(&self, name: &str) -> Option<String> {
        let full = &self.full_version;
        Some(match name {
            "device-memory" | "sec-ch-device-memory" => self.device_memory.to_string(),
            "dpr" | "sec-ch-dpr" => "1".into(),
            "viewport-width" | "sec-ch-viewport-width" => self.viewport_width.to_string(),
            "sec-ch-viewport-height" => self.viewport_height.to_string(),
            // A fast connection: what `navigator.connection` reports by default.
            "rtt" => "50".into(),
            "downlink" => "1.55".into(),
            "ect" => "4g".into(),
            "sec-ch-ua-full-version" => format!("\"{full}\""),
            "sec-ch-ua-arch" => format!("\"{}\"", self.arch),
            "sec-ch-ua-platform-version" => format!("\"{}\"", self.platform_version),
            "sec-ch-ua-model" => format!("\"{}\"", self.model),
            "sec-ch-ua-bitness" => format!("\"{}\"", self.bitness),
            "sec-ch-ua-wow64" => "?0".into(),
            "sec-ch-ua-full-version-list" => format!(
                "\"Not=A?Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"{full}\", \"Chromium\";v=\"{full}\""
            ),
            "sec-ch-ua-form-factors" => "\"Desktop\"".into(),
            "sec-ch-prefers-color-scheme" => "light".into(),
            "sec-ch-prefers-reduced-motion" | "sec-ch-prefers-reduced-transparency" => {
                "no-preference".into()
            }
            _ => return None,
        })
    }
}

/// Per-origin hint preferences, kept for the client's lifetime like its
/// cookies.
#[derive(Debug, Default)]
pub(crate) struct HintStore {
    prefs: Mutex<HashMap<String, Vec<&'static str>>>,
}

impl HintStore {
    pub(crate) fn get(&self, origin: &str) -> Vec<&'static str> {
        self.prefs
            .lock()
            .map(|p| p.get(origin).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Store what `Accept-CH` asked for; an empty value forgets the origin.
    pub(crate) fn set(&self, origin: &str, hints: Vec<&'static str>) {
        if let Ok(mut p) = self.prefs.lock() {
            if hints.is_empty() {
                p.remove(origin);
            } else {
                p.insert(origin.to_string(), hints);
            }
        }
    }
}

/// Client hints only go to potentially trustworthy origins.
pub(crate) fn secure(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let host = url
        .strip_prefix("http://")
        .and_then(|r| r.split(['/', '?', '#']).next())
        .unwrap_or("");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

// --- Blink's header map -----------------------------------------------------
//
// `HTTPHeaderMap` is a WTF `HashMap` keyed with `DeprecatedCaseFoldingHash`:
// rapidhash over the name folded to lower case and widened to UTF-16, masked
// to 24 bits. Open addressing with quadratic probing, 8 buckets to start,
// doubled once half full; growing reinserts in old slot order. Iteration is
// slot order. (third_party/blink/renderer/platform/wtf/hash_table.h,
// text/case_folding_hash.h, third_party/rapidhash/rapidhash.h, 7922.)

const RAPID_SEED: u64 = 0xbdd8_9aa9_8270_4029;
const RAPID_SECRET: [u64; 3] = [0x2d35_8dcc_aa6c_78a5, 0x8bb8_4b93_962e_acc9, 0x4b33_a62e_d433_d4a3];

fn mul128(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128) * (b as u128);
    (r as u64, (r >> 64) as u64)
}

fn mix(a: u64, b: u64) -> u64 {
    let (lo, hi) = mul128(a, b);
    lo ^ hi
}

fn read64(p: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(p[i..i + 8].try_into().unwrap_or([0; 8]))
}

fn read32(p: &[u8], i: usize) -> u64 {
    u32::from_le_bytes(p[i..i + 4].try_into().unwrap_or([0; 4])) as u64
}

fn rapidhash(p: &[u8]) -> u64 {
    let n = p.len();
    let mut seed = RAPID_SEED;
    seed ^= mix(seed ^ RAPID_SECRET[0], RAPID_SECRET[1]) ^ n as u64;
    let (mut a, mut b);
    if n <= 16 {
        if n >= 4 {
            let plast = n - 4;
            a = (read32(p, 0) << 32) | read32(p, plast);
            let delta = (n & 24) >> (n >> 3);
            b = (read32(p, delta) << 32) | read32(p, plast - delta);
        } else if n > 0 {
            a = ((p[0] as u64) << 56) | ((p[n >> 1] as u64) << 32) | p[n - 1] as u64;
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        let mut i = n;
        let mut off = 0;
        if i > 48 {
            let (mut see1, mut see2) = (seed, seed);
            loop {
                seed = mix(read64(p, off) ^ RAPID_SECRET[0], read64(p, off + 8) ^ seed);
                see1 = mix(read64(p, off + 16) ^ RAPID_SECRET[1], read64(p, off + 24) ^ see1);
                see2 = mix(read64(p, off + 32) ^ RAPID_SECRET[2], read64(p, off + 40) ^ see2);
                off += 48;
                i -= 48;
                if i < 48 {
                    break;
                }
            }
            seed ^= see1 ^ see2;
        }
        if i > 16 {
            seed = mix(read64(p, off) ^ RAPID_SECRET[2], read64(p, off + 8) ^ seed ^ RAPID_SECRET[1]);
            if i > 32 {
                seed = mix(read64(p, off + 16) ^ RAPID_SECRET[2], read64(p, off + 24) ^ seed);
            }
        }
        a = read64(p, off + i - 16);
        b = read64(p, off + i - 8);
    }
    a ^= RAPID_SECRET[1];
    b ^= seed;
    let (lo, hi) = mul128(a, b);
    mix(lo ^ RAPID_SECRET[0] ^ n as u64, hi ^ RAPID_SECRET[1])
}

/// `DeprecatedCaseFoldingHash` of an ASCII header name.
fn fold_hash(name: &str) -> u32 {
    let wide: Vec<u8> = name
        .bytes()
        .flat_map(|c| [c.to_ascii_lowercase(), 0])
        .collect();
    let h = (rapidhash(&wide) & ((1 << 24) - 1)) as u32;
    if h == 0 {
        0x8000_0000 >> 8
    } else {
        h
    }
}

fn place(table: &mut [Option<String>], name: String) {
    let mask = table.len() - 1;
    let mut i = fold_hash(&name) as usize & mask;
    let mut probe = 0;
    while table[i].is_some() {
        probe += 1;
        i = (i + probe) & mask;
    }
    table[i] = Some(name);
}

/// The order Blink's header map yields `names`, inserted in the given order.
/// Names are lower-case and distinct.
pub(crate) fn blink_map_order(names: &[String]) -> Vec<String> {
    let mut table: Vec<Option<String>> = vec![None; 8];
    let mut count = 0;
    for name in names {
        if table.iter().flatten().any(|n| n == name) {
            continue;
        }
        place(&mut table, name.clone());
        count += 1;
        if count * 2 >= table.len() {
            let mut grown: Vec<Option<String>> = vec![None; table.len() * 2];
            for n in table.into_iter().flatten() {
                place(&mut grown, n);
            }
            table = grown;
        }
    }
    table.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(insert: &[&str]) -> Vec<String> {
        blink_map_order(&insert.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    /// Subresource header orders captured from Chrome 151.0.7922.173.
    #[test]
    fn the_header_map_orders_names_as_chrome_does() {
        assert_eq!(
            order(&["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent"]),
            ["sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile"]
        );
        assert_eq!(
            order(&["content-type", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent"]),
            ["sec-ch-ua-platform", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile"]
        );
        assert_eq!(
            order(&["x-api-key", "authorization", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent"]),
            ["sec-ch-ua-platform", "authorization", "user-agent", "sec-ch-ua", "x-api-key", "sec-ch-ua-mobile"]
        );
        let all: Vec<&str> = BLINK_INSERT_ORDER.iter().copied().chain(["user-agent"]).collect();
        assert_eq!(
            order(&all),
            [
                "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width", "device-memory",
                "sec-ch-ua", "sec-ch-dpr", "sec-ch-ua-model", "sec-ch-ua-mobile", "sec-ch-ua-form-factors",
                "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch", "sec-ch-prefers-reduced-transparency",
                "sec-ch-ua-full-version", "sec-ch-viewport-width", "downlink", "sec-ch-viewport-height", "ect",
                "sec-ch-device-memory", "sec-ch-prefers-reduced-motion", "dpr", "sec-ch-prefers-color-scheme",
                "user-agent", "rtt", "sec-ch-ua-platform-version",
            ]
        );
        assert_eq!(
            order(&["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-bitness", "dpr", "user-agent"]),
            ["sec-ch-ua-platform", "dpr", "user-agent", "sec-ch-ua", "sec-ch-ua-bitness", "sec-ch-ua-mobile", "sec-ch-ua-platform-version"]
        );
    }

    #[test]
    fn accept_ch_names_the_hints_to_send() {
        assert_eq!(parse("Sec-CH-UA-Arch, sec-ch-ua-model,Sec-CH-UA, Save-Data, Width, bogus"), ["sec-ch-ua-arch", "sec-ch-ua-model"]);
        assert!(parse("").is_empty());
        assert!(secure("https://a.b/"));
        assert!(secure("http://localhost:8080/x"));
        assert!(secure("http://127.0.0.1:9/"));
        assert!(!secure("http://example.com/"));
    }
}
