//! Import maps (`<script type="importmap">`), as the HTML standard resolves
//! module specifiers with them. GitHub's pages import `react` and friends by
//! bare name; without the map every module graph failed to load.

use url::Url;

/// One parsed import map: top-level `imports` and per-prefix `scopes`, each
/// sorted with the longest key first so the most specific prefix wins.
/// Specifier (or prefix) to address; `None` is a mapping that resolves to an error.
type SpecifierMap = Vec<(String, Option<Url>)>;

#[derive(Debug, Default, Clone)]
pub(crate) struct ImportMap {
    imports: SpecifierMap,
    scopes: Vec<(String, SpecifierMap)>,
}

/// A specifier that is a URL or starts like a path (`/`, `./`, `../`).
fn url_like(spec: &str, base: &Url) -> Option<Url> {
    if spec.starts_with('/') || spec.starts_with("./") || spec.starts_with("../") {
        return base.join(spec).ok();
    }
    Url::parse(spec).ok()
}

fn sort_longest_first<T>(v: &mut [(String, T)]) {
    v.sort_by(|a, b| b.0.cmp(&a.0));
}

fn specifier_map(obj: &serde_json::Map<String, serde_json::Value>, base: &Url) -> SpecifierMap {
    let mut out = Vec::new();
    for (key, value) in obj {
        if key.is_empty() {
            continue;
        }
        let key = url_like(key, base).map(|u| u.to_string()).unwrap_or_else(|| key.clone());
        // A value that is not an address, or a prefix key mapped to a
        // non-prefix address, makes the key resolve to an error.
        let addr = value.as_str().and_then(|v| url_like(v, base));
        let addr = addr.filter(|a| !key.ends_with('/') || a.as_str().ends_with('/'));
        out.push((key, addr));
    }
    sort_longest_first(&mut out);
    out
}

impl ImportMap {
    /// Parse the map's JSON against the document's address. Invalid JSON or a
    /// non-object top level gives `None` (the browser reports an error).
    pub(crate) fn parse(json: &str, base: &str) -> Option<Self> {
        let base = Url::parse(base).ok()?;
        let v: serde_json::Value = serde_json::from_str(json).ok()?;
        let top = v.as_object()?;
        let imports = top.get("imports").and_then(|i| i.as_object()).map(|o| specifier_map(o, &base)).unwrap_or_default();
        let mut scopes = Vec::new();
        if let Some(s) = top.get("scopes").and_then(|s| s.as_object()) {
            for (prefix, map) in s {
                let (Ok(p), Some(m)) = (base.join(prefix), map.as_object()) else { continue };
                scopes.push((p.to_string(), specifier_map(m, &base)));
            }
        }
        sort_longest_first(&mut scopes);
        Some(Self { imports, scopes })
    }

    /// A later map adds what the earlier one does not already define.
    pub(crate) fn merge(&mut self, other: ImportMap) {
        for (k, v) in other.imports {
            if !self.imports.iter().any(|(e, _)| *e == k) {
                self.imports.push((k, v));
            }
        }
        sort_longest_first(&mut self.imports);
        for (p, m) in other.scopes {
            match self.scopes.iter_mut().find(|(e, _)| *e == p) {
                Some((_, mine)) => {
                    for (k, v) in m {
                        if !mine.iter().any(|(e, _)| *e == k) {
                            mine.push((k, v));
                        }
                    }
                    sort_longest_first(mine);
                }
                None => self.scopes.push((p, m)),
            }
        }
        sort_longest_first(&mut self.scopes);
    }
}

fn match_in(normalized: &str, as_url: Option<&Url>, map: &SpecifierMap) -> Option<Option<String>> {
    for (key, addr) in map {
        if key == normalized {
            return Some(addr.as_ref().map(|a| a.to_string()));
        }
        let special = as_url.is_none_or(|u| matches!(u.scheme(), "http" | "https" | "ftp" | "ws" | "wss" | "file"));
        if key.ends_with('/') && normalized.starts_with(key.as_str()) && special {
            let Some(addr) = addr else { return Some(None) };
            let rest = &normalized[key.len()..];
            // The result must stay under the address it was mapped to.
            return Some(addr.join(rest).ok().map(|u| u.to_string()).filter(|u| u.starts_with(addr.as_str())));
        }
    }
    None
}

/// Resolve `spec` imported from `base`: through the map when there is one,
/// else as a URL. `None` is the browser's "Failed to resolve module
/// specifier" (a bare name with no mapping, or a mapping to nothing).
pub(crate) fn resolve(map: Option<&ImportMap>, base: &str, spec: &str) -> Option<String> {
    let base_url = Url::parse(base).ok()?;
    let as_url = url_like(spec, &base_url);
    let normalized = as_url.as_ref().map(|u| u.to_string()).unwrap_or_else(|| spec.to_string());
    if let Some(map) = map {
        let base_str = base_url.as_str();
        for (prefix, scope) in &map.scopes {
            if prefix == base_str || (prefix.ends_with('/') && base_str.starts_with(prefix.as_str())) {
                if let Some(r) = match_in(&normalized, as_url.as_ref(), scope) {
                    return r;
                }
            }
        }
        if let Some(r) = match_in(&normalized, as_url.as_ref(), &map.imports) {
            return r;
        }
    }
    as_url.map(|u| u.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_names_resolve_only_through_the_map() {
        let doc = "https://site.test/app/page.html";
        let map = ImportMap::parse(
            r#"{"imports":{"react":"https://cdn.test/react-1.js","lib/":"./vendor/lib/","bad":42,"pre/":"https://cdn.test/no-slash"},
                "scopes":{"/app/legacy/":{"react":"https://cdn.test/react-0.js"}}}"#,
            doc,
        )
        .unwrap();
        let m = Some(&map);
        assert_eq!(resolve(m, doc, "react").as_deref(), Some("https://cdn.test/react-1.js"));
        assert_eq!(resolve(m, "https://site.test/app/legacy/x.js", "react").as_deref(), Some("https://cdn.test/react-0.js"));
        assert_eq!(resolve(m, doc, "lib/a/b.js").as_deref(), Some("https://site.test/app/vendor/lib/a/b.js"));
        assert_eq!(resolve(m, doc, "./x.js").as_deref(), Some("https://site.test/app/x.js"));
        assert_eq!(resolve(m, doc, "https://other.test/y.js").as_deref(), Some("https://other.test/y.js"));
        assert_eq!(resolve(m, doc, "vue"), None, "an unmapped bare name does not resolve");
        assert_eq!(resolve(m, doc, "bad"), None, "a key mapped to a non-address is an error");
        assert_eq!(resolve(m, doc, "pre/x"), None, "a prefix mapped to a non-prefix is an error");
        assert_eq!(resolve(None, doc, "react"), None);
        assert_eq!(resolve(None, doc, "../z.js").as_deref(), Some("https://site.test/z.js"));
    }

    #[test]
    fn a_url_key_remaps_that_url_and_a_later_map_only_adds() {
        let doc = "https://site.test/";
        let mut map = ImportMap::parse(r#"{"imports":{"/a.js":"/b.js"}}"#, doc).unwrap();
        map.merge(ImportMap::parse(r#"{"imports":{"/a.js":"/c.js","d":"/d.js"}}"#, doc).unwrap());
        assert_eq!(resolve(Some(&map), doc, "./a.js").as_deref(), Some("https://site.test/b.js"));
        assert_eq!(resolve(Some(&map), doc, "d").as_deref(), Some("https://site.test/d.js"));
        assert!(ImportMap::parse("[1]", doc).is_none());
    }
}
