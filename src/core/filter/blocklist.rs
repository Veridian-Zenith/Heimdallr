// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! M6.1 — Blocklist loader.
//!
//! Supports the standard source-file styles used by hagezi, OISD,
//! AdGuard, StevenBlack, urlhaus, and similar lists:
//!
//! - **Hosts format**: `0.0.0.0 example.com` / `127.0.0.1 example.com`
//!   per line, comments (`#`) and blank lines skipped.
//! - **AdGuard DNS style**: `||example.com^` (and `@@||example.com^`
//!   exception, treated as block for our purposes).
//! - **Meta-list**: a file whose content is mostly URLs to other
//!   blocklists (hagezi wildcard lists, OISD, urlhaus, etc.). URLs
//!   are extracted, fetched, and parsed. Recursion is bounded.
//!
//! Matching is suffix-based: an entry for `example.com` blocks
//! `ads.example.com`. The separate [`Allowlist`] overrides
//! [`Blocklist`] matches.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::time::Duration;

use tracing::{debug, warn};

/// Max recursion depth for meta-list expansion.
const META_MAX_DEPTH: u8 = 4;

/// Per-URL fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// In-memory blocklist (FQDNs, lowercased, trailing dot stripped).
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    entries: HashSet<String>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add a single FQDN (normalized).
    pub fn insert(&mut self, name: &str) {
        let n = normalize(name);
        if !n.is_empty() {
            self.entries.insert(n);
        }
    }

    /// Parse a hosts-format string and merge entries into self.
    /// Invalid lines are skipped.
    pub fn parse_hosts(&mut self, text: &str) {
        for line in text.lines() {
            if let Some(name) = parse_hosts_line(line) {
                self.entries.insert(name);
            }
        }
    }

    /// True if the text is a meta-list (mostly URLs, few/no
    /// hosts-format entries). Used to decide whether to recurse.
    fn looks_like_meta_list(text: &str) -> bool {
        let mut sources = 0usize;
        let mut hosts = 0usize;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if is_url(trimmed) || trimmed.starts_with('/') {
                sources += 1;
            } else if trimmed.starts_with("||")
                || trimmed.starts_with("@@||")
                || trimmed
                    .split_whitespace()
                    .next()
                    .is_some_and(|t| t.parse::<std::net::Ipv4Addr>().is_ok())
            {
                hosts += 1;
            }
        }
        sources >= 2 && sources > hosts
    }

    /// Load every source. Each source may be a file path or an
    /// `http(s)://` URL. File sources whose content is a meta-list
    /// (mostly URLs) are expanded recursively up to
    /// [`META_MAX_DEPTH`].
    pub fn load_sources(sources: &[String]) -> Self {
        let mut bl = Self::new();
        let mut visited: HashSet<String> = HashSet::new();
        for src in sources {
            load_source(src, &mut bl, &mut visited, 0);
        }
        bl
    }

    /// True if `qname` matches a blocklist entry or any of its
    /// parent names. Case-insensitive. `qname` may have a trailing
    /// dot or not.
    pub fn is_blocked(&self, qname: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let normalized = normalize(qname);
        let mut cur = normalized.as_str();
        loop {
            if self.entries.contains(cur) {
                return true;
            }
            match cur.find('.') {
                Some(idx) => cur = &cur[idx + 1..],
                None => return false,
            }
        }
    }
}

/// In-memory allowlist (FQDNs, lowercased). Mirrors blocklist
/// semantics: an entry for `example.com` allows all subdomains.
#[derive(Debug, Default, Clone)]
pub struct Allowlist(HashSet<String>);

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Load every source. Each source may be a file path or URL.
    /// Meta-lists are expanded.
    pub fn load_sources(sources: &[String]) -> Self {
        let mut bl = Blocklist::new();
        let mut visited: HashSet<String> = HashSet::new();
        for src in sources {
            load_source(src, &mut bl, &mut visited, 0);
        }
        Self(bl.entries)
    }

    /// True if `qname` matches an allowlist entry or any of its
    /// parent names. Case-insensitive.
    pub fn is_allowed(&self, qname: &str) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let normalized = normalize(qname);
        let mut cur = normalized.as_str();
        loop {
            if self.0.contains(cur) {
                return true;
            }
            match cur.find('.') {
                Some(idx) => cur = &cur[idx + 1..],
                None => return false,
            }
        }
    }
}

/// True if `qname` is on the blocklist AND not on the allowlist.
pub fn blocked(blocklist: &Blocklist, allowlist: &Allowlist, qname: &str) -> bool {
    if allowlist.is_allowed(qname) {
        return false;
    }
    blocklist.is_blocked(qname)
}

// ── Internals ────────────────────────────────────────────────────────────────

/// Load a single source into `bl`. `visited` deduplicates URLs and
/// file paths. `depth` bounds meta-list recursion.
fn load_source(src: &str, bl: &mut Blocklist, visited: &mut HashSet<String>, depth: u8) {
    let key = normalize(src);
    if !visited.insert(key) {
        return;
    }
    if depth > META_MAX_DEPTH {
        warn!("blocklist: max meta-list depth exceeded at '{src}', skipping");
        return;
    }
    let text = match fetch_text(src) {
        Ok(t) => t,
        Err(e) => {
            warn!("blocklist: failed to load '{src}': {e}");
            return;
        }
    };
    if Blocklist::looks_like_meta_list(&text) {
        debug!("blocklist: meta-list detected at '{src}' (depth={depth})");
        for line in text.lines() {
            let trimmed = line.trim();
            if is_url(trimmed) || trimmed.starts_with('/') {
                load_source(trimmed, bl, visited, depth + 1);
            }
        }
    } else {
        let n_before = bl.len();
        bl.parse_hosts(&text);
        debug!(
            "blocklist: parsed {} entries from '{src}' (depth={depth})",
            bl.len() - n_before
        );
    }
}

/// Fetch text from a URL or read from a local file. Returns the
/// raw text body.
fn fetch_text(src: &str) -> io::Result<String> {
    if is_url(src) {
        fetch_url(src)
    } else {
        fs::read_to_string(src)
    }
}

/// Fetch a URL body with `ureq`. Blocks the current thread.
fn fetch_url(url: &str) -> io::Result<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().build().into();
    match agent.get(url).call() {
        Ok(mut resp) => resp
            .body_mut()
            .read_to_string()
            .map_err(|e| io::Error::other(format!("read body: {e}"))),
        Err(e) => Err(io::Error::other(format!("HTTP: {e}"))),
    }
}

/// True if `s` looks like an http(s) URL.
fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Parse a single hosts-format line. Returns the FQDN (no trailing
/// dot, lowercased) if the line is a valid block entry, or None.
fn parse_hosts_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    // AdGuard DNS style: ||example.com^ or exception @@||example.com^
    if let Some(stripped) = trimmed
        .strip_prefix("||")
        .or_else(|| trimmed.strip_prefix("@@||"))
    {
        let stripped = stripped.trim_end_matches('^');
        let name = stripped.split_whitespace().next()?;
        if name.is_empty()
            || name == "localhost"
            || name == "localhost.localdomain"
            || name.contains('/')
        {
            return None;
        }
        return Some(normalize(name));
    }
    // Hosts format: <ip> <name> [<name> ...]
    let mut parts = trimmed.split_whitespace();
    let first = parts.next()?;
    // Reject bare URLs in hosts files (they're not block entries).
    if is_url(first) {
        return None;
    }
    if first.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    let name = parts.next()?;
    if name.is_empty()
        || name == "localhost"
        || name == "localhost.localdomain"
        || name.contains('/')
    {
        return None;
    }
    Some(normalize(name))
}

/// Normalize a QNAME for matching: strip trailing dot, lowercase.
fn normalize(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_basic_hosts() {
        let mut bl = Blocklist::new();
        bl.parse_hosts(
            "\
# This is a comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net

0.0.0.0 doubleclick.net
",
        );
        assert_eq!(bl.len(), 3);
        assert!(bl.is_blocked("ads.example.com."));
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("sub.ads.example.com"));
        assert!(!bl.is_blocked("example.com"));
    }

    #[test]
    fn parse_adguard_format() {
        let mut bl = Blocklist::new();
        bl.parse_hosts("||ads.example.com^\n||allowed.example.com^\n");
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("x.ads.example.com"));
        assert!(bl.is_blocked("allowed.example.com"));
    }

    #[test]
    fn ignore_localhost_and_blank() {
        let mut bl = Blocklist::new();
        bl.parse_hosts("\n\n# c\n0.0.0.0 localhost\n0.0.0.0 localhost.localdomain\n");
        assert!(bl.is_empty());
    }

    #[test]
    fn case_insensitive() {
        let mut bl = Blocklist::new();
        bl.parse_hosts("0.0.0.0 Ads.Example.COM");
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("ADS.EXAMPLE.COM"));
        assert!(bl.is_blocked("sub.ads.example.com"));
    }

    #[test]
    fn suffix_match_walks_labels() {
        let mut bl = Blocklist::new();
        bl.parse_hosts("0.0.0.0 example.com");
        assert!(bl.is_blocked("a.b.c.example.com"));
        assert!(bl.is_blocked("example.com"));
        assert!(!bl.is_blocked("notexample.com"));
        assert!(!bl.is_blocked("example.org"));
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut bl = Blocklist::new();
        bl.parse_hosts("0.0.0.0 example.com\n");
        let empty = Allowlist::new();
        assert!(blocked(&bl, &empty, "x.example.com"));

        let text = "0.0.0.0 sub.example.com\n";
        let t = tmp(text);
        let allow = Allowlist::load_sources(&[t.path().to_string_lossy().into()]);
        assert!(blocked(&bl, &allow, "x.example.com"));
        assert!(!blocked(&bl, &allow, "sub.example.com"));
        assert!(!blocked(&bl, &allow, "deep.sub.example.com"));
    }

    #[test]
    fn meta_list_detection() {
        let meta = "\
# Hagezi lists
https://example.com/a.txt
https://example.com/b.txt
https://example.com/c.txt
";
        assert!(Blocklist::looks_like_meta_list(meta));

        let hosts = "\
# Hosts file
0.0.0.0 a.example
0.0.0.0 b.example
";
        assert!(!Blocklist::looks_like_meta_list(hosts));

        let mixed = "\
0.0.0.0 a.example
https://example.com/b.txt
";
        assert!(!Blocklist::looks_like_meta_list(mixed));
    }

    #[test]
    fn meta_list_file_expands_recursively() {
        // Build a meta-list that points to two local hosts files.
        let hosts_a = tmp("0.0.0.0 a.example\n");
        let hosts_b = tmp("0.0.0.0 b.example\n");
        let meta_body = format!(
            "# meta\n{}\n{}\n",
            hosts_a.path().display(),
            hosts_b.path().display()
        );
        let meta_file = tmp(&meta_body);
        let bl = Blocklist::load_sources(&[meta_file.path().to_string_lossy().into()]);
        assert!(bl.is_blocked("a.example"));
        assert!(bl.is_blocked("b.example"));
        assert!(!bl.is_blocked("c.example"));
    }

    #[test]
    fn hosts_line_with_url_prefix_is_rejected() {
        // Some meta-lists have a stray "0.0.0.0 https://..." — reject.
        let mut bl = Blocklist::new();
        bl.parse_hosts("0.0.0.0 https://example.com/list\n");
        assert!(bl.is_empty());
    }

    #[test]
    fn load_sources_dedup() {
        // Same source twice should not double-count.
        let t = tmp("0.0.0.0 a.example\n");
        let bl = Blocklist::load_sources(&[
            t.path().to_string_lossy().into(),
            t.path().to_string_lossy().into(),
        ]);
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn load_file_roundtrip() {
        let text = "# header\n0.0.0.0 a.example\n0.0.0.0 b.example\n";
        let t = tmp(text);
        let bl = Blocklist::load_file_inline(t.path()).unwrap();
        assert_eq!(bl.len(), 2);
        assert!(bl.is_blocked("a.example"));
    }

    #[test]
    fn load_sources_missing_is_warned_not_errored() {
        let bl = Blocklist::load_sources(&["/nonexistent/path/hosts".into()]);
        assert!(bl.is_empty());
    }

    // Helper: expose load_file for the roundtrip test.
    impl Blocklist {
        pub(crate) fn load_file_inline(path: &std::path::Path) -> io::Result<Self> {
            let text = fs::read_to_string(path)?;
            let mut bl = Self::new();
            bl.parse_hosts(&text);
            Ok(bl)
        }
    }
}
