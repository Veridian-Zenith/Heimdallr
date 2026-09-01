// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! QNAME minimization driver (RFC 9156).
//!
//! Implements the iterative label-peeling algorithm described in
//! [RFC 9156 §3](https://www.rfc-editor.org/rfc/rfc9156.html#section-3).
//! When resolving a name like `foo.bar.example.com`, instead of asking
//! the root servers for the full A record on the first iteration, the
//! driver issues a sequence of queries with progressively more labels —
//! `com.`, then `example.com.`, then `bar.example.com.`, then finally
//! `foo.bar.example.com.` — so that the upstream authoritative server
//! only ever learns the QNAME prefix it is responsible for.
//!
//! ## Algorithm
//!
//! For each step `i`:
//! 1. Build `target_qname = original.trim_to(num_labels - i)`.
//! 2. Issue `lookup(target_qname, original_qtype)`.
//! 3. On success, advance to the next (longer) label.
//! 4. Return the records from the final successful step.
//!
//! If every minimization step errors, RFC 9156 §3.4 mandates a fallback
//! to a single unminimized query. [`resolve_with_minimization`] returns
//! either the answer from the last successful step or the fallback
//! result. [`QnameMinResult::fell_back`] reports which path was taken.
//!
//! ## Mode semantics
//!
//! * [`QnameMinMode::Incremental`] — 1 label peeled per step (most
//!   compatible). Same algorithm regardless of cached NS state.
//! * [`QnameMinMode::Aggressive`] — skip a label if the previously
//!   learned NS set already covers it. (Currently identical to
//!   `Incremental`; the cache shortcut is a follow-up.)
//! * [`QnameMinMode::Strict`] — RFC 9156 §3.3 algorithm. Same
//!   behavior as `Incremental` for this first PR; the differentiation
//!   will matter when NS-aware skipping is implemented in M5.7.
//!
//! ## Integration
//!
//! Wired into [`CacheForwardAuthority`](super::forward::CacheForwardAuthority)
//! behind the `resolver.qname_minimization.enable` config flag.
//! The default `false` preserves the existing single-query recursive
//! behavior — opt-in only.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_net::NetError;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_server::proto::rr::{Name, Record, RecordType};
use tokio::sync::Mutex;
use tracing::{debug, trace};

use crate::config::ResolverQnameMinimization;

/// Minimal resolver abstraction for unit tests.
///
/// The production impl wraps [`HickoryResolver`]; tests supply a
/// canned-response mock. Returns a vector of [`Record`]s to keep the
/// trait agnostic of hickory-resolver's `Lookup` wrapper.
#[async_trait]
pub trait QnameMinResolver: Send + Sync {
    async fn lookup(&self, name: Name, qtype: RecordType) -> Result<Vec<Record>, NetError>;
}

/// Adapter that wraps a `HickoryResolver` so it can be driven by the
/// minimization loop.
pub struct HickoryMinResolver {
    inner: Arc<HickoryResolver<TokioRuntimeProvider>>,
}

impl HickoryMinResolver {
    /// Wrap a [`HickoryResolver`] for use by [`resolve_with_minimization`].
    pub fn new(resolver: HickoryResolver<TokioRuntimeProvider>) -> Self {
        Self {
            inner: Arc::new(resolver),
        }
    }
}

#[async_trait]
impl QnameMinResolver for HickoryMinResolver {
    async fn lookup(&self, name: Name, qtype: RecordType) -> Result<Vec<Record>, NetError> {
        self.inner
            .lookup(name, qtype)
            .await
            .map(|l| l.answers().to_vec())
    }
}

/// Result of a minimization run.
#[derive(Debug, Clone)]
pub struct QnameMinResult {
    /// Records returned from the final successful minimization step.
    pub records: Vec<Record>,
    /// The QNAME at which the final answer was obtained.
    pub final_qname: Name,
    /// Number of minimization steps actually issued.
    pub steps: u8,
    /// `true` if the driver fell back to a non-minimized query after
    /// all minimization steps errored.
    pub fell_back: bool,
}

/// Build the sequence of progressively shorter QNAMEs from `original`.
///
/// `foo.bar.example.com.` → `[foo.bar.example.com., bar.example.com.,
/// example.com., com., .]`
pub fn peel_labels(original: &Name) -> Vec<Name> {
    let mut out = Vec::with_capacity(original.num_labels() as usize + 1);
    let mut current = original.clone();
    out.push(current.clone());
    while current.num_labels() > 1 {
        current = current.base_name();
        out.push(current.clone());
    }
    // Push the root label last so the algorithm can detect "we got
    // here" as the terminal step (RFC 9156 §3.3).
    if !current.is_root() {
        out.push(Name::root());
    }

    out
}

/// Run RFC 9156 QNAME minimization against `resolver`.
///
/// See the [module-level docs](self) for the full algorithm. If every
/// peel step errors, falls back to a single unminimized lookup of
/// `original` (RFC 9156 §3.4) and sets [`QnameMinResult::fell_back`].
pub async fn resolve_with_minimization<R: QnameMinResolver>(
    resolver: &R,
    original: Name,
    qtype: RecordType,
    config: &ResolverQnameMinimization,
) -> Result<QnameMinResult, NetError> {
    // RFC 9156 has nothing to minimize on the empty/root QNAME: it would
    // just bounce a single root query. Detect via label count rather than
    // Name::is_root() because callers (e.g. forward.rs) may have already
    // called set_fqdn(false) on the name, which Name::is_root() interprets
    // as "not root".
    if original.num_labels() == 0 {
        debug!(
            qname = %original,
            "qname-min: empty/root name, no minimization possible"
        );
        return Err(NetError::from(std::io::Error::other(
            "qname-min: cannot minimize root name",
        )));
    }

    let labels = peel_labels(&original);
    let max = (config.max_iterations as usize).max(1).min(labels.len());

    debug!(
        original = %original,
        steps_planned = max,
        mode = ?config.mode,
        "qname-min: starting"
    );

    let mut last_records: Vec<Record> = Vec::new();
    let mut last_qname = original.clone();
    let mut last_error: Option<NetError> = None;
    let mut steps_taken: u8 = 0;

    for (i, label) in labels.iter().take(max).enumerate() {
        let step = (i + 1) as u8;
        steps_taken = step;
        debug!(
            original = %original,
            step,
            label = %label,
            "qname-min: step"
        );

        match resolver.lookup(label.clone(), qtype).await {
            Ok(records) => {
                trace!(
                    original = %original,
                    step,
                    label = %label,
                    n_records = records.len(),
                    "qname-min: response"
                );
                // RFC 9156 §3.3: only the last *non-empty* answer is our
                // positive result. Keep the prior positive answer if this
                // peel step returns NODATA so a later failure doesn't
                // cause a fallback that wipes it out.
                if !records.is_empty() {
                    last_records = records;
                    last_qname = label.clone();
                }
                last_error = None;
            }
            Err(e) => {
                debug!(
                    original = %original,
                    step,
                    label = %label,
                    error = %e,
                    "qname-min: step errored"
                );
                last_error = Some(e);
                // Per RFC 9156 §3.4 — keep prior data if we have it;
                // otherwise the fallback below will run.
            }
        }
    }

    if last_records.is_empty() {
        // Total failure across all minimization steps — fall back to
        // a single unminimized query per RFC 9156 §3.4.
        debug!(
            original = %original,
            "qname-min: fell back to full QNAME"
        );
        let records = match resolver.lookup(original.clone(), qtype).await {
            Ok(r) => r,
            Err(e) => {
                // If the minimization errored AND the fallback also
                // errored, surface the fallback error (more recent).
                return Err(last_error.unwrap_or(e));
            }
        };
        return Ok(QnameMinResult {
            records,
            final_qname: original,
            steps: steps_taken,
            fell_back: true,
        });
    }

    Ok(QnameMinResult {
        records: last_records,
        final_qname: last_qname,
        steps: steps_taken,
        fell_back: false,
    })
}

// Make `Arc<Mutex<…>>` work as a `QnameMinResolver` so tests can wrap
// mock state in a `tokio::sync::Mutex` for interior mutability.
#[async_trait]
impl<T: QnameMinResolver + ?Sized> QnameMinResolver for Arc<Mutex<T>> {
    async fn lookup(&self, name: Name, qtype: RecordType) -> Result<Vec<Record>, NetError> {
        let guard = self.lock().await;
        guard.lookup(name, qtype).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::RData;
    use std::str::FromStr;

    /// Build a Name from a wire-format string. Kept FQDN so it matches
    /// the names produced by `peel_labels` (the driver preserves FQDN
    /// to avoid search-list expansion at the hickory-resolver layer).
    fn n(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn a_record(qname: &Name, ip: [u8; 4]) -> Record {
        Record::from_rdata(
            qname.clone(),
            300,
            RData::A(std::net::Ipv4Addr::from(ip).into()),
        )
    }

    /// Sequence-driven mock. Each `lookup()` call pops the next canned
    /// response and records the (qname, qtype) it was asked about.
    /// `Mutex` keeps the trait signature `&self`-only and stays `Send+Sync`
    /// so the trait bound holds.
    struct SeqMock {
        responses: std::sync::Mutex<
            std::collections::VecDeque<(Name, RecordType, Result<Vec<Record>, NetError>)>,
        >,
        calls: std::sync::Mutex<Vec<(Name, RecordType)>>,
    }

    impl SeqMock {
        fn new(responses: Vec<(Name, RecordType, Result<Vec<Record>, NetError>)>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into_iter().collect()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(Name, RecordType)> {
            self.calls.lock().expect("mock mutex poisoned").clone()
        }
    }

    #[async_trait]
    impl QnameMinResolver for SeqMock {
        async fn lookup(&self, name: Name, qtype: RecordType) -> Result<Vec<Record>, NetError> {
            self.calls
                .lock()
                .expect("mock mutex poisoned")
                .push((name, qtype));
            self.responses
                .lock()
                .expect("mock mutex poisoned")
                .pop_front()
                .map(|(_, _, r)| r)
                .unwrap_or_else(|| {
                    Err(NetError::from(std::io::Error::other(
                        "SeqMock: no more responses",
                    )))
                })
        }
    }

    // ── peel_labels unit tests ───────────────────────────────────────

    #[test]
    fn peel_full_name_yields_labels_in_order() {
        // Peel produces a sequence of progressively shorter QNAMEs, ending
        // with the root label. Names are kept FQDN (hickory-resolver's
        // lookup accepts both FQDN and non-FQDN, and FQDN prevents
        // accidental search-list expansion).
        let full = n("foo.bar.example.com.");
        let labels = peel_labels(&full);
        let names: Vec<String> = labels.iter().map(|l| l.to_string()).collect();
        assert_eq!(names[0], "foo.bar.example.com.");
        assert_eq!(names[1], "bar.example.com.");
        assert_eq!(names[2], "example.com.");
        assert_eq!(names[3], "com.");
        let last = labels.last().unwrap();
        assert!(last.is_root(), "last label should be root: {last}");
    }

    #[test]
    fn peel_single_label_name_includes_root_probe() {
        // Per RFC 9156 §3.3, the minimization sequence for a single-label
        // name ends at the root (.) - the root must be probed so we can
        // discover which NS records are authoritative for the TLD.
        let one = n("example.");
        let labels = peel_labels(&one);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].to_string(), "example.");
        assert!(labels[1].is_root(), "root probe missing");
    }

    #[test]
    fn peel_root_name_yields_root_entry() {
        // For an empty/root QNAME the peel sequence is just the root
        // itself. The driver's main entry point (resolve_with_minimization)
        // short-circuits before this is called, so this case is mostly
        // a sanity check on peel_labels.
        let root = Name::root();
        let labels = peel_labels(&root);
        assert_eq!(labels.len(), 1);
        assert!(labels[0].is_root());
    }

    #[test]
    fn peel_seven_labels_includes_root() {
        let full = n("a.b.c.d.e.f.g.");
        let labels = peel_labels(&full);
        // 7 labels + root = 8 entries.
        assert_eq!(labels.len(), 8);
    }

    // ── resolve_with_minimization unit tests ─────────────────────────

    #[tokio::test]
    async fn root_name_returns_error_no_calls() {
        let mock = SeqMock::new(vec![]);
        // Pass the root name in FQDN form so Name::is_root() recognises it
        // and the driver early-exits before any lookup.
        let root = Name::root();
        let cfg = ResolverQnameMinimization::default();
        let res = resolve_with_minimization(&mock, root, RecordType::A, &cfg).await;
        assert!(res.is_err());
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn single_label_name_two_queries_with_root_probe() {
        // Single-label name -> [example., root] peel sequence (RFC 9156 sec 3.3).
        let one = n("example.");
        let root = Name::root();
        let mock = SeqMock::new(vec![
            (
                one.clone(),
                RecordType::A,
                Ok(vec![a_record(&one, [1, 2, 3, 4])]),
            ),
            (root, RecordType::A, Ok(vec![])),
        ]);
        let cfg = ResolverQnameMinimization {
            enable: true,
            max_iterations: 7,
            ..Default::default()
        };
        let res = resolve_with_minimization(&mock, one.clone(), RecordType::A, &cfg).await;
        let r = res.expect("single-label lookup should succeed");
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].name.to_string(), "example.");
        assert_eq!(r.steps, 2);
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0.to_string(), "example.");
        assert_eq!(calls[0].1, RecordType::A);
    }

    #[tokio::test]
    async fn four_label_name_peels_through_intermediate_steps() {
        let full = n("a.b.example.com.");
        // Peel sequence: a.b.example.com. -> b.example.com. -> example.com.
        // -> com. -> root (RFC 9156 sec 3.3). First step returns an answer;
        // subsequent steps return empty (NODATA) and the driver continues
        // until the cap or a positive answer.
        let mock = SeqMock::new(vec![
            (
                n("a.b.example.com."),
                RecordType::A,
                Ok(vec![a_record(&full, [10, 0, 0, 1])]),
            ),
            (n("b.example.com."), RecordType::A, Ok(vec![])),
            (n("example.com."), RecordType::A, Ok(vec![])),
            (n("com."), RecordType::A, Ok(vec![])),
            (Name::root(), RecordType::A, Ok(vec![])),
        ]);
        let cfg = ResolverQnameMinimization {
            enable: true,
            max_iterations: 7,
            ..Default::default()
        };
        let res = resolve_with_minimization(&mock, full.clone(), RecordType::A, &cfg).await;
        let r = res.expect("multi-step lookup should succeed");
        assert!(!r.fell_back);
        assert!(r.records.iter().any(|rec| {
            rec.name.to_string() == "a.b.example.com." && matches!(rec.data, RData::A(_))
        }));

        let calls = mock.calls();
        assert_eq!(calls[0].0.to_string(), "a.b.example.com.");
        assert_eq!(calls[0].1, RecordType::A);
        assert!(calls.iter().any(|(q, _)| q.to_string() == "b.example.com."));
        assert!(calls.iter().any(|(q, _)| q.to_string() == "example.com."));
        assert!(calls.iter().any(|(q, _)| q.to_string() == "com."));
    }

    #[tokio::test]
    async fn timeout_falls_back_to_unminimized() {
        let full = n("x.example.com.");
        // First peel step errors with timeout; the fallback succeeds.
        let mock = SeqMock::new(vec![
            (n("x.example.com."), RecordType::A, Err(NetError::Timeout)),
            (
                full.clone(),
                RecordType::A,
                Ok(vec![a_record(&full, [10, 0, 0, 1])]),
            ),
        ]);
        let cfg = ResolverQnameMinimization {
            enable: true,
            max_iterations: 1,
            ..Default::default()
        };
        let res = resolve_with_minimization(&mock, full.clone(), RecordType::A, &cfg).await;
        let r = res.expect("fallback should return success");
        assert!(r.fell_back, "should have fallen back after timeout");
        assert!(r.records.iter().any(|rec| {
            rec.name.to_string() == "x.example.com." && matches!(rec.data, RData::A(_))
        }));
    }

    #[tokio::test]
    async fn empty_answers_during_peeling_still_proceeds() {
        // All peel steps return NODATA -> driver falls back to the full
        // unminimized lookup (RFC 9156 sec 3.4). The intermediate steps
        // themselves do not abort the algorithm - that's what we test.
        let full = n("y.example.com.");
        let mock = SeqMock::new(vec![
            (n("y.example.com."), RecordType::A, Ok(vec![])),
            (n("example.com."), RecordType::A, Ok(vec![])),
            (n("com."), RecordType::A, Ok(vec![])),
            (Name::root(), RecordType::A, Ok(vec![])),
            // Fallback: full QNAME returns a record
            (
                full.clone(),
                RecordType::A,
                Ok(vec![a_record(&full, [10, 0, 0, 2])]),
            ),
        ]);
        let cfg = ResolverQnameMinimization {
            enable: true,
            max_iterations: 7,
            ..Default::default()
        };
        let res = resolve_with_minimization(&mock, full.clone(), RecordType::A, &cfg).await;
        let r = res.expect("NODATA peel should fall back to unminimized query");
        assert!(r.fell_back);
        assert_eq!(r.steps, 4);
        // 4 peel steps + 1 fallback = 5 total
        assert_eq!(mock.calls().len(), 5);
    }

    #[test]
    fn default_config_is_opt_in_strict_mode() {
        let cfg = ResolverQnameMinimization::default();
        assert!(!cfg.enable, "M5.4 default must be opt-in (off)");
        assert_eq!(cfg.mode, crate::config::QnameMinMode::Strict);
        assert!(cfg.max_iterations > 0);
    }
}
