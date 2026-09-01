# Heimdallr M5 — Advanced Records & Resolver Behaviors

**Milestone:** M5 — Advanced Records & Behaviors
**Status:** Planned (M0–M4 complete, tagged `v0.4.0a`)
**Author:** Architect pass, 2026-09-01
**Branch target:** `main` (working tree clean at start of M5)

This document specifies the design for M5 — the seventh milestone in the Heimdallr
roadmap. M5 extends the zone data model with **SVCB/HTTPS/SSHFP/DNAME/ANAME**
records and the resolver with **QNAME minimization, DNS64, ECS, and CNAME
cloaking** — all strictly under the existing architectural rules
(`core` is pure, `net` only frames, `api` only exposes state).

---

## 1. Overview

### Goals

1. **Modern service-discovery records.** Implement first-class support for
   RFC 9460/9461/9462 (SVCB + HTTPS) so that Heimdallr can publish and serve
   service-binding hints the same way Cloudflare/Google/Apple do today.
2. **Cryptographic key publication.** Add SSHFP (RFC 4255) so administrators
   can publish SSH host key fingerprints in-band and have Heimdallr sign them.
3. **Name redirection.** Add DNAME (RFC 6676) for whole-subtree redirection
   and ANAME ("apex CNAME flattening") for ALIAS-at-apex semantics, both for
   primary zones and forward responses.
4. **Privacy-preserving resolution.** Implement QNAME minimization (RFC 9156)
   in the recursive path, and add CNAME cloaking enforcement so internal
   tracking subdomains (`_dnsquery.*`, `_metrics.*`, etc.) cannot be exfiltrated
   by malicious authoritative answers.
5. **NAT64 / IPv6 transition.** Add DNS64 (RFC 6147) so IPv6-only resolvers
   can reach IPv4-only origins via a synthesized AAAA.
6. **Authoritative-aware caching.** Add EDNS Client Subnet (RFC 7871) so
   upstream CDNs can return scope-correct answers, with cache partitioning
   keyed by `(qname, qtype, client-subnet)`.

### Non-goals

- **No new transports.** M4 closed the transport story (DoT/DoH/DoQ). M5
  uses them but does not add RR/QUIC/HTTP/3.
- **No custom rdata for SVCB/HTTPS.** `hickory-proto` 0.26.1 already ships
  `Svcb<Rdata>` / `Https<Rdata>` and full SvcParam parsing — we will *not*
  roll our own.
- **No DANE TLSA expansion.** M3 covers DANE; M5 only adds the SSHFP analog.
- **No policy / Apps integration.** M6 owns DnsApp & blocklists; M5 just
  surfaces CNAME-chain limits that M6 will later consume.

### Success criteria

| # | Gate |
|---|------|
| 1 | `cargo check && cargo build --release` — clean compile, no new lints |
| 2 | `cargo test` — all existing 41+ tests pass; new unit tests per sub-task |
| 3 | `tests/m5-records-validate.sh` — zone file with SVCB/HTTPS/SSHFP/DNAME/ANAME loads, signed by DNSSEC, validated by `delv` |
| 4 | `tests/m5-resolver-validate.sh` — query for an SVCB name returns the in-zone record (authoritative path) and a Cloudflare HTTPS record (recursive path); `dig +short HTTPS cloudflare.com` matches |
| 5 | `tests/m5-qmin-validate.sh` — enable `qname_minimization=true`, capture upstream traffic, assert query count per QNAME ≤ 3 labels per RFC 9156 |
| 6 | `tests/m5-dns64-validate.sh` — synthesize AAAA from A with `dns64_prefix=64:ff9b::/96`, verify response |
| 7 | `tests/m5-ecs-validate.sh` — send query with ECS option, verify scope-zeroing on egress to authority, scope-aware cache key |
| 8 | `tests/m5-cname-cloak-validate.sh` — chain of 9 CNAMEs → SERVFAIL (cloaking limit 8) |

Tag `v0.5.0-alpha` when all 8 gates pass.

---

## 2. Sub-milestone breakdown

| ID | Name | RFCs | File targets | Size | Depends on | Order |
|---|---|---|---|---|---|---|
| **M5.1** | SVCB / HTTPS | 9460 / 9461 / 9462 | `src/core/zone/record.rs`, `src/core/zone/file.rs` | **M** | — | 2 |
| **M5.2** | SSHFP | 4255 | `src/core/zone/record.rs` | **S** | — | 3 (parallel with M5.1) |
| **M5.3** | DNAME / ANAME | 6676 (DNAME); draft-ietf-dnsop-aname (ANAME) | `src/core/resolver/forward.rs`, `src/core/zone/record.rs` | **M** | — | 4 |
| **M5.4** | QNAME minimization | 9156 | `src/core/resolver/forward.rs`, `src/core/rec/mod.rs` | **M** | — | 1 (foundational) |
| **M5.5** | CNAME cloaking | vendor-specific (RFC 1035 §8 glue-aware limits) | `src/core/filter/mod.rs`, `src/core/resolver/forward.rs` | **S** | — | 5 (parallel with M5.3) |
| **M5.6** | DNS64 | 6147 | `src/core/resolver/dns64.rs` (new) | **L** | M5.4 | 7 |
| **M5.7** | ECS | 7871 | `src/core/cache/mod.rs`, `src/core/resolver/forward.rs` | **M** | — | 6 |

### Refinement vs proposed split

The proposed split is solid; two refinements:

- **M5.4 (QNAME minimization) is reordered to land first.** It's a passive
  behavior change that touches only the upstream forwarder in
  [`forward.rs`](src/core/resolver/forward.rs:258) and creates the
  hooks (label-by-label query iterator) that M5.6 (DNS64) reuses for
  A→AAAA synthesis. Landing it first unblocks DNS64 cleanly.
- **M5.7 (ECS) is moved before M5.6** because the cache partitioning logic
  it adds (subnet-aware [`CacheKey`](src/core/cache/mod.rs:14)) is a
  structural prerequisite if M5.6 (DNS64) is to record its synthesized
  AAAA in cache (so a second client with the same scope reuses it).

### Complexity rationale

- **S (SSHFP, CNAME cloaking):** Single 4-line wire format, similar to TLSA.
- **M (SVCB/HTTPS, DNAME, QNAME minimization, ECS):** Real parser/rdata
  complexity or RFC 9156 iterative state machine, but mostly contained.
- **L (DNS64):** Requires a new module, two-pass synthesis, glue handling,
  negative caching, integration with QNAME minimization hooks, and ECS
  scope awareness.

---

## 3. Per-sub-task design sketches

### M5.1 — SVCB / HTTPS (RFC 9460/9461/9462)

- **Wire format / data model.** `hickory_server::proto::rr::rdata::Svcb<R>`
  and `Https<R>` are already exported in 0.26.1. SVCB type code = 64,
  HTTPS = 65. Both wrap a `SvcParams<Key>` with presentation-format
  text keys (`alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech`, `mandatory`,
  `no-default-alpn`, etc.). We use `Svcb<Uninterpreted>` round-tripping
  when we cannot interpret a key, and `Svcb<Https>` is a typed alias
  (`Svcb<https=true>`).
- **Storage location.** Persist in zone files as presentation format
  (already supported by hickory's zone parser via `FileZoneHandler`).
  In-memory: existing `Record<RData>` machinery. Add SVCB/HTTPS arms to
  [`parse_rdata()`](src/core/zone/record.rs:269) so the API
  `/api/zones/{name}/records` can CRUD them.
- **Handler/resolver integration points.** No special handler — hickory's
  `FileZoneHandler` already serves them. For recursive resolution, the
  upstream `HickoryResolver` already understands SVCB; we only need to
  *cache* responses (already handled — see
  [`forward.rs`](src/core/resolver/forward.rs:178)).
- **Test strategy.** Unit tests in
  [`record.rs`](src/core/zone/record.rs:449) for `parse_svcb_data()`:
  - happy path: `_dns.example.test. 3600 IN HTTPS 1 . alpn="h2,h3" ipv4hint=192.0.2.1`
  - ServiceMode=Alias vs ServiceMode=ServiceEndpoints
  - mandatory=alpn round-trip
  - reject: missing `alpn` when `no-default-alpn` set (RFC 9460 §7.1)
  Integration shell: `tests/m5-records-validate.sh` — load zone with
  SVCB+HTTPS, `delv` validate, `kdig +short HTTPS cloudflare.com`
  recursive match.
- **Edge cases / known pitfalls.**
  - "ech" param is opaque base64; don't try to decode, pass through.
  - SvcParamKey values ≥ 0x8000 are private — accept, don't error.
  - HTTPS RR is SVCB in disguise — same parser, different rdata enum.
  - AliasForm (`SvcPriority=0`) MUST have `TargetName`, no SvcParams.
- **Reference RFC sections to read first.** RFC 9460 §2 (SVCB), §7
  (SvcParams), §9 (Aliases); RFC 9461 (SVCB alias chain); RFC 9462
  (HTTPS RR).

### M5.2 — SSHFP (RFC 4255)

- **Wire format / data model.**
  `hickory_server::proto::rr::rdata::sshfp::SSHFP` (Algorithm, Type, Fingerprint).
  Algorithms: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519, 6=Ed448. Types: 1=SHA-1, 2=SHA-256.
- **Storage location.** Zone files (hickory's parser supports it
  natively); in-memory same `Record<RData>` machinery. Add to
  `parse_record_type()` and `parse_rdata()` in
  [`record.rs`](src/core/zone/record.rs:237).
- **Handler/resolver integration points.** None — purely a zone-record
  type. Recursive resolvers do not interpret SSHFP; they just forward.
- **Test strategy.** Unit: parse `host.example.test. 3600 IN SSHFP 2 1 abc123...`
  with SHA-1 20 bytes; reject SHA-256 wrong length; reject unknown
  algorithm (allow 1/2/3/4/6). Integration shell: signed zone with
  SSHFP; `delv` validates; `ssh-keyscan -D` test client happy.
- **Edge cases / known pitfalls.**
  - Fingerprint length must match `Type`: SHA-1=20, SHA-256=32.
  - Algorithm numbers in RFC 6594/Emerging: only warn, don't reject.
  - DNSSEC-signed SSHFP is the whole point — must sign in M5.2 path.
- **Reference RFC sections.** RFC 4255 §2 (RDATA), §3 (presentation),
  §4 (DNSSEC interaction).

### M5.3 — DNAME / ANAME (RFC 6676 + draft-aname)

- **Wire format / data model.** DNAME: existing `hickory_server::proto::rr::rdata::DNAME(Name)`.
  ANAME is *not* a distinct RRtype — it's an aliasing *behavior* over
  CNAME-equivalent records. Implement as a synthetic logic on top of
  zone file parser: treat `ANAME` keyword (presentation format) as
  CNAME at apex with auto-flatten.
- **Storage location.** DNAME: same path as CNAME — zone file parser
  handles. Add to `parse_record_type()` / `parse_rdata()`. ANAME: a
  presentation-form only construct; convert at parse time in
  [`file.rs`](src/core/zone/file.rs:40) by rewriting to CNAME rdata
  with marker comment, then synthesize the A/AAAA target at lookup
  time from the `ANAME` table.
- **Handler/resolver integration points.** For recursive DNAME, add a
  resolution rule in [`forward.rs`](src/core/resolver/forward.rs:178):
  when upstream returns DNAME in answer, synthesize CNAME records in
  the response (RFC 6676 §2.2 replacement logic) before caching. ANAME:
  in `CacheForwardAuthority::lookup`, after the upstream `A`/`AAAA`
  lookup for an apex CNAME target, prepend a synthetic CNAME to the
  response.
- **Test strategy.** Unit: parse DNAME `a.b.example.test. 3600 IN DNAME c.d.example.test.`;
  verify CNAME substitution math. Integration shell:
  - Query `foo.example.test` which has `bar.foo.example.test. IN DNAME bar.example.test.`
  - Expect `foo.example.test. 3600 IN DNAME bar.foo.example.test.` AND
    `bar.foo.example.test. 3600 IN CNAME bar.example.test.` (substitution)
  - ANAME: query apex, expect synthesized CNAME → upstream A
- **Edge cases / known pitfalls.**
  - DNAME cannot coexist with CNAME at the same name (RFC 6676 §2.2).
  - DNSSEC NSEC/NSEC3 must cover *both* DNAME and synthesized CNAME.
  - ANAME flattening must respect TTL of the underlying A/AAAA.
  - Loop detection: don't synthesize a CNAME whose target is the
    original apex (would loop).
- **Reference RFC sections.** RFC 6676 §2 (DNAME semantics), §3 (DNSSEC).
  draft-ietf-dnsop-aname-04 §3.

### M5.4 — QNAME minimization (RFC 9156)

- **Wire format / data model.** No new rdata. Modify the forward path to
  issue *multiple* lookups (one per RFC 9156 step) instead of a single
  full-QNAME query. State: `QminState { current: Name, next_label: usize, max_steps: u8 }`.
- **Storage location.** New sub-module `src/core/resolver/qmin.rs`
  implementing a coroutine-like driver. Driver state held in
  `CacheForwardAuthority` per request; *not* persistent.
- **Handler/resolver integration points.** In
  [`forward.rs`](src/core/resolver/forward.rs:178), before issuing the
  upstream lookup, call `qmin::plan_queries(name)` which yields
  `[Name, Name.parent().parent, ..., Name]`. Cache each non-terminal
  intermediate response (NS referral) separately in
  [`SharedCache`](src/core/cache/mod.rs:223) under a
  `CacheKey { qname, qtype: NS }` pseudo-type.
- **Test strategy.** Unit: synthesize an upstream sequence in a mock
  Resolver (using the `testing` feature already enabled in
  [`Cargo.toml`](Cargo.toml:19)); verify Heimdallr issues
  `com. NS`, then `example.com. NS`, then `www.example.com. A` (3
  queries, not 1). Integration: capture UDP packets with tcpdump to
  the upstream, count distinct QNAMEs.
- **Edge cases / known pitfalls.**
  - RFC 9156 §3 "skipping" rules: when referral is missing glue, skip
    one label up.
  - QNAME minimization interacts badly with DNAME chains — disable
    QNAME minimization when DNAME is involved (RFC 9156 §2.2 last
    paragraph).
  - Negative cache TTLs: NXDOMAIN at level 2 does not mean NXDOMAIN
    at level 3 (RFC 9156 §3.3).
- **Reference RFC sections.** RFC 9156 §2 (algorithm), §3 (behavioral
  rules). See also RFC 7816 (historical predecessor) for context.

### M5.5 — CNAME cloaking (vendor-specific)

- **Wire format / data model.** No new rdata. Just a counter and a
  limit. `Filter::cname_chain_limit: u8 = 8` in
  [`filter/mod.rs`](src/core/filter/mod.rs:1).
- **Storage location.** In-memory only. State held in the
  `CacheForwardAuthority` lookup call stack.
- **Handler/resolver integration points.** In
  [`forward.rs`](src/core/resolver/forward.rs:178), after upstream
  returns, count CNAME records in the answer+additional sections.
  If `count > filter.cname_chain_limit` → return SERVFAIL with EDE 37
  (DNSSEC Bogus — closest existing code; future M6 may reserve a
  private EDE). Also enforced during DNSSEC chain synthesis to
  prevent NSEC3 walking past the limit.
- **Test strategy.** Unit: build a synthetic message with 9 CNAMEs in
  chain, assert SERVFAIL returned. Integration shell: query a
  test-zone with 9-level CNAME; expect SERVFAIL with EDE.
- **Edge cases / known pitfalls.**
  - DNSSEC-signed chains have a hard limit of 7 (RFC 5155) — Heimdallr's
    limit of 8 is consistent and safe.
  - The chain limit must apply to *forward* (query→answer) chains,
    not to chains followed *during* recursion (those are unbounded
    in hickory-resolver).
  - Logs MUST record both `qname` and the limit that triggered, for
    operational debugging.
- **Reference RFC sections.** Not in an RFC — most public resolvers
  (Google 8.8.8.8, Cloudflare 1.1.1.1) implement this as a chain limit
  of 16-32; we use 8 to match RFC 5155 conservative bound.

### M5.6 — DNS64 (RFC 6147)

- **Wire format / data model.** No new rdata. Synthesis rule:
  given A response `A 192.0.2.1` and prefix `64:ff9b::/96`,
  synthesize `AAAA 64:ff9b::192.0.2.1`. Implementation lives in a new
  module `src/core/resolver/dns64.rs`.
- **Storage location.** No persistent storage; the synthesizer is
  invoked at lookup-time inside
  [`forward.rs`](src/core/resolver/forward.rs:178) for matching
  queries, and the synthesized AAAA is recorded in
  [`SharedCache`](src/core/cache/mod.rs:223) keyed by
  `(qname, AAAA, client-subnet)`.
- **Handler/resolver integration points.** New module
  `dns64::synthesize(prefix, a_records) -> Vec<AAAA>`. Called in
  `CacheForwardAuthority::lookup` when:
  1. query is AAAA,
  2. upstream returns NOERROR with empty answer,
  3. upstream then returns NOERROR with A records (chained query),
  4. `config.dns64_prefix` is configured.
  Reuses M5.4 hooks for the chained A query (so A→AAAA falls out
  cleanly from the QNAME minimization driver).
- **Test strategy.** Unit: synthesize from
  `A [192.0.2.1] + prefix 64:ff9b::/96` →
  `AAAA [64:ff9b::192.0.2.1]`. Test multiple A records. Test
  `::ffff:0:0` IPv4-mapped representation. Integration shell:
  - `kdig @127.0.0.1 AAAA ipv4only.example.test` (with DNS64 prefix set)
  - Expect synthesized AAAA matching `64:ff9b::<real A>`.
- **Edge cases / known pitfalls.**
  - RFC 6147 §3: MUST NOT synthesize if upstream returns NOERROR+empty
    answer *and* authority NS records indicate the zone is DNSSEC-signed
    — Heimdallr's validator enforces this.
  - Negative synthesis: if the A lookup returns NXDOMAIN, the synthesized
    AAAA must also be NXDOMAIN (cached for the same TTL).
  - TTL of synthesized AAAA MUST be the minimum of the A records'
    TTLs (RFC 6147 §4.1).
- **Reference RFC sections.** RFC 6147 §3 (RFC 6052), §4 (synthesis
  rules); RFC 6052 (IPv6 prefix translation).

### M5.7 — ECS (RFC 7871)

- **Wire format / data model.**
  `hickory_server::proto::rr::rdata::edns::EdnsOption::Subnet(EdnsClientSubnet)`
  is already supported in 0.26.1. Use the existing
  `EdnsClientSubnet { address, source_prefix, scope_prefix }`.
- **Storage location.** Persistent cache key change:
  [`CacheKey`](src/core/cache/mod.rs:14) gains an optional
  `client_subnet: Option<(IpAddr, u8)>` discriminator. Old entries
  remain valid; new entries get subnet-aware keying.
- **Handler/resolver integration points.** In
  [`forward.rs`](src/core/resolver/forward.rs:178):
  1. **Ingress**: extract ECS from request EDNS options; rewrite
     `source_prefix` to scope (RFC 7871 §7.1.2 — privacy: zero trailing
     bits).
  2. **Egress**: forward with the scoped ECS.
  3. **Response handling**: copy upstream ECS `scope_prefix` into
     cache key as the lookup discriminator; strip before returning
     to client.
- **Test strategy.** Unit: scope-zero an IPv4 `192.0.2.123/24` →
  `192.0.2.0/24`; scope-zero IPv6 `2001:db8::123/56` →
  `2001:db8::/56`. Test cache key equivalence:
  `192.0.2.123/24` and `192.0.2.5/24` hit the same cache slot, but
  `192.0.2.123/16` does not. Integration: send query with ECS,
  verify egress with scope-zeroed option; query without ECS, verify
  no ECS egress (default privacy mode).
- **Edge cases / known pitfalls.**
  - ECS + DNSSEC chain: DNSSEC proofs are computed against the
    un-scoped qname, so cache partitioning by ECS must NOT create
    divergent chain-of-trust (just partition answer section).
  - Family mismatch (client sends IPv4 ECS for IPv6-only zone): drop
    ECS silently.
  - Heavily affects cache hit rate — document this in README and
    keep `resolver.ecs` opt-in (already `default=false` in
    [`ResolverConfig`](src/config/mod.rs:78)).
- **Reference RFC sections.** RFC 7871 §4 (wire format), §7.1.2
  (privacy scope-zeroing), §7.1.3 (cache partitioning).

---

## 4. Cross-cutting concerns

### Config schema additions

New top-level key `[dns64]` (optional) and small additions to
`[resolver]` and `[cache]`. Existing
[`ResolverConfig`](src/config/mod.rs:67) already carries
`qname_minimization`, `qname_randomization`, and `ecs` — those are
already wired in TOML; M5 only needs to *consume* them.

```toml
# config.toml excerpt — M5 additions
[resolver]
forwarders = ["1.1.1.1:53"]
forward_protocol = "dot"
qname_minimization = true   # M5.4
qname_randomization = true  # existing
ecs = false                 # M5.7
concurrency = 2
timeout_ms = 2000

[cache]
size = 50000
serve_stale = true
prefetch = 2
persistent = "/var/lib/heimdallr/cache.bin"
# M5.7: max cache growth multiplier when ECS partitions cache; 4 means
# cache can grow up to 4×size with ECS-on. Default 4.
ecs_partition_factor = 4

[dns64]
# RFC 6052/6147 prefix for IPv4→IPv6 synthesis. Empty/None = DNS64 off.
prefix = "64:ff9b::/96"
# When true, synthesize AAAA even if upstream returns a real AAAA
# (for testing). Default false.
always_synthesize = false

[filter]
# M5.5 — CNAME chain limit. Default 8.
cname_chain_limit = 8
# existing fields preserved
blocklists = []
allowlists = []
cname_cloaking = true
rebinding = true
```

### API surface

`/api/zones/{name}/records` already routes through
[`record.rs`](src/core/zone/record.rs:99) for any record type — M5.1
(M5.2) only needs the parser/rdata arms added there to make SVCB,
HTTPS, SSHFP, DNAME, and ANAME creatable via API.

New endpoints (only needed for ECS control):

| Method | Path | Body | Purpose |
|--------|------|------|---------|
| GET | `/api/rec/options` | — | Read current QNAME-min/ECS/DNS64 state |
| PUT | `/api/rec/options` | `{qname_min, ecs, dns64_prefix}` | Toggle features at runtime (M9 will harden auth) |

No new `/api/zones/*` endpoints — existing record CRUD already
parameterizes on `record_type`.

### Metrics

`tracing` fields to add (JSON output for Prometheus scraping in M6):

| Field | Where | Meaning |
|-------|-------|---------|
| `svc.svcb_served` | `record.rs` insert/list counter | SVCB records served |
| `svc.https_served` | `record.rs` | HTTPS records served |
| `svc.sshfp_served` | `record.rs` | SSHFP records served |
| `rec.qmin_steps` | `forward.rs` | Histogram: 1, 2, 3, … labels per recursive query |
| `rec.qmin_disabled_dname` | `forward.rs` | Counter: queries where QNAME min was skipped due to DNAME |
| `rec.cname_chain_truncated` | `forward.rs` | Counter: chains cut at limit |
| `cache.ecs_partitions` | `cache.rs` | Gauge: distinct subnet cache buckets in use |
| `dns64.synthesized` | `dns64.rs` | Counter: AAAA records synthesized from A |
| `dns64.skipped_signed` | `dns64.rs` | Counter: synthesis skipped because zone is DNSSEC-signed |

### DNSSEC interaction

- **SVCB, HTTPS, SSHFP** — must be signed. `DnssecZoneHandler` already
  signs any record type in a signed zone, so no extra code needed.
  **Verify in tests:** `delv` validates signed SSHFP+HTTPS+SVCB RRsets.
- **DNAME** — RFC 6676 §3 mandates that the DNAME *and* the
  synthesized CNAME both fall under the same RRSIG. Heimdallr's signer
  re-signs the DNAME RRset, but DNAME+CNAME co-existence (chain
  synthesis) at response time is the resolver's job, not the signer's.
  **Note:** M5.3 DNAME synthesis in the recursive path does NOT need
  re-signing because the upstream response is already signed.
- **ANAME** — synthetic, never persisted, never signed. NSEC/NSEC3
  coverage of CNAME-apex-redirect is a known operator footgun;
  document in README.
- **ECS** — does *not* change the signed name. DNSKEY/DS chain is
  computed against the un-scoped qname. No signer changes needed.
- **DNS64** — synthesized AAAA MUST NOT be included in upstream
  responses (we synthesize only if upstream returned empty answer or
  we are authoritative with empty zone). For authoritative signed
  zones, refuse synthesis (RFC 6147 §3).
- **CNAME cloaking** — occurs *after* validation, so no DNSSEC
  interaction; just count and truncate.

### Compatibility — hickory-proto 0.26.1 type availability

| Type | In hickory 0.26.1? | Notes |
|------|---------------------|-------|
| `RecordType::SVCB` | ✅ Yes | Already used in [`record.rs`](src/core/zone/record.rs:250) |
| `RecordType::HTTPS` | ✅ Yes | Already used in [`record.rs`](src/core/zone/record.rs:249) |
| `Svcb<Rdata>` / `Https<Rdata>` | ✅ Yes | `proto::rr::rdata::svcb` module |
| `SvcParams<Key>` | ✅ Yes | Full SvcParamKey parsing incl. `alpn`, `port`, `ipv4hint`, `ipv6hint`, `ech`, `mandatory`, `no-default-alpn` |
| `RecordType::SSHFP` | ✅ Yes | `proto::rr::rdata::sshfp::SSHFP` |
| `RecordType::DNAME` | ✅ Yes | `proto::rr::rdata::DNAME` |
| `EdnsClientSubnet` | ✅ Yes | `proto::rr::edns::EdnsOption::Subnet(...)` |
| `CAA`, `TLSA`, `NSEC3` | ✅ Yes | Already used in M3 |

**Conclusion:** hickory 0.26.1 has every rdata type M5 needs. **No
custom rdata fallback required.** The risk in M5 is *presentation
format parsing*, not wire format — hickory's zone file parser already
accepts all of these in zone files.

---

## 5. Implementation order & PR strategy

### Recommended landing order (one PR per sub-task)

| PR | Sub-task | Justification |
|----|----------|---------------|
| **PR 1** | M5.4 QNAME minimization | Pure addition to forward path; touches only [`forward.rs`](src/core/resolver/forward.rs:178). Sets up hooks for M5.6 (DNS64) reuse. |
| **PR 2** | M5.1 SVCB/HTTPS | Adds rdata arms to [`record.rs`](src/core/zone/record.rs:269) — required before M5.2 can land because SSHFP CRUD uses the same parser plumbing. |
| **PR 3** | M5.2 SSHFP | Parallel to PR 2; uses already-landed parser infrastructure. Tiny PR. |
| **PR 4** | M5.5 CNAME cloaking | Independent of everything; only touches [`filter/mod.rs`](src/core/filter/mod.rs:1) + a 5-line check in [`forward.rs`](src/core/resolver/forward.rs:178). |
| **PR 5** | M5.3 DNAME/ANAME | Depends on M5.4 (QNAME-min-aware DNAME substitution) and M5.5 (chain-counting). Larger — do alone. |
| **PR 6** | M5.7 ECS | Cache partitioning is a *structural* change. Land *before* M5.6 so DNS64 inherits the subnet-aware cache key. |
| **PR 7** | M5.6 DNS64 | Largest sub-task, requires M5.4 (chained A→AAAA via qmin) and M5.7 (subnet-aware cache). Last. |

### Why this order

1. **M5.4 first** is foundational: it creates the iterative upstream
   query driver that M5.6 (DNS64's chained A→AAAA synthesis) reuses.
   M5.4 is also a passive feature (default `true` but easy to
   disable), so a buggy landing is recoverable.
2. **M5.1 before M5.2** because M5.1's parser plumbing
   (`parse_rdata` arms for SVCB/HTTPS) is structurally identical to
   what M5.2 needs for SSHFP. Landing M5.1 first means M5.2 is
   literally a copy-paste of the SSHFP helper.
3. **M5.5 (CNAME cloaking) early** because M5.3 (DNAME) and M5.6
   (DNS64) both *increase* the chain length they produce; the
   cloaking limit must already be in place to bound them.
4. **M5.7 (ECS) before M5.6 (DNS64)** because cache partitioning by
   subnet is a [`CacheKey`](src/core/cache/mod.rs:14) shape change.
   Once M5.7 lands, M5.6 just synthesizes and inserts; before
   M5.7, M5.6 would have to retroactively migrate every cache
   entry.

### Parallelization

- PRs 2 and 3 (SVCB/HTTPS, SSHFP) can be developed in parallel by
  separate engineers and merged in either order; they touch
  overlapping lines but not overlapping arms.
- PR 4 (CNAME cloaking) is fully parallel to PRs 2/3 — small, isolated.
- M5.4 should land alone (foundational), and M5.6 should land alone
  (final integration).

---

## 6. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|------------|--------|------------|
| **R1** | `hickory_server::proto::rr::rdata::svcb::Svcb::emit` may not preserve presentation order of SvcParams, breaking round-trip with our `persist_zone` writer. | M | M | Add a round-trip unit test that parses a complex SVCB and re-emits via `Display`, asserting set equality. If unstable, accept set-equality and document in `persist_zone` doc comment. |
| **R2** | DNAME synthesis creates NSEC3 holes that the existing NSEC3 signer doesn't cover. | M | H | Document the limitation; advise operators to use NSEC in zones with DNAME; add a `--check-zone` warning (M6). |
| **R3** | QNAME minimization causes SERVFAIL for zones that depend on full-QNAME behavior (e.g., wildcard catch-alls in authoritative NS responses). | M | M | Honor RFC 9156 §3.1: when an upstream NS referral doesn't cover the query, fall back to the full-QNAME query and disable QNAME min for that zone (cache the "qmin-incompatible" fact for that NS for 1h). |
| **R4** | DNS64 + DNSSEC: synthesizing AAAA in a signed zone violates the zone's NSEC3 chain. | H | H | Detect signed zones (presence of DNSKEY/NSEC3 at apex) and refuse synthesis in that branch. Match upstream authoritative for non-empty answer; only synthesize for recursive empty-answer case where upstream is unsigned. |
| **R5** | ECS with cache partitioning explodes cache memory (`O(snooped_subnets × answers)`). | M | M | Add `ecs_partition_factor` config (default 4× cache size); reject new partitions when full and log at WARN. M6 will add a Prometheus histogram. |
| **R6** | ANAME flattening changes the response qname but the cached TTL of the underlying A/AAAA may already be near expiry; flattening serves stale data past intended TTL. | L | L | Use `min(aname_ttl, a_ttl, aaaa_ttl)` as the response TTL. Document in code. |
| **R7** | hickory's `FileZoneHandler` rejects `HTTPS` records in some edge cases (e.g., presence in unsigned zone with NSEC3 expected). | L | M | Pre-flight test: load a zone file containing HTTPS+NSEC3 and `ldns-verify-zone` it. Document any uncovered combinations. |

---

## 7. Open questions

1. **QNAME minimization `max_steps` default.** RFC 9156 leaves the
   maximum label depth to the operator. Should the default be 4 (RFC
   9156 §2.2) or unlimited-up-to-NS-referral? *Need operator
   decision before PR 1 lands.*
2. **DNS64 prefix list.** Single prefix (`64:ff9b::/96` only) or
   multi-prefix (e.g., `64:ff9b::/96` for global + `::ffff:0:0/96`
   for local)? The latter requires ECS-style scope awareness. *Defer
   to M5.6 implementation; likely ship with single prefix first.*
3. **ANAME TTL semantics.** When ANAME flattens, what TTL do we use
   for the synthesized CNAME? Options: (a) the configured `aname_ttl`
   in the zone file, (b) `min(aname_ttl, a_ttl)`, (c) inherit
   directly from A. (b) is safest; (c) gives operators the least
   control. *Need operator input.*
4. **CNAME cloaking EDE code.** RFC 8914 does not define an EDE for
   "chain truncated". Use EDE 37 (DNSSEC Bogus) as a placeholder
   until IANA assigns one, or do not emit EDE at all? *Decide before
   PR 4.*
5. **API auth for runtime feature toggles.** `PUT /api/rec/options`
   should require auth (M7). Should we ship it authless behind a
   config flag `[api].allow_unsafe_rec_toggle` (off by default) for
   early M5 testing, then enforce in M7? *Yes, propose this.*

---

## Appendix A — Files touched by M5

```
src/
  core/
    cache/mod.rs           # +ECS partition field on CacheKey (M5.7)
    filter/mod.rs          # +cname_chain_limit, count check (M5.5)
    rec/mod.rs             # +RecOptions already exists; wire to config
    resolver/
      forward.rs           # M5.3 DNAME synthesis, M5.4 qmin driver,
                           # M5.5 cloak check, M5.7 ECS in/out, glue
      qmin.rs        NEW   # M5.4 QNAME minimization driver
      dns64.rs        NEW   # M5.6 AAAA synthesis
    zone/
      file.rs              # ANAME keyword handling (M5.3)
      record.rs            # +SVCB/HTTPS/SSHFP/DNAME in parse_rdata (M5.1/2/3)
  api/
    mod.rs                 # +/api/rec/options endpoints
  config/
    mod.rs                 # +[dns64], +cname_chain_limit, +ecs_partition_factor
tests/
  m5-records-validate.sh   NEW
  m5-resolver-validate.sh  NEW
  m5-qmin-validate.sh      NEW
  m5-dns64-validate.sh     NEW
  m5-ecs-validate.sh       NEW
  m5-cname-cloak-validate.sh NEW
config/
  zones/live/example.test.zone    # +SVCB/HTTPS/SSHFP/DNAME sample RRs
  zones/templates/forward.zone.template   # +ANAME keyword comment
```

## Appendix B — Backwards compatibility

- Existing `Cargo.lock` is unchanged; no new third-party deps.
- Default config additions are additive and preserve all current
  behavior (every new key has a sensible default).
- Existing zone files continue to load unchanged (no required rdata
  migration).
- API additions are pure additions; no removed endpoints.
- `hickory-proto` already provides every rdata type required.

— End of M5 design —
