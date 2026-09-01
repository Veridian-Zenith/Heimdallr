# M5 meta-tracking issue

> Meta-issue for milestone **M5 — Advanced Records & Resolver Behaviors**.
> Source of truth: [`plans/m5_design.md`](https://github.com/Veridian-Zenith/Heimdallr/blob/feat/m5/plans/m5_design.md).
> Branch: `feat/m5` · Target tag: `v0.5.0-alpha`.

## Status

<!-- Fill in PR numbers / issue links as they are opened. -->

| ID | Sub-task | Issue | PR | RFCs | Order | Status |
|----|----------|-------|----|------|-------|--------|
| M5.4 | QNAME minimization |  |  | 9156 | 1 | ⬜ |
| M5.1 | SVCB / HTTPS |  |  | 9460 / 9461 / 9462 | 2 | ⬜ |
| M5.2 | SSHFP |  |  | 4255 | 3 | ⬜ |
| M5.5 | CNAME cloaking |  |  | vendor-specific | 4 | ⬜ |
| M5.3 | DNAME / ANAME |  |  | 6676 + draft-aname | 5 | ⬜ |
| M5.7 | ECS |  |  | 7871 | 6 | ⬜ |
| M5.6 | DNS64 |  |  | 6147 | 7 | ⬜ |

## Sub-task progress

<!-- One checkbox per sub-task. Open a sub-task issue (via .github/ISSUE_TEMPLATE/m5-subtask.yml) and reference its number. -->

- [ ] **M5.4** — QNAME minimization (RFC 9156) — PR order #1
- [ ] **M5.1** — SVCB / HTTPS (RFC 9460/9461/9462) — PR order #2
- [ ] **M5.2** — SSHFP (RFC 4255) — PR order #3
- [ ] **M5.5** — CNAME cloaking (vendor-specific) — PR order #4
- [ ] **M5.3** — DNAME / ANAME (RFC 6676 + draft-aname) — PR order #5
- [ ] **M5.7** — ECS (RFC 7871) — PR order #6
- [ ] **M5.6** — DNS64 (RFC 6147) — PR order #7

## Success gates (from design doc §1)

<!-- Each gate must pass before M5 release tag. -->

- [ ] Gate 1 — `cargo check && cargo build --release` clean
- [ ] Gate 2 — `cargo test` all green (existing + new unit tests)
- [ ] Gate 3 — `tests/m5-records-validate.sh` (SVCB/HTTPS/SSHFP/DNAME/ANAME zone + DNSSEC)
- [ ] Gate 4 — `tests/m5-resolver-validate.sh` (SVCB authoritative + recursive Cloudflare HTTPS)
- [ ] Gate 5 — `tests/m5-qmin-validate.sh` (QNAME minimization: ≤3 labels per RFC 9156)
- [ ] Gate 6 — `tests/m5-dns64-validate.sh` (DNS64 synthesis from A with `64:ff9b::/96`)
- [ ] Gate 7 — `tests/m5-ecs-validate.sh` (scope-zero egress, subnet-aware cache key)
- [ ] Gate 8 — `tests/m5-cname-cloak-validate.sh` (9 CNAMEs → SERVFAIL)

## Release

- [ ] **M5 release tagged** (`v0.5.0-alpha`) — only after all 8 gates pass and the sub-task table above is fully ticked.
