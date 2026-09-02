# M5 — Tracking Addendum

> Living tracker for the M5 scaffold + implementation work. Created as
> PR 0 of the M5 milestone. Last touched: 2026-09-01 (M5.4 landed).

## Scaffold state

| Item | Value |
|------|-------|
| Branch | `main` (direct commits — solo maintainer workflow; no long-lived feature branch) |
| Base for scaffold | `main` @ `96c6b93` (M4 complete, tagged `v0.4.0a`) |
| Design doc | [`plans/m5_design.md`](m5_design.md) (commit 1 of scaffold) |
| Sub-task issue template | [`.github/ISSUE_TEMPLATE/m5-subtask.yml`](../.github/ISSUE_TEMPLATE/m5-subtask.yml) |
| Meta-tracking issue template | [`.github/ISSUE_TEMPLATE/m5-meta.md`](../.github/ISSUE_TEMPLATE/m5-meta.md) |
| Template config | [`.github/ISSUE_TEMPLATE/config.yml`](../.github/ISSUE_TEMPLATE/config.yml) (`blank_issues_enabled: false`) |
| First sub-task to open | **M5.1 — SVCB / HTTPS** (M5.4 landed on `main`) |
| Target tag | `v0.5.0-alpha` (after all 8 success gates pass; see design doc §1) |

## Commit log for M5 scaffold

<!-- Refresh with: git log --oneline 96c6b93..HEAD -->

```
c725ed4 ci(issues): M5 issue templates + meta-tracking checklist
f748f96 docs(plans): M5 design — SVCB/HTTPS, SSHFP, DNAME/ANAME, QNAME min, CNAME cloaking, DNS64, ECS
```

## PR-by-PR landing plan

Per [`plans/m5_design.md`](m5_design.md) §5 (architect-recommended order).
For sub-task implementation work, branch from `main`, open a PR against `main`,
squash-merge once the gate closes:

| PR | ID | Sub-task | Issue template | Branch suggestion |
|----|----|----------|----------------|-------------------|
| 0 | — | Scaffold (this) | — | (committed directly to `main`) |
| 2 | M5.1 | SVCB / HTTPS | `m5-subtask.yml` (id=M5.1) | `feat/m5-svcb` |
| 3 | M5.2 | SSHFP | `m5-subtask.yml` (id=M5.2) | `feat/m5-sshfp` |
| 4 | M5.5 | CNAME cloaking | `m5-subtask.yml` (id=M5.5) | `feat/m5-cname-cloak` |
| 5 | M5.3 | DNAME / ANAME | `m5-subtask.yml` (id=M5.3) | `feat/m5-dname-aname` |
| 6 | M5.7 | ECS | `m5-subtask.yml` (id=M5.7) | `feat/m5-ecs` |
| 7 | M5.6 | DNS64 | `m5-subtask.yml` (id=M5.6) | `feat/m5-dns64` |

## Landed

| PR | ID | Sub-task | Commit | CI run | Notes |
|----|----|----------|--------|--------|-------|
| 1 | M5.4 | QNAME minimization (RFC 9156) | [`47569fe`](https://github.com/Veridian-Zenith/Heimdallr/commit/47569fe) on `main` | [run 33571400992](https://github.com/Veridian-Zenith/Heimdallr/actions/runs/33571400992) ✅ | opt-in (`enable=false` default); 10 unit tests; `tests/qname-min-validate.sh`; clippy/fmt/audit/deny clean. Driver in `src/core/resolver/qname_min.rs`; wiring in `src/core/resolver/forward.rs`. |
| 2 | M5.1 | SVCB / HTTPS (RFC 9460/9461) | [`faad4e6`](https://github.com/Veridian-Zenith/Heimdallr/commit/faad4e6) on `main` (parser) + this commit (API + docs) | [run 33573013483](https://github.com/Veridian-Zenith/Heimdallr/actions/runs/33573013483) ✅ (parser run) | Parser in `src/core/zone/file.rs` (`parse_svcb_data` / `parse_https_data`); API CRUD wired in `src/core/zone/record.rs::parse_rdata`; 3 unit tests for SVCB basic, HTTPS alpn, garbage rejection. Round-trip works (hickory `Display` is stable key-order). Next: **M5.2 SSHFP** — copy-paste of M5.1 plumbing. |
| 3 | M5.2 | SSHFP (RFC 4255) | this commit on `main` | (see PR run) | Parser in `src/core/zone/file.rs::parse_sshfp_data`; API CRUD wired in `src/core/zone/record.rs::parse_rdata`; 5 unit tests (3 in `file.rs`: RFC 4255 example, Ed25519+SHA-256, garbage rejection; 2 in `record.rs`: basic, garbage). Test count 84 → 89. Hickory `SSHFP` uses field access (not methods) + `u8::from(...)` for the algorithm/fingerprint_type enums. Next: **M5.5 CNAME cloaking** (per design doc §5 PR order). |

## Opening the first sub-task issue

1. Use the **M5 Sub-task** template on GitHub (`.github/ISSUE_TEMPLATE/m5-subtask.yml`).
2. Set `subtask_id` = **M5.1 — SVCB / HTTPS**.
3. Fill `rfc` = `9460`.
4. Fill `files` = `src/core/zone/record.rs`, `src/core/rec/mod.rs`.
5. Fill `gate` = `Gate #4`.
6. Reference design-doc sections in `notes` (RFC 9460 §2, design doc §3 M5.1 block).
7. Apply the meta-issue checklist update in `.github/ISSUE_TEMPLATE/m5-meta.md` for the M5.1 row.

## Notes / deviations from this scaffold

- **No `assignees:`** in `m5-subtask.yml` — GitHub's issue-form schema rejects empty
  arrays; omit rather than specify.
- **Contact links** in `config.yml` point at the `main` branch for the design doc
  URL so the linked content is always the latest merged version.
- **Working on `main`, not `feat/m5`** — solo maintainer; long-lived feature
  branches add no review value here. The two scaffold commits ship straight to
  `main` and individual sub-task branches (`feat/m5-qmin`, `feat/m5-svcb`, …)
  are opened per the table above when implementation begins.
