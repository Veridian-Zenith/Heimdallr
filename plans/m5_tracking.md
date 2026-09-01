# M5 — Tracking Addendum

> Living tracker for the M5 scaffold + implementation work. Created as
> PR 0 of the M5 milestone. Last touched: 2026-09-01.

## Scaffold state

| Item | Value |
|------|-------|
| Branch | `main` (direct commits — solo maintainer workflow; no long-lived feature branch) |
| Base for scaffold | `main` @ `96c6b93` (M4 complete, tagged `v0.4.0a`) |
| Design doc | [`plans/m5_design.md`](m5_design.md) (commit 1 of scaffold) |
| Sub-task issue template | [`.github/ISSUE_TEMPLATE/m5-subtask.yml`](../.github/ISSUE_TEMPLATE/m5-subtask.yml) |
| Meta-tracking issue template | [`.github/ISSUE_TEMPLATE/m5-meta.md`](../.github/ISSUE_TEMPLATE/m5-meta.md) |
| Template config | [`.github/ISSUE_TEMPLATE/config.yml`](../.github/ISSUE_TEMPLATE/config.yml) (`blank_issues_enabled: false`) |
| First sub-task to open | **M5.4 — QNAME minimization (RFC 9156)** — per design doc §5 PR order |
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
| 1 | M5.4 | QNAME minimization | `m5-subtask.yml` (id=M5.4) | `feat/m5-qmin` |
| 2 | M5.1 | SVCB / HTTPS | `m5-subtask.yml` (id=M5.1) | `feat/m5-svcb` |
| 3 | M5.2 | SSHFP | `m5-subtask.yml` (id=M5.2) | `feat/m5-sshfp` |
| 4 | M5.5 | CNAME cloaking | `m5-subtask.yml` (id=M5.5) | `feat/m5-cname-cloak` |
| 5 | M5.3 | DNAME / ANAME | `m5-subtask.yml` (id=M5.3) | `feat/m5-dname-aname` |
| 6 | M5.7 | ECS | `m5-subtask.yml` (id=M5.7) | `feat/m5-ecs` |
| 7 | M5.6 | DNS64 | `m5-subtask.yml` (id=M5.6) | `feat/m5-dns64` |

## Opening the first sub-task issue

1. Use the **M5 Sub-task** template on GitHub (`.github/ISSUE_TEMPLATE/m5-subtask.yml`).
2. Set `subtask_id` = **M5.4 — QNAME minimization (RFC 9156)**.
3. Fill `rfc` = `9156`.
4. Fill `files` = `src/core/resolver/forward.rs`, `src/core/resolver/qmin.rs (new)`, `src/core/rec/mod.rs`.
5. Fill `gate` = `Gate #5`.
6. Reference design-doc sections in `notes` (RFC 9156 §2/§3, design doc §3 M5.4 block).
7. Apply the meta-issue checklist update in `.github/ISSUE_TEMPLATE/m5-meta.md` for the M5.4 row.

## Notes / deviations from this scaffold

- **No `assignees:`** in `m5-subtask.yml` — GitHub's issue-form schema rejects empty
  arrays; omit rather than specify.
- **Contact links** in `config.yml` point at the `main` branch for the design doc
  URL so the linked content is always the latest merged version.
- **Working on `main`, not `feat/m5`** — solo maintainer; long-lived feature
  branches add no review value here. The two scaffold commits ship straight to
  `main` and individual sub-task branches (`feat/m5-qmin`, `feat/m5-svcb`, …)
  are opened per the table above when implementation begins.
