# Branding — Heimdallr

Watcher at the `Bifrost`. Part of the `Veridian Zenith` `Nordic` lineage that includes `Galdr` (chant), `Verdandi` (fate), `Voix` (voice), `DDS` (presence), `Ljod`, `WuMing` (`~/Work/VZ` `1-8`).

## Name

**Heimdallr** — Old Norse. The god who hears grass grow and watches the bridge. The daemon that watches `53/udp` exactly the same way. No anglicized `Heimdall`.

- Use: `Heimdallr` (capital `H`, lower `r` terminal).
- Binary: `heimdallr` (lower, `Cargo.toml:name`).
- Service: `heimdallr.service`.
- Repo: `github.com/Veridian-Zenith/Heimdallr` (`Cargo.toml:repository`).

Never `Technitium`, `Heimdall`, `Heimdall DNS`.

## Mark

Design tokens mirror `vzdev.indevs.in/TODO.md:7-9` `Amber, Red, Gold, Black`:

- Sigil: `H` formed from `ᚼ` (`Hagall`) + bridge arch, stroke `Amber #f59e0b` on `Void Black #0a0a0a`, `Glitch Red #ef4444` for errors (same `HIDDEN.md` `Red Copyright` riddle).
- `Rosemary` + `Iosevka` (`vzdev.indevs.in/TODO.md:48-49`) — `Rosemary` for display, `Iosevka` for `dig` blocks/code, both vendored under `public/` when console ships (`M7`).
- Do not reuse `Technitium DnsServer/DnsServerCore/www` assets or `DnsServerApp/logo2.ico`.

## Voice

Short and concise, facts over superlatives — same as `Veridian Zenith` `vzdev.indevs.in` pages. No `military-grade` / `blazingly fast` claims; cite `ns`/`qps` bench (`docs/testing.md:Flamethrower`).

## Usage rules (enforce `LICENSE:25` `Exclusions`)

- Do not use `Veridian Zenith` or `Heimdallr` marks to endorse a fork without written permission.
- Derivative web consoles must replace the `Loading Screen` latency sigil (`vzdev.indevs.in/HIDDEN.md:5` `Void Latency Feedback` clone temptation) with own runes.
- `OSL-3.0` requires retaining `LICENSE` notices in Source Code (`LICENSE:6` Attribution Rights) — keep `Copyright (c) 2026 Veridian Zenith` adjacent to `Licensed under OSL-3.0`.

## Assets (planned)

```
assets/
  brand/
    heimdallr-sigil.svg
    heimdallr-wordmark.svg
  console/
    favicon.svg
```

Export via `vite-plugin-pwa` style single source (`vzdev.indevs.in/TODO.md:56`) when `M7` console lands.
