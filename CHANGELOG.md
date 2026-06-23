# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`. Entries are hand-edited (no scriv) — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## [Unreleased]

### Added

- **GHSA source** (`source: ghsa`) — GitHub Security Advisories via the REST
  `/advisories` API; advisory `html_url` carried in `refs` as CC-BY 4.0
  attribution (schema 1.3.0).
- **MSRC source** (`source: msrc`) — Microsoft Security Response Center CVRF
  v3.0 (schema 1.4.0). Built against the documented shape; runs behind graceful
  degradation as MSRC's WAF may block datacenter IPs.
- **NVD vendor inference** — when CPE analysis is absent, infer vendors from
  `github.com/<org>` references (host-anchored).
- **Graceful per-source degradation** — one source failing is logged and
  skipped instead of sinking the whole refresh; only an all-sources failure errors.
- **Docs**: `CONTRIBUTING.md`, `docs/SCHEMA.md`, `docs/reusable-workflow.md`;
  release tooling via `bump-my-version` + `make` targets.

### Changed

- **Auto-PR commits are now signed** — the weekly refresh commits via the Git
  Data API (web-flow signed), so the PR auto-merges under `required_signatures`.
- **Showcase filter** swapped from a keyword set to a CPE/ref-derived **vendor
  allowlist** (more precise), gated to this repo's own cron.
- **README** adopted the doc-structure canon (Hero → What → How → Why → Refs →
  License) with badges; depth moved to `docs/`. C1 schema is now **1.4.0**.
- Refreshed the browser User-Agent pool to current major versions.

### Fixed

- KEV `notes` with multiple semicolon-separated URLs now split into distinct
  `refs[]` entries.
- The producer creates a missing output directory instead of raising
  `FileNotFoundError`.
- One-time warning when the NVD host is queried without `NVD_API_KEY`.
- Data-only auto-PRs are no longer blocked by a required CodeQL check.

### Security

- Bumped `pydantic-settings` to 2.14.2 (symlink-traversal advisory) and
  `actions/checkout` to v7.
- Restricted the repo Actions policy to a `selected` allowlist (github-owned +
  pinned third-party actions) and added a `pip-audit` dependency gate.
