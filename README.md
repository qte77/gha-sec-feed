# gha-sec-feed

> Weekly CVE/KEV security feed as a reusable GitHub Actions workflow — normalized JSONL, auto-committed, zero-auth to consume.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/qte77/gha-sec-feed?color=blue)](https://github.com/qte77/gha-sec-feed/releases)
[![CI](https://github.com/qte77/gha-sec-feed/actions/workflows/ci.yaml/badge.svg)](https://github.com/qte77/gha-sec-feed/actions/workflows/ci.yaml)

## What

- A weekly feed of **NVD CVE + CISA KEV** vulnerability data, normalized to one stable JSONL contract (**C1**).
- Consumable as a raw file — **no API, no auth, no rate limits** — straight from GitHub.
- **Reusable as a GitHub Actions workflow**: drop it into any repo to produce your own filtered feed.
- Filter by keyword, severity, KEV status, CWE, or CPE-derived vendor at the producer boundary.
- Each refresh auto-commits a **signed** `chore(data)` PR and merges hands-off once green.
- Self-describing: per-source licence + attribution travel inside `feed-meta.json`.
- Tiny, dependency-light Python producer; new sources land additively.

## How

Consume the published feed directly:

```bash
curl -s https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl \
  | jq -c 'select(.kev == true)'
```

- **Contract** (row + sidecar shape): [`docs/SCHEMA.md`](docs/SCHEMA.md)
- **Reuse** it in your own repo: [`docs/reusable-workflow.md`](docs/reusable-workflow.md)
- **Run / develop** locally: [`CONTRIBUTING.md`](CONTRIBUTING.md)

This repo's own `data/feed.jsonl` is filtered to a qte77-stack keyword showcase;
consumers who want the unfiltered superset call the reusable workflow with
`keywords: ''`. See [`docs/SOURCES.md`](docs/SOURCES.md).

## Why

NVD and CISA KEV are authoritative but awkward to consume directly: rate-limited
APIs, differing shapes, and no built-in filtering. `gha-sec-feed` normalizes them
into one stable JSONL contract, refreshes it on a cron, and serves it as a plain
file — so downstream repos get filtered, attributed vulnerability data with zero
infrastructure and zero auth, instead of each re-implementing fetch/normalize/rate-limit.

## Refs

- [`docs/SCHEMA.md`](docs/SCHEMA.md) — the C1 row + meta contract
- [`docs/reusable-workflow.md`](docs/reusable-workflow.md) — calling it from your repo
- [`docs/SOURCES.md`](docs/SOURCES.md) — data sources, licensing, showcase scope
- [`docs/GLOSSARY.md`](docs/GLOSSARY.md) — acronyms (NVD, KEV, CVSS, C1, …)
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — local dev, CLI, configuration

## License

[Apache-2.0](LICENSE).
