# Data sources

The producer's brief at session-start enumerated **10 authoritative
vulnerability and threat-intel sources**. The v0.1.0 floor ships **2 active**
and defers **8** until a concrete consumer asks. This document is the
single source of truth for that split, and for the licensing / attribution
posture per source.

See [`GLOSSARY.md`](GLOSSARY.md) for acronym expansions.

## Schema + filter capability (v0.2.0)

C1 reached **schema 1.1.0** in v0.2.0 (current is **1.2.0** — see
[`SCHEMA.md`](SCHEMA.md) for the canonical field table and version history).
Additive over 1.0.0: rows gain `description` (English free text) and `cwes`
(CWE-prefixed identifiers). v1.0.0 consumers reading later rows see extra keys
they can ignore.

The producer applies an optional, env-driven row filter post-merge.
Four knobs — `severity_min`, `kev_only`, `cwe_include`, `keywords` —
all default to "no filter" so callers who set nothing receive the full
merged feed (v0.1.0 behaviour preserved). The reusable workflow
(`.github/workflows/update_feed.yaml`, `workflow_call:` surface) maps
its inputs to the corresponding `GSF_*` env vars on the producer step.

This repo's own cron uses a qte77-stack keyword set as a **showcase**
of the filter capability — see [README §Showcase scope](../README.md#showcase-scope).

## Schema 1.2.0

Additive over 1.1.0: rows gain `vendors` (CPE-derived vendor names,
lowercased) and `keywords_matched` (audit trail of which configured
`keywords` matched). Both default to `[]` so v1.0.0 / v1.1.0 consumers
reading v1.2.0 rows see extra keys they can ignore.

`vendors` is extracted from NVD's `configurations[].nodes[].cpeMatch[]`
by splitting CPE 2.3 criteria on `:` and taking index 3. Wildcard `*`
and dash `-` placeholders are skipped; dedup preserves NVD's
first-occurrence order. All CPE parts (`a` / `h` / `o`) are included;
the producer's `vendor_include` filter narrows at the call site. KEV
rows ship with `vendors=[]` (the catalog carries no CPE) so they are
rejected when `vendor_include` is set — downstream callers wanting
"KEV ∪ vendor scope" use `kev_only` orthogonally.

Fresh NVD CVEs occasionally ship before CPE analysis completes and
arrive with `vendors=[]`; the trade-off is symmetric with the existing
"missing CWE = reject" semantic on `cwe_include`. Documented here so
consumers know what `vendor_include` excludes.

`keywords_matched` is populated per-producer-run: the subset of the
producer's resolved `settings.keywords` that hit the row's
`id + description` (settings form preserved, so casing matches the
caller's input). The same row consumed by two reusable-workflow
callers with different `keywords:` inputs carries different
`keywords_matched` arrays — this is **not** a canonical row attribute.

`keywords_matched` is **distinct from C2's `matched_keywords`** as
emitted by downstream evaluators like `gha-sec-feed-eval`: C2's field
reflects the eval's `stack_keywords` matched against `refs`. Same
audit-trail purpose, different scope; the producer's field is
forwarded through unchanged.

`products` is a deliberate omission per YAGNI. CPE-derived product
names would be extracted from index 4 of the same `cpe:2.3:` split
and would mirror the `vendors` flow 1:1. Track via a tag/issue when
a concrete consumer asks.

The producer's filter gains a fifth knob — `vendor_include` (CSV,
intersection semantics, case-insensitive) — mirroring `cwe_include`'s
surface. Reusable workflow input + `GSF_VENDOR_INCLUDE` env var added.

## Active in v0.1.0

| `source` slug | Catalog | Endpoint + 1p docs | Auth | Licence | Attribution required |
|---|---|---|---|---|---|
| `nvd` | NVD CVE API v2 | `https://services.nvd.nist.gov/rest/json/cves/2.0` · [API docs](https://nvd.nist.gov/developers/vulnerabilities) | Optional [`NVD_API_KEY`](https://nvd.nist.gov/developers/request-an-api-key) raises rate limit 5/30s → 50/30s | US Government work (public domain) | **Yes** — verbatim string below |
| `cisa-kev` | CISA Known Exploited Vulnerabilities catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` · [catalog homepage](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | None | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) (per [cisagov/kev-data](https://github.com/cisagov/kev-data)) | Not legally required; credit is best practice |

### Required NVD attribution (verbatim)

> This product uses the NVD API but is not endorsed or certified by the NVD.

This string MUST appear in `data/feed-meta.json` under each NVD source
entry. Phase 2d (CLI assembly) wires it in automatically via a static
sources manifest in the writer/CLI layer so it travels with every
published artifact.

## Deferred (restore on first concrete request)

| `source` slug | Catalog | Endpoint + 1p docs | Licence | Attribution / blockers | Why deferred |
|---|---|---|---|---|---|
| `epss` | FIRST.org EPSS | `https://api.first.org/data/v1/epss` · [API docs](https://www.first.org/epss/api) | Unclear (free public grant; "All Rights Reserved" copyright on the site) | Soft request: cite [https://www.first.org/epss](https://www.first.org/epss) | Orthogonal probability score; useful once we have a consumer who ranks |
| `ghsa` | GitHub Security Advisories | REST `GET https://api.github.com/advisories?type=reviewed` · [API reference](https://docs.github.com/en/rest/security-advisories/global-advisories) | [CC-BY 4.0](https://github.com/github/advisory-database) | **Per-record `source_url`** (`html_url`) to `https://github.com/advisories/GHSA-xxxx` required | Ecosystem-tagged (npm / PyPI / Go / RubyGems) → better stack mapping than NVD for downstream filtering |
| `osv` | Google OSV.dev | `https://api.osv.dev/v1/query` · [API docs](https://google.github.io/osv.dev/api/) | Apache-2.0 for the platform; per-record license follows upstream (e.g., GHSA → CC-BY 4.0) | Inherits upstream attribution; cite OSV at `https://osv.dev/` | Distributed vuln DB; OSV-Scanner consumes the same format |
| `redhat` | Red Hat Security Data API | `https://access.redhat.com/hydra/rest/securitydata/cve.json` · [API docs](https://access.redhat.com/articles/red_hat_security_data_api) | [CC-BY 4.0](https://access.redhat.com/security/data) | **Per-record** attribution to `https://access.redhat.com/security/cve/<id>` required | RHEL / UBI advisories — needed when Docker base images are RHEL/UBI |
| `ubuntu` | Ubuntu Security Notices | `https://ubuntu.com/security/notices.json` · [catalog homepage](https://ubuntu.com/security/notices) | **Unclear** — no open-data licence found; notice text is © Canonical Ltd. | **Inquiry to Canonical legal required before adding** | Same for Ubuntu base images |
| `urlhaus` | abuse.ch URLhaus | `https://urlhaus-api.abuse.ch/` · [API docs](https://urlhaus.abuse.ch/api/) | Proprietary — [abuse.ch ToS](https://abuse.ch/terms-of-use/) prohibits derivative works without consent | **Hard blocker** — written permission required; commercial use → Spamhaus subscription | Non-CVE IOCs (malicious URLs) |
| `threatfox` | abuse.ch ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` · [API docs](https://threatfox.abuse.ch/api/) | Proprietary — [abuse.ch ToS](https://abuse.ch/terms-of-use/) | **Hard blocker** — same as URLhaus | Non-CVE IOCs (general threat indicators) |
| `malwarebazaar` | abuse.ch MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` · [API docs](https://bazaar.abuse.ch/api/) | Proprietary — [abuse.ch ToS](https://abuse.ch/terms-of-use/) | **Hard blocker** — same as URLhaus; sample redistribution carries additional criminal-law exposure | Non-CVE IOCs (malware samples) |

The umbrella tracking issue for restoring deferred sources is referenced
from the README's "Brief deviations" section and from the PR that scaffolded
this repo.

### TOU posture summary

- **Easiest to add** (lowest legal-review cost): EPSS, OSV, GHSA, Red Hat. CC-BY 4.0 sources require per-record `source_url` fields in `feed.jsonl` and a per-source attribution block in `feed-meta.json`.
- **Needs inquiry**: Ubuntu USN. No open licence text was found in the audit; Canonical's IP policy covers the distro, not advisory text. Reach out to Canonical legal before scaffolding the fetcher.
- **Cannot add without written consent**: all three abuse.ch sources (URLhaus, ThreatFox, MalwareBazaar). Their ToS explicitly prohibits derivative works and redistribution without express consent of abuse.ch and/or Spamhaus. Public auto-merged GitHub feed is the exact use case they prohibit. Commercial downstream consumers would trigger Spamhaus subscription requirements. MalwareBazaar additionally carries computer-fraud exposure for sample redistribution.

## Why this split (active vs deferred)

The brief's full 10-source set was correct for a steady-state producer. The
floor variant ships only the pair that **answers two distinct questions**
with **zero auth** and **zero overlap**:

1. **What's a CVE?** — NVD has the canonical record + CVSS.
2. **Which CVEs actively matter?** — KEV is the curated exploit-in-the-wild list.

The other 8 add value only once a downstream evaluator/consumer differentiates
on the dimensions they capture (EPSS probability, ecosystem mapping, distro
advisories, non-CVE IOCs). Until such a consumer exists, adding fetchers is
work spent on hypothetical demand — see [README's Brief deviations](../README.md#brief-deviations).

## Restoration path

For each deferred source:

1. **Check the TOU column above first.** Hard blockers and inquiries cannot be skipped.
2. Add the host to `src/gha_sec_feed/http.py:_ALLOWED_HOSTS`.
3. Add `src/gha_sec_feed/<slug>.py` with a `fetch()` function returning
   `list[dict]` matching the C1 row shape (see README).
4. Add `tests/fixtures/<slug>_sample.json` (recorded real response) +
   `tests/test_<slug>.py` (strict TDD: fixture → failing test → impl).
5. Wire into `src/gha_sec_feed/__main__.py:main()` — append to the dedupe
   stream; KEV-style flags (`kev=true`, future `ransomware=true`) win on conflict.
6. Bump `feed-meta.sources` listing **with the source's `license` and `attribution` strings** so the published artifact carries the required notices.
7. For CC-BY-4.0 sources (`ghsa`, `redhat`): also add a per-row `source_url` field linking to the canonical advisory page (e.g., `https://github.com/advisories/GHSA-xxxx`, `https://access.redhat.com/security/cve/CVE-...`).
8. **No `schema_version` bump required** for new sources alone. The `source_url` extension for CC-BY sources IS a minor schema bump (1.0.x → 1.1.0).

## Allowlist coupling

The same allowlist that governs our GitHub Actions (org-level baseline,
applied via an internal `repo-baseline` tool — not public-linkable) does
**not** apply to outbound HTTP from the producer — that's covered by
[`src/gha_sec_feed/http.py`](../src/gha_sec_feed/http.py)'s `_ALLOWED_HOSTS`
frozenset. The two allowlists are independent: one for build-time
third-party actions, one for runtime egress.
