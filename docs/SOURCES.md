# Data sources

The producer's brief at session-start enumerated **10 authoritative
vulnerability and threat-intel sources**. The v0.1.0 floor ships **2 active**
and defers **8** until a concrete consumer asks. This document is the
single source of truth for that split.

See [`GLOSSARY.md`](GLOSSARY.md) for acronym expansions.

## Active in v0.1.0

| `source` slug | Catalog | Endpoint + 1p docs | Auth | Notes |
|---|---|---|---|---|
| `nvd` | NVD CVE API v2 | `https://services.nvd.nist.gov/rest/json/cves/2.0` · [API docs](https://nvd.nist.gov/developers/vulnerabilities) | Optional [`NVD_API_KEY`](https://nvd.nist.gov/developers/request-an-api-key) env var raises rate limit 5/30s → 50/30s | Canonical CVE database; broadest coverage; CVSS scores |
| `cisa-kev` | CISA Known Exploited Vulnerabilities catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` · [catalog homepage](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | None | High-signal subset (~1,600 entries) of actively-exploited CVEs |

## Deferred (restore on first concrete request)

| `source` slug | Catalog | Endpoint + 1p docs | Why deferred |
|---|---|---|---|
| `epss` | FIRST.org EPSS | `https://api.first.org/data/v1/epss` · [API docs](https://www.first.org/epss/api) | Orthogonal probability score; useful once we have a consumer who ranks |
| `ghsa` | GitHub Security Advisories | GraphQL `securityAdvisories` on `https://api.github.com/graphql` · [API reference](https://docs.github.com/en/graphql/reference/queries#securityadvisories) | Ecosystem-tagged (npm / PyPI / Go / RubyGems) → better stack mapping than NVD for downstream filtering |
| `osv` | Google OSV.dev | `https://api.osv.dev/v1/query` · [API docs](https://google.github.io/osv.dev/api/) | Distributed vuln DB; OSV-Scanner consumes the same format |
| `redhat` | Red Hat Security Data API | `https://access.redhat.com/hydra/rest/securitydata/cve.json` · [API docs](https://access.redhat.com/articles/red_hat_security_data_api) | RHEL / UBI advisories — needed when Docker base images are RHEL/UBI |
| `ubuntu` | Ubuntu Security Notices | `https://ubuntu.com/security/notices.json` · [catalog homepage](https://ubuntu.com/security/notices) | Same for Ubuntu base images |
| `urlhaus` | abuse.ch URLhaus | `https://urlhaus-api.abuse.ch/` · [API docs](https://urlhaus.abuse.ch/api/) | Non-CVE IOCs (malicious URLs) |
| `threatfox` | abuse.ch ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` · [API docs](https://threatfox.abuse.ch/api/) | Non-CVE IOCs (general threat indicators) |
| `malwarebazaar` | abuse.ch MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` · [API docs](https://bazaar.abuse.ch/api/) | Non-CVE IOCs (malware samples) |

The umbrella tracking issue for restoring deferred sources is referenced
from the README's "Brief deviations" section and from the PR that scaffolded
this repo.

## Why this split

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

1. Add the host to `src/gha_sec_feed/http.py:_ALLOWED_HOSTS`.
2. Add `src/gha_sec_feed/<slug>.py` with a `fetch()` function returning
   `list[dict]` matching the C1 row shape (see README).
3. Add `tests/fixtures/<slug>_sample.json` (recorded real response) +
   `tests/test_<slug>.py` (strict TDD: fixture → failing test → impl).
4. Wire into `src/gha_sec_feed/__main__.py:main()` — append to the dedupe
   stream; KEV-style flags (`kev=true`, future `ransomware=true`) win on conflict.
5. Bump `feed-meta.sources` listing.
6. **No `schema_version` bump required** — new sources don't break C1.

## Allowlist coupling

The same allowlist that governs our GitHub Actions (org-level baseline,
applied via an internal `repo-baseline` tool — not public-linkable) does
**not** apply to outbound HTTP from the producer — that's covered by
[`src/gha_sec_feed/http.py`](../src/gha_sec_feed/http.py)'s `_ALLOWED_HOSTS`
frozenset. The two allowlists are independent: one for build-time
third-party actions, one for runtime egress.
