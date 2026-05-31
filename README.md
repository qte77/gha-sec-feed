# gha-sec-feed

A small Python producer that fetches CVE data from **NVD** and **CISA KEV**,
normalises into a JSONL stream, and commits the output to this repo's `data/`
directory on a weekly cron. The single external contract is **C1** — the row
shape of `data/feed.jsonl` plus the structure of `data/feed-meta.json`.

For acronym expansions (NVD, KEV, CVE, CVSS, EPSS, C1, JSONL, ...) see
[`docs/GLOSSARY.md`](docs/GLOSSARY.md).

## How to consume

`data/feed.jsonl` ships one JSON row per line, fetched directly from GitHub:

```bash
curl -s https://raw.githubusercontent.com/qte77/gha-sec-feed/main/data/feed.jsonl \
  | jq -c 'select(.kev == true)'
```

Per-row C1 shape:

```json
{
  "id": "CVE-2026-12345",
  "source": "nvd",
  "published": "2026-05-31T00:00:00Z",
  "severity": "critical",
  "cvss": 9.8,
  "epss": null,
  "kev": true,
  "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"],
  "schema_version": "1.0.0"
}
```

| Field | Meaning |
|---|---|
| `id` | Canonical CVE identifier (`CVE-YYYY-NNNNN`) |
| `source` | `nvd` or `cisa-kev` (v0.1.0 floor — more sources may be added) |
| `published` | ISO 8601 UTC timestamp |
| `severity` | One of `critical`, `high`, `medium`, `low`, `unknown` |
| `cvss` | Float 0.0-10.0; `null` if unknown |
| `epss` | Float 0.0-1.0; `null` if not in EPSS (always `null` in the floor) |
| `kev` | Boolean — is this CVE in the CISA KEV catalog? |
| `refs` | Array of authoritative URLs (≥ 1) |
| `schema_version` | `"1.0.0"` — bumped only on breaking changes |

`data/feed-meta.json` ships sidecar metadata: `sources`, `last_run`,
`schema_version`, `item_count`.

## Local development

```bash
make install              # uv sync --dev
make lint                 # ruff + pyright
make test                 # pytest with coverage
make validate             # lint + test
make run                  # run the producer; writes ./data/feed.jsonl
```

Optional `NVD_API_KEY` env var raises NVD's rate limit from 5/30s to 50/30s.

## Brief deviations

This repo deliberately ships **below** the design-brief MVP. The cuts are
documented here so that the brief author or a future-me can restore individual
items on first concrete user request.

**Cut:**

- 8 of 10 brief sources (only NVD + CISA KEV; the rest — EPSS, GHSA, OSV, RHSA, USN, urlhaus, threatfox, malwarebazaar — are deferred)
- All Pydantic machinery (`pydantic`, `pydantic-settings`, `AppSettings`) — plain dicts; consumers validate at their boundary
- All governance files (`AGENTS.md`, `AGENT_LEARNINGS.md`, `AGENT_REQUESTS.md`, `CONTRIBUTING.md`, `CODEOWNERS`)
- `CHANGELOG.md` + `changelog.d/` — restored at first `v0.1.0` release tag
- `.devcontainer/`, `.markdownlint-cli2.jsonc`, `lychee.toml`, `NOTICE`
- Workflows: `markdownlint`, `lychee`, `gitleaks`, `trivy`, `osv-scanner`, `actionlint`
- `step-security/harden-runner` (no release artifacts to harden against yet)
- Dashboard, GitHub Pages deploy, `feed.xml` RSS
- SBOM via Syft, SLSA build provenance attestation, sigstore signing
- `config/categories.default.yaml` — producer-side filtering; consumers filter
- `docs/architecture.md` boundary failure-policy table
- `complexipy` — ruff's `C90` McCabe check covers it
- In-repo `.claude/skills/`, `.claude/rules/` — user-global config covers

**Kept verbatim from the brief:**

- C1 contract (row shape + meta shape, locked at v1.0.0)
- `_ALLOWED_HOSTS` egress allowlist (Megalodon-style defence)
- Identity-shape `User-Agent` defaulted on every outbound request
- `Accept: application/json` default
- `Retry-After` parsing on 429 responses
- Conditional NVD `apiKey` header when `NVD_API_KEY` is set
- SHA-pinned `uses:` for every GitHub Action
- Default-deny `permissions: {}` at workflow top + per-job scoping
- Weekly Dependabot (pip + github-actions)
- CodeQL scan with inline-suppression dismissals

## License

[Apache-2.0](LICENSE).
