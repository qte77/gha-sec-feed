# C1 schema

`C1` is this producer's external contract: the row shape of `data/feed.jsonl`
(one JSON object per line) plus the `data/feed-meta.json` sidecar. See
[`GLOSSARY.md`](GLOSSARY.md) for acronyms. The version string is defined once,
in `src/gha_sec_feed/models.py` (`FEED_SCHEMA_VERSION`).

## `feed.jsonl` row

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
  "description": "SQL injection in /api/v1/users",
  "cwes": ["CWE-89"],
  "vendors": ["python"],
  "keywords_matched": ["fastapi"],
  "schema_version": "1.2.0"
}
```

| Field | Meaning |
|---|---|
| `id` | Canonical CVE identifier (`CVE-YYYY-NNNNN`) |
| `source` | `nvd` or `cisa-kev` (more sources may be added) |
| `published` | ISO 8601 UTC timestamp |
| `severity` | One of `critical`, `high`, `medium`, `low`, `unknown` |
| `cvss` | Float 0.0–10.0; `null` if unknown |
| `epss` | Float 0.0–1.0; `null` if not in EPSS |
| `kev` | Boolean — is this CVE in the CISA KEV catalog? |
| `refs` | Array of authoritative URLs (≥ 1) |
| `description` | Free-text summary (English; v1.1.0+) |
| `cwes` | Array of CWE-prefixed identifiers (v1.1.0+) |
| `vendors` | CPE-derived vendor names, lowercased (v1.2.0+; empty for KEV rows and fresh CVEs awaiting CPE analysis) |
| `keywords_matched` | Subset of the producer's configured `keywords` that matched `id + description` (v1.2.0+; per-producer-run, preserves caller casing) |
| `schema_version` | Current `"1.2.0"`; additive bumps stay backwards-compatible |

## `feed-meta.json` sidecar

Sidecar metadata carried alongside the feed: `sources` (per-source licence +
attribution), `last_run`, `schema_version`, `item_count`, `tool_version`.

## Version history

| Schema | Added |
|---|---|
| 1.0.0 | Base row: `id`, `source`, `published`, `severity`, `cvss`, `epss`, `kev`, `refs` |
| 1.1.0 | `description`, `cwes` |
| 1.2.0 | `vendors`, `keywords_matched` |

Every bump is **additive**: a consumer reading newer rows sees extra keys it can
safely ignore, so older consumers keep working.
