# Use as a reusable workflow

Downstream repos can produce their own filtered C1 feed by calling this
workflow from their own `.github/workflows/`. Each call writes
`data/feed.jsonl` + `data/feed-meta.json` to the caller's repo and auto-merges
a `chore(data)` PR with the refresh.

```yaml
name: sec-feed
on:
  schedule: [{ cron: '0 6 * * 1' }]
  workflow_dispatch: {}
permissions:
  contents: write
  pull-requests: write
jobs:
  update:
    uses: qte77/gha-sec-feed/.github/workflows/update_feed.yaml@main
    secrets: inherit
    with:
      keywords: 'kubernetes,nginx,traefik'   # CSV; empty = no filter
      severity_min: 'high'                    # critical/high/medium/low/unknown
      # since: '2026-05-01T00:00:00Z'         # ISO-8601 Z; default 8 days ago
      # kev_only: true                        # keep only KEV-flagged rows
      # cwe_include: 'CWE-79,CWE-200'         # CSV; intersect with row cwes
      # vendor_include: 'python,kubernetes'   # CPE-derived; KEV rejected when set
      # out_dir: 'data'                       # default
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `since` | 8 days ago | `pubStartDate` override, ISO-8601 Z UTC |
| `keywords` | `''` (no filter) | CSV keyword filter on `id + description`, case-insensitive |
| `severity_min` | `unknown` | Minimum severity (`unknown` = no severity filter) |
| `kev_only` | `false` | Keep only `kev=true` rows |
| `cwe_include` | `''` | CSV CWE ids; a row passes if it shares at least one |
| `vendor_include` | `''` | CSV CPE-derived vendors; KEV rows have empty vendors and are rejected when set |
| `out_dir` | `data` | Output directory for the two artifacts |

> **Dispatch quirk (#49):** triggering ad-hoc with `gh workflow run
> update_feed.yaml -f keywords=` (empty value) does **not** clear the filter —
> GitHub Actions falls back to the input's `default`. The `workflow_call`
> surface above uses `default: ''`, so downstream callers passing `keywords: ''`
> correctly get no filter. To force no-filter from an ad-hoc dispatch, pass
> `-f keywords=" "` (a single space, which the producer's CSV parser strips to
> an empty filter).
