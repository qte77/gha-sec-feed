# Contributing

## Local development

All dev commands live in the [`Makefile`](Makefile) — the single source of
truth. Run them via `make`:

| Command | What it does |
|---|---|
| `make install` | Sync the dev environment (`uv sync --dev`) |
| `make fmt` | Auto-format with `ruff format` |
| `make lint` | `ruff check` + `ruff format --check` + `pyright` |
| `make test` | Run the test suite (`pytest`) |
| `make validate` | `lint` + `test` — the same gate CI runs |
| `make run` | Run the producer; writes `./data/feed.jsonl` |

Run `make validate` before pushing; CI runs the same target.

## Workflow conventions

- **Strict TDD** for module logic (`fetchers/`, `filter`, `config`, `http`,
  `writer`): write a failing test, implement, refactor to green. Thin CLI/script
  glue does not need tests.
- Use **property-based tests** (`hypothesis`) for invariant-dense functions
  (parsers, mergers, score mappings).
- One topic per commit; conventional-commit messages.
- PRs squash-merge once CI + CodeFactor are green.

## CLI reference

```text
uv run python -m gha_sec_feed [--out PATH] [--since ISO-Z]

  --out PATH     Output directory for feed.jsonl + feed-meta.json (default: ./data)
  --since ISO-Z  Earliest published date to fetch (default: 7 days ago, UTC)
```

## Configuration (environment variables)

The producer reads deployment knobs from env vars (`GSF_` prefix; `NVD_API_KEY`
is unprefixed to match NIST's name). The reusable workflow maps its inputs to
these — see [`docs/reusable-workflow.md`](docs/reusable-workflow.md).

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `GSF_OUT_DIR` | path | `./data` | Output directory |
| `GSF_SINCE_DAYS` | int 1–120 | `7` | Default lower-bound window in days |
| `GSF_HTTP_TIMEOUT` | float | `30.0` | Per-request HTTP timeout (seconds) |
| `GSF_HTTP_MAX_RETRIES` | int 1–10 | `3` | Attempts before raising |
| `GSF_USER_AGENT` | str | random browser UA | Outbound User-Agent (avoids CDN bot heuristics) |
| `GSF_SEVERITY_MIN` | enum | `unknown` | Minimum severity admitted (`unknown` = all) |
| `GSF_KEV_ONLY` | bool | `false` | Keep only `kev=true` rows |
| `GSF_CWE_INCLUDE` | CSV | (empty) | CWE allowlist; empty = no filter |
| `GSF_VENDOR_INCLUDE` | CSV | (empty) | Vendor allowlist; empty = no filter |
| `GSF_KEYWORDS` | CSV | (empty) | Keyword filter on `id + description`; empty = no filter |
| `NVD_API_KEY` | secret | (none) | Raises the NVD rate limit from 5 to 50 requests / 30s |

`NVD_API_KEY` is optional: get a free [NVD key](https://nvd.nist.gov/developers/request-an-api-key)
and set it via `.env` or the environment. Without it the producer emits a
one-time warning and runs at the 5 req/30s limit.
