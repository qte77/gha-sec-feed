"""Tests for ``gha_sec_feed.filter`` — post-merge row filter.

Each test catches a specific buggy impl variant (OR-vs-AND, scrambled
rank, case-sensitive match, refs-as-haystack noise, subset-vs-equality,
missing-data-passes, sort-introduction). Tautologies excluded.
"""

from __future__ import annotations

from typing import Any

from gha_sec_feed.config import AppSettings
from gha_sec_feed.filter import _passes, _severity_rank, apply_filters
from gha_sec_feed.models import FeedRow


def _row(**overrides: Any) -> FeedRow:
    base: dict[str, Any] = {
        "id": "CVE-2026-0001",
        "source": "nvd",
        "published": "2026-05-30T12:00:00Z",
        "severity": "high",
        "cvss": 7.5,
        "epss": None,
        "kev": False,
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
        "description": "",
        "cwes": [],
        "vendors": [],
    }
    base.update(overrides)
    return FeedRow.model_validate(base)


def _settings(**overrides: Any) -> AppSettings:
    return AppSettings(**overrides)  # pyright: ignore[reportCallIssue]


# ---------- _severity_rank ---------------------------------------------------


def test_severity_rank_is_strictly_increasing_unknown_to_critical():
    # Catches scrambled enum mapping (e.g., "low" ranked above "medium").
    assert (
        _severity_rank("unknown")
        < _severity_rank("low")
        < _severity_rank("medium")
        < _severity_rank("high")
        < _severity_rank("critical")
    )


# ---------- severity_min predicate -------------------------------------------


def test_passes_severity_min_admits_rows_at_or_above_threshold():
    s = _settings(severity_min="high")
    assert _passes(_row(severity="critical"), s) is True
    assert _passes(_row(severity="high"), s) is True


def test_passes_severity_min_rejects_rows_below_threshold():
    # Catches an off-by-one or strict ">" instead of ">=".
    s = _settings(severity_min="high")
    assert _passes(_row(severity="medium"), s) is False
    assert _passes(_row(severity="low"), s) is False
    assert _passes(_row(severity="unknown"), s) is False


# ---------- keyword predicate ------------------------------------------------


def test_passes_keyword_matches_description_not_refs():
    # Anti-noise: GHSA-mirror NVD refs are dominated by github.com URLs,
    # so haystacking refs would make the "github" keyword match every NVD
    # row. The haystack must be id + description ONLY.
    s = _settings(keywords=["github"])
    row = _row(description="Apache Struts RCE", refs=["https://github.com/example/repo"])
    assert _passes(row, s) is False


def test_passes_keyword_is_case_insensitive():
    # Catches a `keyword in description` impl without .lower() on both sides.
    s = _settings(keywords=["github"])
    assert _passes(_row(description="GitHub Actions workflow RCE"), s) is True


def test_passes_keyword_matches_against_cve_id_too():
    # The id is part of the haystack so vendors can keyword on CVE prefix
    # patterns. Catches a description-only impl.
    s = _settings(keywords=["CVE-2026-0001"])
    assert _passes(_row(description="unrelated"), s) is True


def test_passes_keyword_uses_word_boundary_not_substring():
    # `rust` must match the standalone word "Rust" but NOT fire on
    # "trust", "intrusion", "untrusted", "robustness", "rusty" — naive
    # substring matching produced ~186/272 hits in the 2026-06-05
    # showcase run, dominated by such false positives. Catches a
    # regression to the substring impl.
    s = _settings(keywords=["rust"])
    # Positive: standalone "Rust" (the language), case-insensitive.
    assert _passes(_row(description="Memory safety bug in the Rust compiler"), s) is True
    # Positive: surrounded by punctuation, still a word boundary.
    assert _passes(_row(description="See rust-lang.org for details"), s) is True
    # Negatives: these all contain the substring "rust" but no
    # standalone word — each must be REJECTED.
    for description in (
        "Untrusted input leads to RCE",
        "Lateral intrusion via SMB",
        "Trust boundary violation in authn flow",
        "Robustness fix for the parser",
        "Rusty hinges in the gate",
    ):
        assert _passes(_row(description=description), s) is False, description


def test_passes_keyword_matches_short_keyword_only_as_whole_word():
    # Short keywords like "uv", "pip", "npm" are the worst substring
    # offenders. Each must be REJECTED inside an unrelated longer word.
    s = _settings(keywords=["uv"])
    assert _passes(_row(description="OpenUV exposure tracker bug"), s) is False
    assert _passes(_row(description="uv-tool maintains the cache"), s) is True


# ---------- cwe_include predicate --------------------------------------------


def test_passes_cwe_include_admits_when_any_overlap():
    # Set intersection semantics — at least one shared CWE admits.
    # Catches a subset-vs-equality bug (requiring full match instead of any).
    s = _settings(cwe_include=["CWE-94", "CWE-79"])
    assert _passes(_row(cwes=["CWE-79", "CWE-200"]), s) is True


def test_passes_cwe_include_rejects_when_no_overlap():
    s = _settings(cwe_include=["CWE-94"])
    assert _passes(_row(cwes=["CWE-79", "CWE-200"]), s) is False


def test_passes_cwe_include_rejects_row_with_empty_cwes_when_filter_set():
    # Catches a "missing data = pass" bug. If the filter is on and the
    # row has no CWEs, intersection is empty → reject.
    s = _settings(cwe_include=["CWE-79"])
    assert _passes(_row(cwes=[]), s) is False


def test_passes_cwe_include_case_insensitive():
    # Catches case-sensitive compare. CWE identifiers are conventionally
    # upper-case but the filter normalises both sides.
    s = _settings(cwe_include=["cwe-79"])
    assert _passes(_row(cwes=["CWE-79"]), s) is True


# ---------- vendor_include predicate -----------------------------------------


def test_passes_vendor_include_admits_when_any_overlap():
    # Set intersection semantics — at least one shared vendor admits.
    # Catches a subset-vs-equality bug. `product_include` would mirror this
    # block 1:1 against `row.products` — add when that field exists.
    s = _settings(vendor_include=["python", "apache"])
    assert _passes(_row(vendors=["python", "tautulli"]), s) is True


def test_passes_vendor_include_rejects_when_no_overlap():
    s = _settings(vendor_include=["python"])
    assert _passes(_row(vendors=["tautulli", "draytek"]), s) is False


def test_passes_vendor_include_rejects_row_with_empty_vendors_when_filter_set():
    # Catches "missing data = pass". Fresh NVD CVEs ship before CPE
    # analysis completes, leaving `vendors=[]`. KEV rows also have
    # `vendors=[]` by default. With the filter set, both must reject.
    s = _settings(vendor_include=["python"])
    assert _passes(_row(vendors=[]), s) is False


def test_passes_vendor_include_case_insensitive():
    # CPE vendor names are lowercase by convention but callers may
    # configure with any case — both sides normalise.
    s = _settings(vendor_include=["Python"])
    assert _passes(_row(vendors=["python"]), s) is True


# ---------- kev_only predicate -----------------------------------------------


def test_passes_kev_only_admits_kev_true_rejects_kev_false():
    s = _settings(kev_only=True)
    assert _passes(_row(kev=True, severity="unknown"), s) is True
    assert _passes(_row(kev=False, severity="critical"), s) is False


# ---------- combined predicates ----------------------------------------------


def test_passes_combined_filters_are_AND_not_OR():
    # severity_min=high + keywords=python → both must hold.
    # Catches OR-vs-AND semantics regression.
    s = _settings(severity_min="high", keywords=["python"])
    assert _passes(_row(severity="high", description="python flaw"), s) is True
    assert _passes(_row(severity="low", description="python flaw"), s) is False
    assert _passes(_row(severity="high", description="rust flaw"), s) is False


# ---------- apply_filters public API -----------------------------------------


def test_apply_filters_default_settings_is_identity():
    # Producer-is-neutral default. Catches an accidental default-on filter.
    rows = [_row(id="CVE-A"), _row(id="CVE-B", kev=True), _row(id="CVE-C")]
    assert apply_filters(rows, _settings()) == rows


def test_apply_filters_populates_keywords_matched_for_admitted_rows():
    # When settings.keywords is non-empty, admitted rows carry the
    # actual matching subset on their `keywords_matched` field. Catches
    # the impl that admits rows without populating the audit trail.
    s = _settings(keywords=["github", "python"])
    row = _row(description="GitHub Actions workflow flaw in python tooling")
    [out] = apply_filters([row], s)
    assert out.keywords_matched == ["github", "python"]


def test_apply_filters_keywords_matched_omits_unmatched_keywords():
    # The audit trail must include ONLY the keywords that actually hit;
    # configured-but-unmatched keywords are excluded. Catches a copy-
    # the-whole-settings-list impl.
    s = _settings(keywords=["github", "python", "kubernetes"])
    row = _row(description="GitHub Actions workflow flaw")
    [out] = apply_filters([row], s)
    assert out.keywords_matched == ["github"]


def test_apply_filters_keywords_matched_preserves_settings_form_strings():
    # The audit trail stores the keyword strings as the caller configured
    # them (settings form), not the lowercased haystack form. Catches an
    # impl that round-trips through .lower() and loses casing.
    s = _settings(keywords=["GitHub", "Python"])
    row = _row(description="github actions flaw in python")
    [out] = apply_filters([row], s)
    assert out.keywords_matched == ["GitHub", "Python"]


def test_apply_filters_preserves_input_order():
    # Catches an accidental sort introduction.
    rows = [
        _row(id="CVE-Z", severity="critical"),
        _row(id="CVE-A", severity="critical"),
        _row(id="CVE-M", severity="critical"),
    ]
    out = apply_filters(rows, _settings(severity_min="high"))
    assert [r.id for r in out] == ["CVE-Z", "CVE-A", "CVE-M"]
