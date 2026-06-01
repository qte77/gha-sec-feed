"""Atomic JSONL + meta writer for the C1 contract output."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_JSONL_NAME = "feed.jsonl"
_META_NAME = "feed-meta.json"


def _write_text_atomic(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` via ``tempfile + os.replace``.

    On failure, the temp file is removed and the destination at ``path``
    (if any) is left untouched.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        if tmp.exists():
            tmp.unlink()
        raise


def write_feed(rows: list[dict[str, Any]], meta: dict[str, Any], out_dir: Path) -> None:
    """Write ``rows`` as JSONL and ``meta`` as JSON to ``out_dir`` atomically.

    Both files are produced via tempfile + ``os.replace``: either both writes
    succeed end-to-end, or any partially-written tempfile is removed and the
    previous file (if any) is left intact.

    Output is deterministic: ``json.dumps(..., sort_keys=True)`` for both,
    so identical inputs produce byte-identical outputs across runs.
    """
    rows_text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    meta_text = json.dumps(meta, sort_keys=True, indent=2) + "\n"
    _write_text_atomic(out_dir / _JSONL_NAME, rows_text)
    _write_text_atomic(out_dir / _META_NAME, meta_text)
