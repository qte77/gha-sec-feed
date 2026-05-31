"""Atomic JSONL + meta writer for the C1 contract output."""

from pathlib import Path


def write_feed(rows: list[dict], meta: dict, out_dir: Path) -> None:
    """Write `feed.jsonl` and `feed-meta.json` atomically. Stub — phase 2b."""
    raise NotImplementedError(rows, meta, out_dir)
