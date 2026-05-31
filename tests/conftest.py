"""Shared pytest fixtures: fixture-file loader and reusable test data paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str) -> Any:
        path = FIXTURES / name
        return json.loads(path.read_text(encoding="utf-8"))

    return _load
