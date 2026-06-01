"""Shared pytest fixtures: fixture-file loader and reusable test data paths."""

from __future__ import annotations

from json import loads
from pathlib import Path
from typing import Any

import pytest


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def load_fixture():
    def _load(name: str) -> Any:
        path = FIXTURES / name
        return loads(path.read_text(encoding="utf-8"))

    return _load
