.PHONY: install fmt lint test run validate clean

install:
	uv sync --dev

fmt:
	uv run ruff format

lint:
	uv run ruff check
	uv run ruff format --check
	uv run pyright src tests

test:
	uv run pytest

run:
	uv run python -m gha_sec_feed --out data

validate: lint test

clean:
	rm -rf .pytest_cache .ruff_cache .coverage coverage.xml htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
