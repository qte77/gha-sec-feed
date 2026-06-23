.PHONY: install fmt lint test test-cov audit run validate bump-patch bump-minor bump-major clean

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

test-cov:
	uv run pytest --cov-fail-under=70

audit:
	uv run pip-audit --skip-editable

run:
	uv run python -m gha_sec_feed --out data

validate: lint audit test-cov

bump-patch:
	uv run bump-my-version bump patch

bump-minor:
	uv run bump-my-version bump minor

bump-major:
	uv run bump-my-version bump major

clean:
	rm -rf .pytest_cache .ruff_cache .coverage coverage.xml htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
