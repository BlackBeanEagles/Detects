.PHONY: install lint fmt type test cov scoreboard check all clean

install:  ## editable install with dev tooling
	python -m pip install -e ".[dev]"

lint:  ## static lint
	ruff check .

fmt:  ## autoformat
	ruff format .
	ruff check --fix .

type:  ## type-check the package
	mypy

test:  ## run the test suite
	pytest

cov:  ## tests with coverage report
	pytest --cov --cov-report=term-missing

scoreboard:  ## run the bundled adversary
	detects scoreboard

check: lint type test  ## everything CI runs

all: fmt check

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage \
	       dist build src/*.egg-info worker.key ledger.jsonl rcpt_*.json
	find . -name __pycache__ -type d -exec rm -rf {} +
