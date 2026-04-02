.PHONY: build wheel sdist clean test lint format

build:
	python -m build

wheel:
	python -m build --wheel

sdist:
	python -m build --sdist

test:
	python -m pytest

lint:
	python -m ruff check empusa/ tests/

format:
	python -m ruff format empusa/ tests/

clean:
	rm -rf build dist *.egg-info