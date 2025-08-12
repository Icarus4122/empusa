.PHONY: build wheel sdist clean

build:
	python -m build

wheel:
	python -m build --wheel

sdist:
	python -m build --sdist

clean:
	rm -rf build dist *.egg-info