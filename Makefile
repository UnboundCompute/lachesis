PYTHON ?= python3

.PHONY: check parity

## Run the maintained test suite used by CI.
check: parity

parity:
	$(PYTHON) -m pytest -q
