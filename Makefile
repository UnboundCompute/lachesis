PYTHON ?= python3

.PHONY: check parity

## Run the compiler/frontend parity gate used by CI.
check: parity

parity:
	$(PYTHON) -m pytest lachesis/frontends/checks.py
