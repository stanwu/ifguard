PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: venv install test run clean

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(BIN)/pip install -e .

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

run:
	@if [ -z "$(IFACE)" ]; then echo "Usage: make run IFACE=eth0 [INTERVAL=10]"; exit 1; fi
	sudo $(BIN)/ifguard-iptop -i $(IFACE) -t $(or $(INTERVAL),10)

clean:
	rm -rf $(VENV) .pytest_cache
