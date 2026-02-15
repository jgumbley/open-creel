.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make bronze          Show bronze Zeek logs"
	@echo "  make silver          Run stub spawner to map conn.log -> OCSF silver"
	@echo "  make silver-proof    Show latest mapped OCSF silver record"

include common.mk

HOSTNAME := $(shell hostname)
PYTHON ?= uv run --python .venv/bin/python
BRONZE_CONN_URI ?= /var/lib/open-creel/data/bronze/zeek/conn.log
SILVER_ROOT_URI ?= /tmp/open-creel/data/silver/ocsf
PART_NAME ?= part-00000.jsonl

.PHONY: infra bronze silver silver-proof

infra:
	ansible-playbook creel.yml -c local -K

bronze:
	ls -lah /var/lib/open-creel/data/bronze/zeek
	tail -n 1 /var/lib/open-creel/data/bronze/zeek/conn.log

silver: .venv/
	$(PYTHON) stub_spawner.py --bronze-uri "$(BRONZE_CONN_URI)" --silver-uri "$(SILVER_ROOT_URI)" --part-name "$(PART_NAME)"

silver-proof:
	ls -lah "$(SILVER_ROOT_URI)"/class_uid=4001
	tail -n 1 "$$(find "$(SILVER_ROOT_URI)/class_uid=4001" -type f -name '*.jsonl' | sort | tail -n 1)"
