.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make bronze          Show bronze Zeek logs"
	@echo "  make silver          Run stub spawner to map conn.log -> OCSF silver"
	@echo "  make silver-proof    Show latest mapped OCSF silver record"
	@echo "  make gold            Run stub spawner with one gold DNS detection rule"
	@echo "  make gold-proof      Show latest mapped OCSF gold detection record"
	@echo "  make clean-silver    Remove generated silver output"
	@echo "  make clean-gold      Remove generated gold output"

include common.mk

HOSTNAME := $(shell hostname)
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR
PYTHON ?= uv run --python .venv/bin/python
BRONZE_CONN_URI ?= /var/lib/open-creel/data/bronze/zeek/conn.log
SILVER_ROOT_URI ?= /tmp/open-creel/data/silver/ocsf
GOLD_ROOT_URI ?= /tmp/open-creel/data/gold/ocsf
PART_NAME ?= part-00000.jsonl

.PHONY: infra bronze silver silver-proof gold gold-proof clean-silver clean-gold

infra:
	ansible-playbook creel.yml -c local -K

bronze:
	ls -lah /var/lib/open-creel/data/bronze/zeek
	tail -n 1 /var/lib/open-creel/data/bronze/zeek/conn.log

silver: .venv/
	$(PYTHON) stub_spawner.py --bronze-uri "$(BRONZE_CONN_URI)" --silver-uri "$(SILVER_ROOT_URI)" --part-name "$(PART_NAME)"

silver-proof:
	ls -lah "$(SILVER_ROOT_URI)"/class_uid=4001
	@set -eu; \
	file="$$(find "$(SILVER_ROOT_URI)/class_uid=4001" -type f -name '*.jsonl' | sort | tail -n 1)"; \
	echo "silver_file=$$file"; \
	echo "silver_rows=$$(wc -l < "$$file")"; \
	tail -n 1 "$$file"

gold: .venv/
	$(PYTHON) stub_spawner.py --bronze-uri "$(BRONZE_CONN_URI)" --silver-uri "$(SILVER_ROOT_URI)" --gold-uri "$(GOLD_ROOT_URI)" --part-name "$(PART_NAME)"

gold-proof:
	ls -lah "$(GOLD_ROOT_URI)"/class_uid=2004
	@set -eu; \
	file="$$(find "$(GOLD_ROOT_URI)/class_uid=2004" -type f -name '*.jsonl' | sort | tail -n 1)"; \
	echo "gold_file=$$file"; \
	echo "gold_rows=$$(wc -l < "$$file")"; \
	tail -n 1 "$$file"

clean-silver:
	rm -rf "$(SILVER_ROOT_URI)"

clean-gold:
	rm -rf "$(GOLD_ROOT_URI)"
