.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make bronze          Show bronze Zeek logs (sudo)"

include common.mk

HOSTNAME := $(shell hostname)

.PHONY: infra bronze

infra:
	ansible-playbook creel.yml -c local -K

bronze:
	sudo ls -lah /var/lib/open-creel/data/bronze/zeek
	sudo tail -n 1 /var/lib/open-creel/data/bronze/zeek/conn.log
