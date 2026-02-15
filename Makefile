.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"

include common.mk

HOSTNAME := $(shell hostname)

.PHONY: infra

infra:
	ansible-playbook creel.yml -c local -K
