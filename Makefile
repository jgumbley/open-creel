.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make vendor/gondolin Clone Gondolin from GitHub into vendor/gondolin"
	@echo "  make provision       Provision baseline infra + Gondolin OpenClaw runtime + bronze proof + guest hello task"
	@echo "  make restart-openclaw-journal  Restart OpenClaw journal collector service (sudo prompt)"
	@echo "  make lint            Run Ansible syntax-check + Ruff lint checks"
	@echo "  make typecheck       Run Ty static type checks"
	@echo "  make test            Run Python unit tests"
	@echo "  make bronze          Show bronze Zeek + eBPF + OpenClaw logs"
	@echo "  make silver          Map bronze Zeek/eBPF -> OCSF silver"
	@echo "  make silver-show-latest  Show latest mapped OCSF silver record (alias: silver-proof)"
	@echo "  make silver-network-summary  Summarize OCSF silver network activity records"
	@echo "  make silver-network-top-dst-hour  Top destination IPs by bytes in the latest hour (alias: silver-top-dst-hour)"
	@echo "  make silver-domain-check DOMAIN=example.com  Search silver network hostnames for a domain"
	@echo "  make gold            Map bronze Zeek/eBPF -> OCSF silver and gold detections"
	@echo "  make gold-show-latest  Show latest mapped OCSF gold detection record (alias: gold-proof)"
	@echo "  make gold-list       List all mapped OCSF gold detection records"
	@echo "  make gold-list-severity-ge3  List gold detections where severity_id >= 3 (alias: gold-severity-ge3)"
	@echo "  make bronze-dns-domain-check DOMAIN=example.com  Search bronze DNS queries for a domain"
	@echo "  make clean-silver    Remove generated silver output"
	@echo "  make clean-gold      Remove generated gold output"
	$(call success)

include common.mk

HOSTNAME := $(shell hostname)
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR
PYTHON ?= uv run --python .venv/bin/python
BRONZE_CONN_URI ?= /var/lib/open-creel/data/bronze/zeek/conn.log
BRONZE_DNS_URI ?= /var/lib/open-creel/data/bronze/zeek/dns.log
BRONZE_HTTP_URI ?= /var/lib/open-creel/data/bronze/zeek/http.log
BRONZE_SSL_URI ?= /var/lib/open-creel/data/bronze/zeek/ssl.log
BRONZE_NOTICE_URI ?= /var/lib/open-creel/data/bronze/zeek/notice.log
BRONZE_EBPF_EXEC_URI ?= /var/lib/open-creel/data/bronze/ebpf/exec.log
BRONZE_EBPF_FILEACCESS_URI ?= /var/lib/open-creel/data/bronze/ebpf/fileaccess.log
BRONZE_EBPF_CONNECT_URI ?= /var/lib/open-creel/data/bronze/ebpf/connect.log
BRONZE_OPENCLAW_RUNTIME_URI ?= /var/lib/open-creel/data/bronze/openclaw/runtime.log
BRONZE_OPENCLAW_AUDIT_URI ?= /var/lib/open-creel/data/bronze/openclaw/audit.log
BRONZE_OPENCLAW_MESSAGES_URI ?= /var/lib/open-creel/data/bronze/openclaw/messages.log
BRONZE_OPENCLAW_TOOL_CALLS_URI ?= /var/lib/open-creel/data/bronze/openclaw/tool_calls.log
BRONZE_OPENCLAW_APPROVALS_URI ?= /var/lib/open-creel/data/bronze/openclaw/approvals.log
BRONZE_OPENCLAW_SKILLS_URI ?= /var/lib/open-creel/data/bronze/openclaw/skills.log
BRONZE_OPENCLAW_AUTH_URI ?= /var/lib/open-creel/data/bronze/openclaw/auth.log
SILVER_ROOT_URI ?= /tmp/open-creel/data/silver/ocsf
GOLD_ROOT_URI ?= /tmp/open-creel/data/gold/ocsf
PART_NAME ?= part-00000.parquet
DOMAIN ?=
GONDOLIN_HOST_DIR ?= vendor/gondolin/host
GONDOLIN_CLI ?= $(GONDOLIN_HOST_DIR)/dist/bin/gondolin.js
GONDOLIN_REPO ?= https://github.com/earendil-works/gondolin.git
CLAW_GATEWAY_HOST ?= 127.0.0.1
CLAW_GATEWAY_PORT ?= 38080
ANSIBLE_LOCAL_TEMP ?= /tmp/open-creel-ansible/local
ANSIBLE_REMOTE_TEMP ?= /tmp/open-creel-ansible/remote
ANSIBLE_PLAYBOOK = ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook

.PHONY: infra provision restart-openclaw-journal lint typecheck test bronze silver silver-show-latest silver-proof silver-network-summary silver-network-top-dst-hour silver-top-dst-hour silver-domain-check gold gold-show-latest gold-proof gold-list gold-list-severity-ge3 gold-severity-ge3 bronze-dns-domain-check clean-silver clean-gold

infra:
	$(ANSIBLE_PLAYBOOK) provision/creel.yml -c local -K
	$(call success)

vendor/gondolin: vendor
	git clone "$(GONDOLIN_REPO)" vendor/gondolin
	$(call success)

vendor:
	mkdir -p vendor
	$(call success)

provision:
	$(MAKE) vendor/gondolin
	$(ANSIBLE_PLAYBOOK) provision/claw.yml -c local -K -e "openclaw_gateway_host=$(CLAW_GATEWAY_HOST)" -e "openclaw_gateway_port=$(CLAW_GATEWAY_PORT)"
	$(MAKE) bronze
	$(call success)

$(GONDOLIN_HOST_DIR)/node_modules: vendor/gondolin
	cd "$(GONDOLIN_HOST_DIR)" && npm install
	$(call success)

$(GONDOLIN_CLI): $(GONDOLIN_HOST_DIR)/node_modules
	cd "$(GONDOLIN_HOST_DIR)" && npm run build
	$(call success)

restart-openclaw-journal:
	sudo systemctl restart open-creel-openclaw-journal.service
	$(call success)

bronze:
	ls -lah /var/lib/open-creel/data/bronze/zeek
	tail -n 1 "$(BRONZE_CONN_URI)"
	tail -n 1 "$(BRONZE_DNS_URI)"
	tail -n 1 "$(BRONZE_HTTP_URI)"
	tail -n 1 "$(BRONZE_SSL_URI)"
	tail -n 1 "$(BRONZE_NOTICE_URI)"
	ls -lah /var/lib/open-creel/data/bronze/ebpf
	tail -n 1 "$(BRONZE_EBPF_EXEC_URI)"
	tail -n 1 "$(BRONZE_EBPF_FILEACCESS_URI)"
	tail -n 1 "$(BRONZE_EBPF_CONNECT_URI)"
	ls -lah /var/lib/open-creel/data/bronze/openclaw
	tail -n 1 "$(BRONZE_OPENCLAW_RUNTIME_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_AUDIT_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_MESSAGES_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_TOOL_CALLS_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_APPROVALS_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_SKILLS_URI)"
	tail -n 1 "$(BRONZE_OPENCLAW_AUTH_URI)"
	$(call success)

silver: .venv/
	$(PYTHON) -m open_creel.cli silver --bronze-conn-uri "$(BRONZE_CONN_URI)" --bronze-dns-uri "$(BRONZE_DNS_URI)" --bronze-http-uri "$(BRONZE_HTTP_URI)" --bronze-ssl-uri "$(BRONZE_SSL_URI)" --bronze-ebpf-exec-uri "$(BRONZE_EBPF_EXEC_URI)" --bronze-ebpf-fileaccess-uri "$(BRONZE_EBPF_FILEACCESS_URI)" --bronze-ebpf-connect-uri "$(BRONZE_EBPF_CONNECT_URI)" --silver-uri "$(SILVER_ROOT_URI)" --part-name "$(PART_NAME)"
	$(call success)

silver-show-latest: .venv/
	$(PYTHON) -m open_creel.cli silver-show-latest --silver-uri "$(SILVER_ROOT_URI)"
	$(call success)

silver-proof: silver-show-latest

silver-network-summary: .venv/
	$(PYTHON) -m open_creel.cli silver-network-summary --silver-uri "$(SILVER_ROOT_URI)"
	$(call success)

silver-network-top-dst-hour: .venv/
	$(PYTHON) -m open_creel.cli silver-network-top-dst-hour --silver-uri "$(SILVER_ROOT_URI)"
	$(call success)

silver-top-dst-hour: silver-network-top-dst-hour

silver-domain-check: .venv/
	$(PYTHON) -m open_creel.cli silver-domain-check --silver-uri "$(SILVER_ROOT_URI)" --domain "$(DOMAIN)"
	$(call success)

gold: .venv/
	$(PYTHON) -m open_creel.cli gold --bronze-conn-uri "$(BRONZE_CONN_URI)" --bronze-dns-uri "$(BRONZE_DNS_URI)" --bronze-http-uri "$(BRONZE_HTTP_URI)" --bronze-ssl-uri "$(BRONZE_SSL_URI)" --bronze-ebpf-exec-uri "$(BRONZE_EBPF_EXEC_URI)" --bronze-ebpf-fileaccess-uri "$(BRONZE_EBPF_FILEACCESS_URI)" --bronze-ebpf-connect-uri "$(BRONZE_EBPF_CONNECT_URI)" --silver-uri "$(SILVER_ROOT_URI)" --gold-uri "$(GOLD_ROOT_URI)" --part-name "$(PART_NAME)"
	$(call success)

gold-show-latest: .venv/
	$(PYTHON) -m open_creel.cli gold-show-latest --gold-uri "$(GOLD_ROOT_URI)"
	$(call success)

gold-proof: gold-show-latest

gold-list: .venv/
	$(PYTHON) -m open_creel.cli gold-list --gold-uri "$(GOLD_ROOT_URI)"
	$(call success)

gold-list-severity-ge3: .venv/
	$(PYTHON) -m open_creel.cli gold-list-severity-ge3 --gold-uri "$(GOLD_ROOT_URI)"
	$(call success)

gold-severity-ge3: gold-list-severity-ge3

bronze-dns-domain-check: .venv/
	$(PYTHON) -m open_creel.cli bronze-dns-domain-check --bronze-dns-uri "$(BRONZE_DNS_URI)" --domain "$(DOMAIN)"
	$(call success)

clean-silver:
	rm -rf "$(SILVER_ROOT_URI)"
	$(call success)

clean-gold:
	rm -rf "$(GOLD_ROOT_URI)"
	$(call success)
