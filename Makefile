.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make bronze          Show bronze Zeek + eBPF logs"
	@echo "  make silver          Run stub spawner to map bronze Zeek/eBPF -> OCSF silver"
	@echo "  make silver-proof    Show latest mapped OCSF silver record"
	@echo "  make silver-network-summary  Summarize OCSF silver network activity records"
	@echo "  make gold            Run stub spawner with gold detection rules"
	@echo "  make gold-proof      Show latest mapped OCSF gold detection record"
	@echo "  make gold-list       List all mapped OCSF gold detection records"
	@echo "  make clean-silver    Remove generated silver output"
	@echo "  make clean-gold      Remove generated gold output"

include common.mk

HOSTNAME := $(shell hostname)
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR
PYTHON ?= uv run --python .venv/bin/python
BRONZE_CONN_URI ?= /var/lib/open-creel/data/bronze/zeek/conn.log
BRONZE_DNS_URI ?= /var/lib/open-creel/data/bronze/zeek/dns.log
BRONZE_EBPF_EXEC_URI ?= /var/lib/open-creel/data/bronze/ebpf/exec.log
BRONZE_EBPF_FILEACCESS_URI ?= /var/lib/open-creel/data/bronze/ebpf/fileaccess.log
BRONZE_EBPF_CONNECT_URI ?= /var/lib/open-creel/data/bronze/ebpf/connect.log
SILVER_ROOT_URI ?= /tmp/open-creel/data/silver/ocsf
GOLD_ROOT_URI ?= /tmp/open-creel/data/gold/ocsf
PART_NAME ?= part-00000.jsonl

.PHONY: infra bronze silver silver-proof silver-network-summary gold gold-proof gold-list clean-silver clean-gold

infra:
	ansible-playbook creel.yml -c local -K

bronze:
	ls -lah /var/lib/open-creel/data/bronze/zeek
	tail -n 1 "$(BRONZE_CONN_URI)"
	tail -n 1 "$(BRONZE_DNS_URI)"
	ls -lah /var/lib/open-creel/data/bronze/ebpf
	tail -n 1 "$(BRONZE_EBPF_EXEC_URI)"
	tail -n 1 "$(BRONZE_EBPF_FILEACCESS_URI)"
	tail -n 1 "$(BRONZE_EBPF_CONNECT_URI)"

silver: .venv/
	$(PYTHON) stub_spawner.py --bronze-conn-uri "$(BRONZE_CONN_URI)" --bronze-dns-uri "$(BRONZE_DNS_URI)" --bronze-ebpf-exec-uri "$(BRONZE_EBPF_EXEC_URI)" --bronze-ebpf-fileaccess-uri "$(BRONZE_EBPF_FILEACCESS_URI)" --bronze-ebpf-connect-uri "$(BRONZE_EBPF_CONNECT_URI)" --silver-uri "$(SILVER_ROOT_URI)" --part-name "$(PART_NAME)"

silver-proof:
	@set -eu; \
	for class_uid in 4001 1007 1001; do \
		class_dir="$(SILVER_ROOT_URI)/class_uid=$$class_uid"; \
		echo "class_uid=$$class_uid"; \
		if [ ! -d "$$class_dir" ]; then \
			echo "silver_rows=0"; \
			echo "silver_file=(none)"; \
			echo "no silver records present"; \
			continue; \
		fi; \
		ls -lah "$$class_dir"; \
		file="$$(find "$$class_dir" -type f -name '*.jsonl' | sort | tail -n 1)"; \
		if [ -z "$$file" ]; then \
			echo "silver_rows=0"; \
			echo "silver_file=(none)"; \
			echo "no silver records present"; \
			continue; \
		fi; \
		echo "silver_file=$$file"; \
		echo "silver_rows=$$(wc -l < "$$file")"; \
		tail -n 1 "$$file"; \
	done

silver-network-summary: .venv/
	@set -eu; \
	class_dir="$(SILVER_ROOT_URI)/class_uid=4001"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "network_rows=0"; \
		echo "network_file=(none)"; \
		echo "no network records present"; \
		exit 0; \
	fi; \
	file="$$(find "$$class_dir" -type f -name '*.jsonl' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "network_rows=0"; \
		echo "network_file=(none)"; \
		echo "no network records present"; \
		exit 0; \
	fi; \
	echo "network_file=$$file"; \
	tmp="$$(mktemp)"; \
	printf '%s\n' \
		'import collections' \
		'import json' \
		'import sys' \
		'' \
		'path = sys.argv[1]' \
		'total = 0' \
		'actor_attributed = 0' \
		'top_hosts = collections.Counter()' \
		'top_ips = collections.Counter()' \
		'top_ports = collections.Counter()' \
		'actor_names = collections.Counter()' \
		'' \
		'with open(path, "r", encoding="utf-8") as handle:' \
		'    for raw in handle:' \
		'        raw = raw.strip()' \
		'        if not raw:' \
		'            continue' \
		'        event = json.loads(raw)' \
		'        total += 1' \
		'        dst = event.get("dst_endpoint") or {}' \
		'        host = dst.get("hostname")' \
		'        ip = dst.get("ip")' \
		'        port = dst.get("port")' \
		'        if isinstance(host, str) and host:' \
		'            top_hosts[host] += 1' \
		'        if isinstance(ip, str) and ip:' \
		'            top_ips[ip] += 1' \
		'        if port is not None:' \
		'            top_ports[str(port)] += 1' \
		'        process = (event.get("actor") or {}).get("process") or {}' \
		'        if process:' \
		'            actor_attributed += 1' \
		'            name = process.get("name")' \
		'            pid = process.get("pid")' \
		'            if isinstance(name, str) and name:' \
		'                actor_names[name] += 1' \
		'            elif pid is not None:' \
		'                actor_names[f"pid-{pid}"] += 1' \
		'            else:' \
		'                actor_names["unknown"] += 1' \
		'' \
		'print(f"network_rows={total}")' \
		'print(f"actor_attributed_rows={actor_attributed}")' \
		'print("top_dst_hostnames=" + json.dumps(top_hosts.most_common(10), separators=(",", ":")))' \
		'print("top_dst_ips=" + json.dumps(top_ips.most_common(10), separators=(",", ":")))' \
		'print("top_dst_ports=" + json.dumps(top_ports.most_common(10), separators=(",", ":")))' \
		'print("top_actor_processes=" + json.dumps(actor_names.most_common(10), separators=(",", ":")))' \
		> "$$tmp"; \
	.venv/bin/python "$$tmp" "$$file"; \
	rm -f "$$tmp"

gold: .venv/
	$(PYTHON) stub_spawner.py --bronze-conn-uri "$(BRONZE_CONN_URI)" --bronze-dns-uri "$(BRONZE_DNS_URI)" --bronze-ebpf-exec-uri "$(BRONZE_EBPF_EXEC_URI)" --bronze-ebpf-fileaccess-uri "$(BRONZE_EBPF_FILEACCESS_URI)" --bronze-ebpf-connect-uri "$(BRONZE_EBPF_CONNECT_URI)" --silver-uri "$(SILVER_ROOT_URI)" --gold-uri "$(GOLD_ROOT_URI)" --part-name "$(PART_NAME)"

gold-proof:
	@set -eu; \
	class_dir="$(GOLD_ROOT_URI)/class_uid=2004"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold detections present"; \
		exit 0; \
	fi; \
	ls -lah "$$class_dir"; \
	file="$$(find "$$class_dir" -type f -name '*.jsonl' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold detections present"; \
		exit 0; \
	fi; \
	echo "gold_file=$$file"; \
	echo "gold_rows=$$(wc -l < "$$file")"; \
	tail -n 1 "$$file"

gold-list:
	@set -eu; \
	class_dir="$(GOLD_ROOT_URI)/class_uid=2004"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold detections present"; \
		exit 0; \
	fi; \
	file="$$(find "$$class_dir" -type f -name '*.jsonl' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold detections present"; \
		exit 0; \
	fi; \
	echo "gold_file=$$file"; \
	echo "gold_rows=$$(wc -l < "$$file")"; \
	nl -ba "$$file"

clean-silver:
	rm -rf "$(SILVER_ROOT_URI)"

clean-gold:
	rm -rf "$(GOLD_ROOT_URI)"
