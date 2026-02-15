.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make infra           Run core system setup and install Zeek (sudo/become prompts)"
	@echo "  make bronze          Show bronze Zeek + eBPF logs"
	@echo "  make silver          Run stub spawner to map bronze Zeek/eBPF -> OCSF silver"
	@echo "  make silver-parquet  Materialize silver Parquet files from mapped JSONL"
	@echo "  make silver-proof    Show latest mapped OCSF silver record"
	@echo "  make silver-network-summary  Summarize OCSF silver network activity records"
	@echo "  make silver-top-dst-hour  Top destination IPs by bytes in the latest hour"
	@echo "  make silver-domain-check DOMAIN=example.com  Search silver network hostnames for a domain"
	@echo "  make gold            Run stub spawner with gold detection rules"
	@echo "  make gold-parquet    Materialize gold Parquet files from mapped JSONL"
	@echo "  make gold-proof      Show latest mapped OCSF gold detection record"
	@echo "  make gold-list       List all mapped OCSF gold detection records"
	@echo "  make gold-severity-ge3  List gold detections where severity_id >= 3"
	@echo "  make bronze-dns-domain-check DOMAIN=example.com  Search bronze DNS queries for a domain"
	@echo "  make clean-silver    Remove generated silver output"
	@echo "  make clean-gold      Remove generated gold output"

include common.mk

HOSTNAME := $(shell hostname)
UV_CACHE_DIR ?= $(CURDIR)/.uv-cache
export UV_CACHE_DIR
PYTHON ?= uv run --python .venv/bin/python
VENV_PYTHON ?= .venv/bin/python
BRONZE_CONN_URI ?= /var/lib/open-creel/data/bronze/zeek/conn.log
BRONZE_DNS_URI ?= /var/lib/open-creel/data/bronze/zeek/dns.log
BRONZE_EBPF_EXEC_URI ?= /var/lib/open-creel/data/bronze/ebpf/exec.log
BRONZE_EBPF_FILEACCESS_URI ?= /var/lib/open-creel/data/bronze/ebpf/fileaccess.log
BRONZE_EBPF_CONNECT_URI ?= /var/lib/open-creel/data/bronze/ebpf/connect.log
SILVER_ROOT_URI ?= /tmp/open-creel/data/silver/ocsf
GOLD_ROOT_URI ?= /tmp/open-creel/data/gold/ocsf
PART_NAME ?= part-00000.jsonl
DOMAIN ?=

.PHONY: infra bronze silver silver-parquet silver-proof silver-network-summary silver-top-dst-hour silver-domain-check gold gold-parquet gold-proof gold-list gold-severity-ge3 bronze-dns-domain-check clean-silver clean-gold

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
	$(MAKE) silver-parquet

silver-parquet: .venv/
	@set -eu; \
	for class_uid in 4001 1007 1001; do \
		class_dir="$(SILVER_ROOT_URI)/class_uid=$$class_uid"; \
		if [ ! -d "$$class_dir" ]; then \
			continue; \
		fi; \
		for file in $$(find "$$class_dir" -type f -name '*.jsonl' | sort); do \
			parquet_file="$${file%.jsonl}.parquet"; \
			echo "silver_parquet_file=$$parquet_file"; \
			$(VENV_PYTHON) -c "import duckdb,sys;src=sys.argv[1].replace(\"'\", \"''\");dst=sys.argv[2].replace(\"'\", \"''\");duckdb.sql(f\"COPY (SELECT * FROM read_ndjson_auto('{src}')) TO '{dst}' (FORMAT PARQUET, COMPRESSION ZSTD)\")" "$$file" "$$parquet_file"; \
		done; \
	done

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
	file="$$(find "$$class_dir" -type f -name '*.parquet' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "network_rows=0"; \
		echo "network_file=(none)"; \
		echo "no network parquet records present"; \
		exit 0; \
	fi; \
	echo "network_file=$$file"; \
	network_rows=$$($(VENV_PYTHON) -c "import duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");print(duckdb.sql(f\"SELECT COUNT(*) FROM read_parquet('{path}')\").fetchone()[0])" "$$file"); \
	has_actor=$$($(VENV_PYTHON) -c "import duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");cols={row[0] for row in duckdb.sql(f\"DESCRIBE SELECT * FROM read_parquet('{path}')\").fetchall()};print(1 if 'actor' in cols else 0)" "$$file"); \
	if [ "$$has_actor" = "1" ]; then \
		actor_attributed_rows=$$($(VENV_PYTHON) -c "import duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");print(duckdb.sql(f\"SELECT COUNT(*) FROM read_parquet('{path}') WHERE actor.process IS NOT NULL\").fetchone()[0])" "$$file"); \
	else \
		actor_attributed_rows=0; \
	fi; \
	echo "network_rows=$$network_rows"; \
	echo "actor_attributed_rows=$$actor_attributed_rows"; \
	echo "top_dst_hostnames=hostname,hits"; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"SELECT dst_endpoint.hostname AS hostname, COUNT(*) AS hits FROM read_parquet('{path}') WHERE dst_endpoint.hostname IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"; \
	echo "top_dst_ips=ip,hits"; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"SELECT dst_endpoint.ip AS ip, COUNT(*) AS hits FROM read_parquet('{path}') WHERE dst_endpoint.ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"; \
	echo "top_dst_ports=port,hits"; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"SELECT CAST(dst_endpoint.port AS VARCHAR) AS port, COUNT(*) AS hits FROM read_parquet('{path}') WHERE dst_endpoint.port IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"; \
	echo "top_actor_processes=process,hits"; \
	if [ "$$has_actor" = "1" ]; then \
		$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"SELECT CASE WHEN actor.process.name IS NOT NULL THEN actor.process.name WHEN actor.process.pid IS NOT NULL THEN 'pid-' || CAST(actor.process.pid AS VARCHAR) ELSE 'unknown' END AS process_name, COUNT(*) AS hits FROM read_parquet('{path}') WHERE actor.process IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"; \
	fi

silver-top-dst-hour: .venv/
	@set -eu; \
	class_dir="$(SILVER_ROOT_URI)/class_uid=4001"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "network_rows=0"; \
		echo "network_file=(none)"; \
		echo "no network records present"; \
		exit 0; \
	fi; \
	file="$$(find "$$class_dir" -type f -name '*.parquet' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "network_rows=0"; \
		echo "network_file=(none)"; \
		echo "no network parquet records present"; \
		exit 0; \
	fi; \
	echo "network_file=$$file"; \
	echo "top_dst_ips_last_hour=ip,total_bytes"; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"WITH t AS (SELECT * FROM read_parquet('{path}')), b AS (SELECT MAX(time) AS max_time_ms FROM t) SELECT t.dst_endpoint.ip AS ip, SUM(COALESCE(t.traffic.bytes, 0)) AS total_bytes FROM t, b WHERE t.time >= b.max_time_ms - 3600000 AND t.dst_endpoint.ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"

silver-domain-check: .venv/
	@set -eu; \
	if [ -z "$(DOMAIN)" ]; then \
		echo "DOMAIN is required (example: make silver-domain-check DOMAIN=example.com)"; \
		exit 2; \
	fi; \
	class_dir="$(SILVER_ROOT_URI)/class_uid=4001"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "domain=$(DOMAIN)"; \
		echo "network_exact_hits=0"; \
		echo "network_like_hits=0"; \
		echo "matching_network_hostnames=hostname,hits"; \
		exit 0; \
	fi; \
	if ! find "$$class_dir" -type f -name '*.parquet' | grep -q .; then \
		echo "domain=$(DOMAIN)"; \
		echo "network_exact_hits=0"; \
		echo "network_like_hits=0"; \
		echo "matching_network_hostnames=hostname,hits"; \
		exit 0; \
	fi; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;class_dir=sys.argv[1].rstrip('/');domain=sys.argv[2].strip().lower();domain_sql=domain.replace(\"'\", \"''\");pattern=f\"{class_dir}/date=*/*.parquet\";con=duckdb.connect();exact=con.execute(f\"SELECT COUNT(*) FROM read_parquet('{pattern}') WHERE lower(coalesce(dst_endpoint.hostname,'')) = '{domain_sql}'\").fetchone()[0];like=con.execute(f\"SELECT COUNT(*) FROM read_parquet('{pattern}') WHERE lower(coalesce(dst_endpoint.hostname,'')) LIKE '%{domain_sql}%'\").fetchone()[0];print(f\"domain={domain}\");print(f\"network_exact_hits={exact}\");print(f\"network_like_hits={like}\");print(\"matching_network_hostnames=hostname,hits\");rows=con.execute(f\"SELECT dst_endpoint.hostname AS hostname, COUNT(*) AS hits FROM read_parquet('{pattern}') WHERE lower(coalesce(dst_endpoint.hostname,'')) LIKE '%{domain_sql}%' GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 20\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$class_dir" "$(DOMAIN)"

gold: .venv/
	$(PYTHON) stub_spawner.py --bronze-conn-uri "$(BRONZE_CONN_URI)" --bronze-dns-uri "$(BRONZE_DNS_URI)" --bronze-ebpf-exec-uri "$(BRONZE_EBPF_EXEC_URI)" --bronze-ebpf-fileaccess-uri "$(BRONZE_EBPF_FILEACCESS_URI)" --bronze-ebpf-connect-uri "$(BRONZE_EBPF_CONNECT_URI)" --silver-uri "$(SILVER_ROOT_URI)" --gold-uri "$(GOLD_ROOT_URI)" --part-name "$(PART_NAME)"
	$(MAKE) silver-parquet
	$(MAKE) gold-parquet

gold-parquet: .venv/
	@set -eu; \
	class_dir="$(GOLD_ROOT_URI)/class_uid=2004"; \
	if [ ! -d "$$class_dir" ]; then \
		exit 0; \
	fi; \
	for file in $$(find "$$class_dir" -type f -name '*.jsonl' | sort); do \
		parquet_file="$${file%.jsonl}.parquet"; \
		echo "gold_parquet_file=$$parquet_file"; \
		$(VENV_PYTHON) -c "import duckdb,sys;src=sys.argv[1].replace(\"'\", \"''\");dst=sys.argv[2].replace(\"'\", \"''\");duckdb.sql(f\"COPY (SELECT * FROM read_ndjson_auto('{src}')) TO '{dst}' (FORMAT PARQUET, COMPRESSION ZSTD)\")" "$$file" "$$parquet_file"; \
	done

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

gold-severity-ge3: .venv/
	@set -eu; \
	class_dir="$(GOLD_ROOT_URI)/class_uid=2004"; \
	if [ ! -d "$$class_dir" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold detections present"; \
		exit 0; \
	fi; \
	file="$$(find "$$class_dir" -type f -name '*.parquet' | sort | tail -n 1)"; \
	if [ -z "$$file" ]; then \
		echo "gold_rows=0"; \
		echo "gold_file=(none)"; \
		echo "no gold parquet detections present"; \
		exit 0; \
	fi; \
	echo "gold_file=$$file"; \
	echo "severity_ge3=time,severity_id,rule_uid,title"; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");rows=duckdb.sql(f\"SELECT time, severity_id, finding_info.uid AS rule_uid, finding_info.title AS title FROM read_parquet('{path}') WHERE severity_id >= 3 ORDER BY time DESC\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$$file"

bronze-dns-domain-check: .venv/
	@set -eu; \
	if [ -z "$(DOMAIN)" ]; then \
		echo "DOMAIN is required (example: make bronze-dns-domain-check DOMAIN=example.com)"; \
		exit 2; \
	fi; \
	if [ ! -f "$(BRONZE_DNS_URI)" ]; then \
		echo "domain=$(DOMAIN)"; \
		echo "dns_exact_hits=0"; \
		echo "dns_like_hits=0"; \
		echo "matching_dns_queries=query,hits"; \
		exit 0; \
	fi; \
	$(VENV_PYTHON) -c "import csv,duckdb,sys;path=sys.argv[1].replace(\"'\", \"''\");domain=sys.argv[2].strip().lower();domain_sql=domain.replace(\"'\", \"''\");con=duckdb.connect();exact=con.execute(f\"SELECT COUNT(*) FROM read_ndjson_auto('{path}') WHERE lower(coalesce(query,'')) = '{domain_sql}'\").fetchone()[0];like=con.execute(f\"SELECT COUNT(*) FROM read_ndjson_auto('{path}') WHERE lower(coalesce(query,'')) LIKE '%{domain_sql}%'\").fetchone()[0];print(f\"domain={domain}\");print(f\"dns_exact_hits={exact}\");print(f\"dns_like_hits={like}\");print(\"matching_dns_queries=query,hits\");rows=con.execute(f\"SELECT query, COUNT(*) AS hits FROM read_ndjson_auto('{path}') WHERE lower(coalesce(query,'')) LIKE '%{domain_sql}%' GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 20\").fetchall();w=csv.writer(sys.stdout,lineterminator='\\n');[w.writerow(row) for row in rows]" "$(BRONZE_DNS_URI)" "$(DOMAIN)"

clean-silver:
	rm -rf "$(SILVER_ROOT_URI)"

clean-gold:
	rm -rf "$(GOLD_ROOT_URI)"
