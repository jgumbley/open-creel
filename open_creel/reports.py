from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

import duckdb

from .pipeline import (
    FILE_CLASS_UID,
    FINDING_CLASS_UID,
    NETWORK_CLASS_UID,
    PROCESS_CLASS_UID,
    resolve_uri,
)


def _sql_quote(value: str) -> str:
    return value.replace("'", "''")


def _print_csv_rows(rows: list[tuple[Any, ...]]) -> None:
    writer = csv.writer(sys.stdout, lineterminator="\n")
    for row in rows:
        writer.writerow(row)


def _latest_parquet_file(class_dir: Path) -> Path | None:
    if not class_dir.is_dir():
        return None
    files = sorted(path for path in class_dir.rglob("*.parquet") if path.is_file())
    if not files:
        return None
    return files[-1]


def _parquet_row_count(file_path: Path) -> int:
    parquet_uri = _sql_quote(str(file_path))
    conn = duckdb.connect()
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{parquet_uri}')").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _latest_row_json(file_path: Path) -> str:
    parquet_uri = _sql_quote(str(file_path))
    conn = duckdb.connect()
    try:
        rel = conn.execute(f"SELECT * FROM read_parquet('{parquet_uri}') ORDER BY time DESC LIMIT 1")
        row = rel.fetchone()
        if row is None:
            return "{}"
        cols = [col[0] for col in rel.description]
        return json.dumps(dict(zip(cols, row)), separators=(",", ":"), default=str)
    finally:
        conn.close()


def _print_zero_result(prefix: str, row_label: str, empty_message: str) -> None:
    print(f"{row_label}=0")
    print(f"{prefix}_file=(none)")
    print(empty_message)


def silver_show_latest(silver_uri: str) -> int:
    silver_root = resolve_uri(silver_uri)
    for class_uid in (NETWORK_CLASS_UID, PROCESS_CLASS_UID, FILE_CLASS_UID):
        print(f"class_uid={class_uid}")
        class_dir = silver_root / f"class_uid={class_uid}"
        file_path = _latest_parquet_file(class_dir)
        if file_path is None:
            _print_zero_result("silver", "silver_rows", "no silver records present")
            continue

        print(f"silver_file={file_path}")
        row_count = _parquet_row_count(file_path)
        print(f"silver_rows={row_count}")
        if row_count == 0:
            print("no silver records present")
            continue
        print(_latest_row_json(file_path))
    return 0


def silver_network_summary(silver_uri: str) -> int:
    silver_root = resolve_uri(silver_uri)
    class_dir = silver_root / f"class_uid={NETWORK_CLASS_UID}"
    file_path = _latest_parquet_file(class_dir)
    if file_path is None:
        print("network_rows=0")
        print("network_file=(none)")
        print("no network records present")
        return 0

    parquet_uri = _sql_quote(str(file_path))
    print(f"network_file={file_path}")

    conn = duckdb.connect()
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{parquet_uri}')").fetchone()
        network_rows = int(row[0]) if row else 0

        describe_rows = conn.execute(f"DESCRIBE SELECT * FROM read_parquet('{parquet_uri}')").fetchall()
        columns = {col[0] for col in describe_rows}
        has_actor = "actor" in columns

        actor_attributed_rows = 0
        if has_actor:
            actor_row = conn.execute(
                f"SELECT COUNT(*) FROM read_parquet('{parquet_uri}') WHERE actor.process IS NOT NULL"
            ).fetchone()
            actor_attributed_rows = int(actor_row[0]) if actor_row else 0

        print(f"network_rows={network_rows}")
        print(f"actor_attributed_rows={actor_attributed_rows}")

        print("top_dst_hostnames=hostname,hits")
        rows = conn.execute(
            f"""
            SELECT dst_endpoint.hostname AS hostname, COUNT(*) AS hits
            FROM read_parquet('{parquet_uri}')
            WHERE dst_endpoint.hostname IS NOT NULL
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 10
            """
        ).fetchall()
        _print_csv_rows(rows)

        print("top_dst_ips=ip,hits")
        rows = conn.execute(
            f"""
            SELECT dst_endpoint.ip AS ip, COUNT(*) AS hits
            FROM read_parquet('{parquet_uri}')
            WHERE dst_endpoint.ip IS NOT NULL
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 10
            """
        ).fetchall()
        _print_csv_rows(rows)

        print("top_dst_ports=port,hits")
        rows = conn.execute(
            f"""
            SELECT CAST(dst_endpoint.port AS VARCHAR) AS port, COUNT(*) AS hits
            FROM read_parquet('{parquet_uri}')
            WHERE dst_endpoint.port IS NOT NULL
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 10
            """
        ).fetchall()
        _print_csv_rows(rows)

        print("top_actor_processes=process,hits")
        if has_actor:
            rows = conn.execute(
                f"""
                SELECT
                    CASE
                        WHEN actor.process.name IS NOT NULL THEN actor.process.name
                        WHEN actor.process.pid IS NOT NULL THEN 'pid-' || CAST(actor.process.pid AS VARCHAR)
                        ELSE 'unknown'
                    END AS process_name,
                    COUNT(*) AS hits
                FROM read_parquet('{parquet_uri}')
                WHERE actor.process IS NOT NULL
                GROUP BY 1
                ORDER BY 2 DESC, 1 ASC
                LIMIT 10
                """
            ).fetchall()
            _print_csv_rows(rows)
    finally:
        conn.close()

    return 0


def silver_network_top_dst_hour(silver_uri: str) -> int:
    silver_root = resolve_uri(silver_uri)
    class_dir = silver_root / f"class_uid={NETWORK_CLASS_UID}"
    file_path = _latest_parquet_file(class_dir)
    if file_path is None:
        print("network_rows=0")
        print("network_file=(none)")
        print("no network records present")
        return 0

    parquet_uri = _sql_quote(str(file_path))
    print(f"network_file={file_path}")
    print("top_dst_ips_last_hour=ip,total_bytes")

    conn = duckdb.connect()
    try:
        rows = conn.execute(
            f"""
            WITH t AS (
                SELECT * FROM read_parquet('{parquet_uri}')
            ),
            b AS (
                SELECT MAX(time) AS max_time_ms FROM t
            )
            SELECT
                t.dst_endpoint.ip AS ip,
                SUM(COALESCE(t.traffic.bytes, 0)) AS total_bytes
            FROM t, b
            WHERE t.time >= b.max_time_ms - 3600000
              AND t.dst_endpoint.ip IS NOT NULL
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 10
            """
        ).fetchall()
        _print_csv_rows(rows)
    finally:
        conn.close()

    return 0


def silver_domain_check(silver_uri: str, domain: str) -> int:
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        raise ValueError("domain must be non-empty")

    silver_root = resolve_uri(silver_uri)
    class_dir = silver_root / f"class_uid={NETWORK_CLASS_UID}"
    if not class_dir.is_dir() or not any(class_dir.rglob("*.parquet")):
        print(f"domain={normalized_domain}")
        print("network_exact_hits=0")
        print("network_like_hits=0")
        print("matching_network_hostnames=hostname,hits")
        return 0

    pattern = _sql_quote(str(class_dir / "date=*" / "*.parquet"))
    domain_sql = _sql_quote(normalized_domain)

    conn = duckdb.connect()
    try:
        exact_row = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM read_parquet('{pattern}')
            WHERE lower(coalesce(dst_endpoint.hostname, '')) = '{domain_sql}'
            """
        ).fetchone()
        like_row = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM read_parquet('{pattern}')
            WHERE lower(coalesce(dst_endpoint.hostname, '')) LIKE '%{domain_sql}%'
            """
        ).fetchone()

        exact_hits = int(exact_row[0]) if exact_row else 0
        like_hits = int(like_row[0]) if like_row else 0

        print(f"domain={normalized_domain}")
        print(f"network_exact_hits={exact_hits}")
        print(f"network_like_hits={like_hits}")
        print("matching_network_hostnames=hostname,hits")

        rows = conn.execute(
            f"""
            SELECT dst_endpoint.hostname AS hostname, COUNT(*) AS hits
            FROM read_parquet('{pattern}')
            WHERE lower(coalesce(dst_endpoint.hostname, '')) LIKE '%{domain_sql}%'
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 20
            """
        ).fetchall()
        _print_csv_rows(rows)
    finally:
        conn.close()

    return 0


def gold_show_latest(gold_uri: str) -> int:
    gold_root = resolve_uri(gold_uri)
    class_dir = gold_root / f"class_uid={FINDING_CLASS_UID}"
    file_path = _latest_parquet_file(class_dir)
    if file_path is None:
        _print_zero_result("gold", "gold_rows", "no gold detections present")
        return 0

    print(f"gold_file={file_path}")
    row_count = _parquet_row_count(file_path)
    print(f"gold_rows={row_count}")
    if row_count == 0:
        print("no gold detections present")
        return 0

    print(_latest_row_json(file_path))
    return 0


def gold_list(gold_uri: str) -> int:
    gold_root = resolve_uri(gold_uri)
    class_dir = gold_root / f"class_uid={FINDING_CLASS_UID}"
    file_path = _latest_parquet_file(class_dir)
    if file_path is None:
        _print_zero_result("gold", "gold_rows", "no gold detections present")
        return 0

    print(f"gold_file={file_path}")
    row_count = _parquet_row_count(file_path)
    print(f"gold_rows={row_count}")
    if row_count == 0:
        print("no gold detections present")
        return 0

    parquet_uri = _sql_quote(str(file_path))
    conn = duckdb.connect()
    try:
        rel = conn.execute(f"SELECT * FROM read_parquet('{parquet_uri}') ORDER BY time ASC")
        cols = [col[0] for col in rel.description]
        rows = rel.fetchall()
        for idx, row in enumerate(rows, start=1):
            payload = json.dumps(dict(zip(cols, row)), separators=(",", ":"), default=str)
            print(f"{idx}\t{payload}")
    finally:
        conn.close()

    return 0


def gold_list_severity_ge3(gold_uri: str) -> int:
    gold_root = resolve_uri(gold_uri)
    class_dir = gold_root / f"class_uid={FINDING_CLASS_UID}"
    file_path = _latest_parquet_file(class_dir)
    if file_path is None:
        _print_zero_result("gold", "gold_rows", "no gold detections present")
        return 0

    parquet_uri = _sql_quote(str(file_path))
    print(f"gold_file={file_path}")
    print("severity_ge3=time,severity_id,rule_uid,title")

    conn = duckdb.connect()
    try:
        rows = conn.execute(
            f"""
            SELECT
                time,
                severity_id,
                finding_info.uid AS rule_uid,
                finding_info.title AS title
            FROM read_parquet('{parquet_uri}')
            WHERE severity_id >= 3
            ORDER BY time DESC
            """
        ).fetchall()
        _print_csv_rows(rows)
    finally:
        conn.close()

    return 0


def bronze_dns_domain_check(bronze_dns_uri: str, domain: str) -> int:
    normalized_domain = domain.strip().lower()
    if not normalized_domain:
        raise ValueError("domain must be non-empty")

    dns_path = resolve_uri(bronze_dns_uri)
    if not dns_path.is_file():
        print(f"domain={normalized_domain}")
        print("dns_exact_hits=0")
        print("dns_like_hits=0")
        print("matching_dns_queries=query,hits")
        return 0

    dns_sql = _sql_quote(str(dns_path))
    domain_sql = _sql_quote(normalized_domain)

    conn = duckdb.connect()
    try:
        exact_row = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM read_ndjson_auto('{dns_sql}')
            WHERE lower(coalesce(query, '')) = '{domain_sql}'
            """
        ).fetchone()
        like_row = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM read_ndjson_auto('{dns_sql}')
            WHERE lower(coalesce(query, '')) LIKE '%{domain_sql}%'
            """
        ).fetchone()

        exact_hits = int(exact_row[0]) if exact_row else 0
        like_hits = int(like_row[0]) if like_row else 0

        print(f"domain={normalized_domain}")
        print(f"dns_exact_hits={exact_hits}")
        print(f"dns_like_hits={like_hits}")
        print("matching_dns_queries=query,hits")

        rows = conn.execute(
            f"""
            SELECT query, COUNT(*) AS hits
            FROM read_ndjson_auto('{dns_sql}')
            WHERE lower(coalesce(query, '')) LIKE '%{domain_sql}%'
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT 20
            """
        ).fetchall()
        _print_csv_rows(rows)
    finally:
        conn.close()

    return 0
