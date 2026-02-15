#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OCSF_VERSION = "1.7.0"

NETWORK_CATEGORY_UID = 4
NETWORK_CLASS_UID = 4001
NETWORK_ACTIVITY_ID = 6
NETWORK_SEVERITY_ID = 1
NETWORK_TYPE_UID = NETWORK_CLASS_UID * 100 + NETWORK_ACTIVITY_ID

FINDING_CATEGORY_UID = 2
FINDING_CLASS_UID = 2004
FINDING_ACTIVITY_ID = 1
FINDING_SEVERITY_LOW_ID = 2
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_ID

DNS_COVERAGE_RULE_UID = "gold_dns_names_not_covered"
DNS_COVERAGE_RULE_NAME = "New DNS Names Outside Existing Coverage"

MAPPED_ZEEK_KEYS = {
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "ip_proto",
    "local_orig",
    "local_resp",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "duration",
}


def resolve_uri(uri: str) -> Path:
    if uri.startswith("dbfs:/"):
        return Path("/dbfs") / uri[len("dbfs:/") :].lstrip("/")
    return Path(uri)


def as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def direction_id(local_orig: Any, local_resp: Any) -> int:
    if local_orig is True and local_resp is False:
        return 2
    if local_orig is False and local_resp is True:
        return 1
    if local_orig is True and local_resp is True:
        return 4
    return 0


def map_conn_event(record: dict[str, Any], raw_line: str, bronze_uri: str) -> tuple[str, float, dict[str, Any]]:
    ts = as_float(record.get("ts"))
    if ts is None:
        raise ValueError("required Zeek field 'ts' is missing or invalid")

    time_ms = int(ts * 1000)
    event: dict[str, Any] = {
        "time": time_ms,
        "activity_id": NETWORK_ACTIVITY_ID,
        "category_uid": NETWORK_CATEGORY_UID,
        "class_uid": NETWORK_CLASS_UID,
        "severity_id": NETWORK_SEVERITY_ID,
        "type_uid": NETWORK_TYPE_UID,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "open-creel",
                "vendor_name": "open-creel",
            },
            "log_name": "zeek.conn",
            "log_provider": "zeek",
            "log_source": bronze_uri,
            "original_time": time_ms,
        },
        "raw_data": raw_line.rstrip("\n"),
    }

    src_ip = record.get("id.orig_h")
    src_port = as_int(record.get("id.orig_p"))
    if src_ip is not None or src_port is not None:
        src_endpoint: dict[str, Any] = {}
        if src_ip is not None:
            src_endpoint["ip"] = src_ip
        if src_port is not None:
            src_endpoint["port"] = src_port
        event["src_endpoint"] = src_endpoint

    dst_ip = record.get("id.resp_h")
    dst_port = as_int(record.get("id.resp_p"))
    if dst_ip is not None or dst_port is not None:
        dst_endpoint: dict[str, Any] = {}
        if dst_ip is not None:
            dst_endpoint["ip"] = dst_ip
        if dst_port is not None:
            dst_endpoint["port"] = dst_port
        event["dst_endpoint"] = dst_endpoint

    connection_info: dict[str, Any] = {
        "direction_id": direction_id(record.get("local_orig"), record.get("local_resp"))
    }
    uid = record.get("uid")
    if uid is not None:
        connection_info["uid"] = uid
    proto = record.get("proto")
    if isinstance(proto, str) and proto:
        connection_info["protocol_name"] = proto.lower()
    proto_num = as_int(record.get("ip_proto"))
    if proto_num is not None:
        connection_info["protocol_num"] = proto_num
    event["connection_info"] = connection_info

    traffic: dict[str, Any] = {}
    orig_bytes = as_int(record.get("orig_bytes"))
    resp_bytes = as_int(record.get("resp_bytes"))
    orig_pkts = as_int(record.get("orig_pkts"))
    resp_pkts = as_int(record.get("resp_pkts"))

    if orig_bytes is not None:
        traffic["bytes_out"] = orig_bytes
    if resp_bytes is not None:
        traffic["bytes_in"] = resp_bytes
    if orig_bytes is not None and resp_bytes is not None:
        traffic["bytes"] = orig_bytes + resp_bytes
    if orig_pkts is not None:
        traffic["packets_out"] = orig_pkts
    if resp_pkts is not None:
        traffic["packets_in"] = resp_pkts
    if orig_pkts is not None and resp_pkts is not None:
        traffic["packets"] = orig_pkts + resp_pkts
    if traffic:
        event["traffic"] = traffic

    duration_seconds = as_float(record.get("duration"))
    if duration_seconds is not None:
        duration_ms = max(0, int(duration_seconds * 1000))
        event["duration"] = duration_ms
        event["end_time"] = time_ms + duration_ms

    unmapped = {key: value for key, value in record.items() if key not in MAPPED_ZEEK_KEYS}
    if unmapped:
        event["unmapped"] = unmapped

    partition_date = datetime.fromtimestamp(time_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    return partition_date, ts, event


def normalize_dns_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def load_dns_index(
    bronze_path: Path,
) -> tuple[dict[tuple[str, str], list[tuple[float, float, str]]], list[str], float | None]:
    dns_path = bronze_path.with_name("dns.log")
    if not dns_path.exists():
        raise FileNotFoundError(f"dns input does not exist: {dns_path}")

    index: dict[tuple[str, str], list[tuple[float, float, str]]] = defaultdict(list)
    dns_names: list[str] = []
    seen_dns_names: set[str] = set()
    latest_dns_ts: float | None = None
    with dns_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{dns_path}:{line_number}: invalid JSON ({exc.msg})") from exc

            if not isinstance(record, dict):
                raise ValueError(f"{dns_path}:{line_number}: expected JSON object")

            ts = as_float(record.get("ts"))
            if ts is None:
                raise ValueError(f"{dns_path}:{line_number}: required field 'ts' is missing or invalid")
            if latest_dns_ts is None or ts > latest_dns_ts:
                latest_dns_ts = ts

            query = record.get("query")
            normalized_query = normalize_dns_name(query) if isinstance(query, str) else ""
            if normalized_query and normalized_query not in seen_dns_names:
                seen_dns_names.add(normalized_query)
                dns_names.append(normalized_query)

            if not isinstance(query, str) or not query:
                continue

            orig_host = record.get("id.orig_h")
            if not isinstance(orig_host, str) or not orig_host:
                continue

            answers = record.get("answers")
            if not isinstance(answers, list) or not answers:
                continue

            ttls = record.get("TTLs")
            ttl_values: list[float | None] = []
            if isinstance(ttls, list):
                for ttl in ttls:
                    ttl_values.append(as_float(ttl))

            for idx, answer in enumerate(answers):
                if not isinstance(answer, str) or not answer:
                    continue
                try:
                    resolved_ip = str(ipaddress.ip_address(answer))
                except ValueError:
                    continue

                ttl = ttl_values[idx] if idx < len(ttl_values) else None
                expires_at = ts + max(0.0, ttl if ttl is not None else 0.0)
                index[(orig_host, resolved_ip)].append((ts, expires_at, query))

    for values in index.values():
        values.sort(key=lambda item: item[0])
    return index, dns_names, latest_dns_ts


def resolve_hostname(
    dns_index: dict[tuple[str, str], list[tuple[float, float, str]]],
    src_ip: Any,
    dst_ip: Any,
    conn_ts: float,
) -> str | None:
    if not isinstance(src_ip, str) or not src_ip:
        return None
    if not isinstance(dst_ip, str) or not dst_ip:
        return None

    candidates = dns_index.get((src_ip, dst_ip))
    if not candidates:
        return None

    for dns_ts, expires_at, query in reversed(candidates):
        if dns_ts > conn_ts:
            continue
        if conn_ts <= expires_at:
            return query
    return None


def dns_name_is_covered(name: str, existing_names: set[str]) -> bool:
    for existing_name in existing_names:
        if name == existing_name:
            return True
        if name.endswith(f".{existing_name}"):
            return True
    return False


def find_uncovered_dns_name_additions(dns_names: list[str]) -> tuple[list[str], list[str]]:
    existing_names: list[str] = []
    existing_lookup: set[str] = set()
    new_names: list[str] = []

    for dns_name in dns_names:
        normalized = normalize_dns_name(dns_name)
        if not normalized or normalized in existing_lookup:
            continue
        if existing_lookup and not dns_name_is_covered(normalized, existing_lookup):
            new_names.append(normalized)
        existing_names.append(normalized)
        existing_lookup.add(normalized)

    new_name_lookup = set(new_names)
    covered_names = [name for name in existing_names if name not in new_name_lookup]
    return covered_names, new_names


def map_dns_name_coverage_detection_event(
    bronze_uri: str,
    detection_time_ms: int,
    covered_names: list[str],
    new_names: list[str],
) -> dict[str, Any]:
    return {
        "time": detection_time_ms,
        "activity_id": FINDING_ACTIVITY_ID,
        "category_uid": FINDING_CATEGORY_UID,
        "class_uid": FINDING_CLASS_UID,
        "severity_id": FINDING_SEVERITY_LOW_ID,
        "type_uid": FINDING_TYPE_UID,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "open-creel",
                "vendor_name": "open-creel",
            },
            "log_name": "open-creel.gold.dns",
            "log_provider": "open-creel",
            "log_source": bronze_uri,
            "original_time": detection_time_ms,
        },
        "finding_info": {
            "title": DNS_COVERAGE_RULE_NAME,
            "desc": "New DNS names were observed that are not covered by existing names in this ingest batch.",
            "uid": DNS_COVERAGE_RULE_UID,
        },
        "unmapped": {
            "existing_dns_names": covered_names,
            "new_dns_names": new_names,
            "new_dns_name_count": len(new_names),
            "rule_uid": DNS_COVERAGE_RULE_UID,
        },
    }


def write_gold_dns_detection(
    bronze_uri: str,
    gold_root: Path,
    part_name: str,
    dns_names: list[str],
    latest_dns_ts: float | None,
) -> int:
    class_root = gold_root / f"class_uid={FINDING_CLASS_UID}"
    if class_root.exists():
        shutil.rmtree(class_root)

    covered_names, new_names = find_uncovered_dns_name_additions(dns_names)
    if not new_names:
        return 0

    detection_ts = latest_dns_ts if latest_dns_ts is not None else datetime.now(tz=timezone.utc).timestamp()
    detection_time_ms = int(detection_ts * 1000)
    event = map_dns_name_coverage_detection_event(
        bronze_uri=bronze_uri,
        detection_time_ms=detection_time_ms,
        covered_names=covered_names,
        new_names=new_names,
    )

    partition_date = datetime.fromtimestamp(detection_time_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    out_path = class_root / f"date={partition_date}" / part_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True))
        handle.write("\n")
    return 1


def run(bronze_uri: str, silver_uri: str, gold_uri: str | None, part_name: str) -> int:
    bronze_path = resolve_uri(bronze_uri)
    silver_root = resolve_uri(silver_uri)
    silver_class_root = silver_root / f"class_uid={NETWORK_CLASS_UID}"
    gold_root = resolve_uri(gold_uri) if gold_uri else None

    if not bronze_path.exists():
        raise FileNotFoundError(f"bronze input does not exist: {bronze_path}")

    dns_index, dns_names, latest_dns_ts = load_dns_index(bronze_path)

    # Idempotent run semantics: rebuild this class partition from bronze each run.
    if silver_class_root.exists():
        shutil.rmtree(silver_class_root)
    silver_class_root.mkdir(parents=True, exist_ok=True)

    outputs: dict[Path, Any] = {}
    processed = 0

    try:
        with bronze_path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{bronze_path}:{line_number}: invalid JSON ({exc.msg})") from exc

                if not isinstance(record, dict):
                    raise ValueError(f"{bronze_path}:{line_number}: expected JSON object")

                partition_date, conn_ts, event = map_conn_event(record, raw_line, bronze_uri)

                resolved_name = resolve_hostname(
                    dns_index=dns_index,
                    src_ip=record.get("id.orig_h"),
                    dst_ip=record.get("id.resp_h"),
                    conn_ts=conn_ts,
                )
                if resolved_name and "dst_endpoint" in event:
                    event["dst_endpoint"]["hostname"] = resolved_name

                out_path = silver_class_root / f"date={partition_date}" / part_name
                if out_path not in outputs:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    outputs[out_path] = out_path.open("w", encoding="utf-8")
                outputs[out_path].write(json.dumps(event, separators=(",", ":"), sort_keys=True))
                outputs[out_path].write("\n")
                processed += 1
    finally:
        for output in outputs.values():
            output.close()

    gold_detections = 0
    if gold_root is not None:
        gold_detections = write_gold_dns_detection(
            bronze_uri=bronze_uri,
            gold_root=gold_root,
            part_name=part_name,
            dns_names=dns_names,
            latest_dns_ts=latest_dns_ts,
        )

    print(
        "worker complete",
        f"processed={processed}",
        f"output_files={len(outputs)}",
        f"silver_root={silver_root}",
        f"gold_detections={gold_detections}",
        f"gold_root={gold_root}" if gold_root is not None else "gold_root=disabled",
    )
    return processed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Map Zeek conn.log JSON lines to OCSF network_activity JSONL and optional gold detections."
    )
    parser.add_argument("--bronze-uri", required=True, help="Input conn.log path or dbfs:/ URI.")
    parser.add_argument("--silver-uri", required=True, help="Output silver root path or dbfs:/ URI.")
    parser.add_argument("--gold-uri", help="Output gold root path or dbfs:/ URI.")
    parser.add_argument("--part-name", default="part-00000.jsonl", help="Output part filename per partition.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run(args.bronze_uri, args.silver_uri, args.gold_uri, args.part_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
