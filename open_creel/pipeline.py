#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import shlex
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import duckdb

OCSF_VERSION = "1.7.0"

SYSTEM_ACTIVITY_CATEGORY_UID = 1
NETWORK_CATEGORY_UID = 4
FINDING_CATEGORY_UID = 2

NETWORK_CLASS_UID = 4001
NETWORK_ACTIVITY_ID = 6
NETWORK_SEVERITY_ID = 1
NETWORK_TYPE_UID = NETWORK_CLASS_UID * 100 + NETWORK_ACTIVITY_ID

PROCESS_CLASS_UID = 1007
PROCESS_ACTIVITY_ID = 1
PROCESS_SEVERITY_ID = 1
PROCESS_TYPE_UID = PROCESS_CLASS_UID * 100 + PROCESS_ACTIVITY_ID

FILE_CLASS_UID = 1001
FILE_ACTIVITY_ID = 1
FILE_SEVERITY_ID = 1
FILE_TYPE_UID = FILE_CLASS_UID * 100 + FILE_ACTIVITY_ID

FINDING_CLASS_UID = 2004
FINDING_ACTIVITY_ID = 1
FINDING_SEVERITY_LOW_ID = 2
FINDING_SEVERITY_MEDIUM_ID = 3
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_ID

DNS_COVERAGE_RULE_UID = "gold_dns_names_not_covered"
DNS_COVERAGE_RULE_NAME = "New DNS Names Outside Existing Coverage"

UNEXPECTED_CHILD_RULE_UID = "gold_unexpected_child_process"
UNEXPECTED_CHILD_RULE_NAME = "Unexpected Child Process from Agent Tree"

SENSITIVE_FILE_RULE_UID = "gold_sensitive_file_read"
SENSITIVE_FILE_RULE_NAME = "Sensitive File Read by Unexpected Process"

CONNECT_JOIN_WINDOW_SECONDS = 10.0
MAX_PROCESS_LINEAGE_DEPTH = 32
MIN_REASONABLE_EPOCH_SECONDS = 946684800.0  # 2000-01-01T00:00:00Z

TIME_FIELD_SCALES = (
    ("ts", 1.0),
    ("timestamp", 1.0),
    ("time", 1.0),
    ("event_time", 1.0),
    ("time_s", 1.0),
    ("timestamp_s", 1.0),
    ("time_ms", 0.001),
    ("timestamp_ms", 0.001),
    ("time_ns", 0.000000001),
    ("timestamp_ns", 0.000000001),
)
TIME_FIELD_KEYS = {field for field, _ in TIME_FIELD_SCALES}

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

MAPPED_ZEEK_HTTP_KEYS = {
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "method",
    "host",
    "uri",
    "status_code",
    "status_msg",
    "user_agent",
    "request_body_len",
    "response_body_len",
}

MAPPED_ZEEK_SSL_KEYS = {
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "server_name",
    "version",
    "cipher",
    "curve",
    "resumed",
}

MAPPED_EXEC_KEYS = TIME_FIELD_KEYS | {
    "pid",
    "tgid",
    "ppid",
    "uid",
    "binary",
    "exe",
    "pathname",
    "path",
    "filename",
    "argv",
    "args",
    "cwd",
    "pwd",
    "workdir",
    "comm",
    "process_name",
    "name",
}

MAPPED_FILEACCESS_KEYS = TIME_FIELD_KEYS | {
    "pid",
    "tgid",
    "ppid",
    "uid",
    "path",
    "file",
    "filename",
    "target_path",
    "flags",
    "open_flags",
    "operation",
    "activity_name",
    "op",
    "read",
    "write",
    "create",
    "truncate",
    "old_path",
    "oldname",
    "new_path",
    "newname",
    "dst_path",
    "src_path",
    "source_path",
    "destination_path",
    "comm",
    "process_name",
    "name",
    "binary",
    "exe",
    "argv",
    "args",
}

MAPPED_CONNECT_KEYS = TIME_FIELD_KEYS | {
    "pid",
    "tgid",
    "dst_ip",
    "daddr",
    "remote_ip",
    "id.resp_h",
    "dst_port",
    "dport",
    "remote_port",
    "id.resp_p",
    "comm",
    "process_name",
    "name",
    "binary",
    "exe",
}

AGENT_TREE_MARKERS = (
    "codex",
    "open-creel",
    "open_creel",
    "open_creel.cli",
    "pane.sh",
    "sandbox",
)

AGENT_TREE_CWD_PREFIXES = (
    "/home/system/wip",
    "/tmp/open-creel",
    "/var/lib/open-creel",
)

DETECTION_RULES_CONFIG_PATH = Path(__file__).with_name("config.json")

SENSITIVE_FILE_PROCESS_ALLOWLIST = {
    "bash",
    "cat",
    "codex",
    "git",
    "head",
    "less",
    "make",
    "open-creel",
    "python",
    "python3",
    "rg",
    "sed",
    "sh",
    "tail",
    "uv",
}

@lru_cache(maxsize=1)
def load_detection_rules() -> tuple[frozenset[str], tuple[str, ...]]:
    try:
        raw = json.loads(DETECTION_RULES_CONFIG_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{DETECTION_RULES_CONFIG_PATH}: failed to read detection rules") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{DETECTION_RULES_CONFIG_PATH}: invalid JSON ({exc.msg})") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"{DETECTION_RULES_CONFIG_PATH}: expected JSON object")

    unexpected_child_raw = raw.get("unexpected_child_process_allowlist")
    if not isinstance(unexpected_child_raw, list):
        raise ValueError(
            f"{DETECTION_RULES_CONFIG_PATH}: unexpected_child_process_allowlist must be a list of strings"
        )
    unexpected_child_allowlist: set[str] = set()
    for idx, value in enumerate(unexpected_child_raw):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"{DETECTION_RULES_CONFIG_PATH}: unexpected_child_process_allowlist[{idx}] must be a non-empty string"
            )
        unexpected_child_allowlist.add(value.strip().lower())

    sensitive_paths_raw = raw.get("sensitive_path_fragments")
    if not isinstance(sensitive_paths_raw, list):
        raise ValueError(f"{DETECTION_RULES_CONFIG_PATH}: sensitive_path_fragments must be a list of strings")
    sensitive_path_fragments: list[str] = []
    for idx, value in enumerate(sensitive_paths_raw):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"{DETECTION_RULES_CONFIG_PATH}: sensitive_path_fragments[{idx}] must be a non-empty string"
            )
        sensitive_path_fragments.append(value.strip().lower())

    return frozenset(unexpected_child_allowlist), tuple(sensitive_path_fragments)


def unexpected_child_process_allowlist() -> frozenset[str]:
    allowlist, _ = load_detection_rules()
    return allowlist


def sensitive_path_fragments() -> tuple[str, ...]:
    _, fragments = load_detection_rules()
    return fragments


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


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def first_value(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key not in record:
            continue
        value = record.get(key)
        if value is None:
            continue
        if isinstance(value, str) and not value:
            continue
        return value
    return None


def first_int(record: dict[str, Any], keys: list[str]) -> int | None:
    return as_int(first_value(record, keys))


def first_str(record: dict[str, Any], keys: list[str]) -> str | None:
    value = first_value(record, keys)
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if normalized else None


def normalize_argv(value: Any) -> list[str]:
    def _normalize_argv_token(token: Any) -> str | None:
        normalized = str(token).strip()
        if not normalized:
            return None
        lowered = normalized.lower()
        if lowered in {"(null)", "<null>", "(fault)", "<fault>"}:
            return None
        return normalized

    if value is None:
        return []
    if isinstance(value, list):
        argv: list[str] = []
        for item in value:
            normalized = _normalize_argv_token(item)
            if normalized is not None:
                argv.append(normalized)
        return argv
    if isinstance(value, str):
        if not value.strip():
            return []
        try:
            parts = [part for part in shlex.split(value) if part]
        except ValueError:
            parts = [value]
        argv = []
        for part in parts:
            normalized = _normalize_argv_token(part)
            if normalized is not None:
                argv.append(normalized)
        return argv
    normalized = _normalize_argv_token(value)
    return [normalized] if normalized is not None else []


def normalize_process_name(comm: str | None, binary: str | None, argv: list[str]) -> str | None:
    if comm:
        return Path(comm).name
    if binary:
        return Path(binary).name
    if argv:
        return Path(argv[0]).name
    return None


def record_time_seconds(record: dict[str, Any], source_path: Path, line_number: int) -> float:
    for field, scale in TIME_FIELD_SCALES:
        if field not in record:
            continue
        raw = as_float(record.get(field))
        if raw is None:
            raise ValueError(f"{source_path}:{line_number}: time field '{field}' is missing or invalid")
        return normalize_epoch_seconds(raw * scale)
    expected_fields = ", ".join(field for field, _ in TIME_FIELD_SCALES)
    raise ValueError(f"{source_path}:{line_number}: required time field is missing ({expected_fields})")


@lru_cache(maxsize=1)
def read_boot_time_seconds() -> float | None:
    stat_path = Path("/proc/stat")
    try:
        with stat_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.startswith("btime "):
                    continue
                parts = line.strip().split()
                if len(parts) != 2:
                    break
                boot_time = as_float(parts[1])
                return boot_time
    except OSError:
        return None
    return None


def normalize_epoch_seconds(seconds: float) -> float:
    if seconds >= MIN_REASONABLE_EPOCH_SECONDS:
        return seconds
    boot_time_seconds = read_boot_time_seconds()
    if boot_time_seconds is None:
        return seconds
    adjusted = boot_time_seconds + seconds
    if adjusted >= MIN_REASONABLE_EPOCH_SECONDS:
        return adjusted
    return seconds


def partition_date_from_seconds(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def read_json_lines(path: Path) -> list[tuple[int, str, dict[str, Any]]]:
    rows: list[tuple[int, str, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON ({exc.msg})") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append((line_number, raw_line, record))
    return rows


def metadata(log_name: str, log_provider: str, log_source: str, time_ms: int) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "product": {
            "name": "open-creel",
            "vendor_name": "open-creel",
        },
        "log_name": log_name,
        "log_provider": log_provider,
        "log_source": log_source,
        "original_time": time_ms,
    }


def direction_id(local_orig: Any, local_resp: Any) -> int:
    if local_orig is True and local_resp is False:
        return 2
    if local_orig is False and local_resp is True:
        return 1
    if local_orig is True and local_resp is True:
        return 4
    return 0


def normalize_dns_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def normalize_http_host(host: str) -> str:
    trimmed = host.strip().lower()
    if not trimmed:
        return ""
    if trimmed.startswith("["):
        closing = trimmed.find("]")
        if closing != -1:
            return trimmed[1:closing]
        return trimmed
    if ":" in trimmed:
        return trimmed.split(":", maxsplit=1)[0]
    return trimmed


def load_dns_index(
    dns_path: Path,
) -> tuple[dict[tuple[str, str], list[tuple[float, float, str]]], list[str], float | None]:
    index: dict[tuple[str, str], list[tuple[float, float, str]]] = defaultdict(list)
    dns_names: list[str] = []
    seen_dns_names: set[str] = set()
    latest_dns_ts: float | None = None

    for line_number, _, record in read_json_lines(dns_path):
        ts = record_time_seconds(record, dns_path, line_number)
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


def load_http_index(http_path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    for line_number, _, record in read_json_lines(http_path):
        ts = record_time_seconds(record, http_path, line_number)
        uid = first_str(record, ["uid"])
        if uid is None:
            continue

        observation: dict[str, Any] = {"ts": ts}
        host = first_str(record, ["host"])
        if host is not None:
            normalized_host = normalize_http_host(host)
            if normalized_host:
                observation["host"] = normalized_host

        method = first_str(record, ["method"])
        if method is not None:
            observation["method"] = method.upper()

        uri = first_str(record, ["uri"])
        if uri is not None:
            observation["uri"] = uri

        status_code = first_int(record, ["status_code"])
        if status_code is not None:
            observation["status_code"] = status_code

        status_msg = first_str(record, ["status_msg"])
        if status_msg is not None:
            observation["status_msg"] = status_msg

        user_agent = first_str(record, ["user_agent"])
        if user_agent is not None:
            observation["user_agent"] = user_agent

        request_body_len = first_int(record, ["request_body_len"])
        if request_body_len is not None:
            observation["request_body_len"] = request_body_len

        response_body_len = first_int(record, ["response_body_len"])
        if response_body_len is not None:
            observation["response_body_len"] = response_body_len

        extras = {key: value for key, value in record.items() if key not in MAPPED_ZEEK_HTTP_KEYS}
        if extras:
            observation["record_extras"] = extras

        existing = index.get(uid)
        existing_ts = as_float(existing.get("ts")) if existing is not None else None
        if existing_ts is None or ts >= existing_ts:
            index[uid] = observation

    return index


def load_ssl_index(ssl_path: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    for line_number, _, record in read_json_lines(ssl_path):
        ts = record_time_seconds(record, ssl_path, line_number)
        uid = first_str(record, ["uid"])
        if uid is None:
            continue

        observation: dict[str, Any] = {"ts": ts}

        server_name = first_str(record, ["server_name"])
        if server_name is not None:
            normalized_server_name = normalize_dns_name(server_name)
            if normalized_server_name:
                observation["server_name"] = normalized_server_name

        tls_version = first_str(record, ["version"])
        if tls_version is not None:
            observation["version"] = tls_version

        cipher = first_str(record, ["cipher"])
        if cipher is not None:
            observation["cipher"] = cipher

        curve = first_str(record, ["curve"])
        if curve is not None:
            observation["curve"] = curve

        resumed = as_bool(record.get("resumed"))
        if resumed is not None:
            observation["resumed"] = resumed

        extras = {key: value for key, value in record.items() if key not in MAPPED_ZEEK_SSL_KEYS}
        if extras:
            observation["record_extras"] = extras

        existing = index.get(uid)
        existing_ts = as_float(existing.get("ts")) if existing is not None else None
        if existing_ts is None or ts >= existing_ts:
            index[uid] = observation

    return index


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


def canonical_process_label(entry: dict[str, Any]) -> str:
    name = entry.get("name")
    if isinstance(name, str) and name:
        return Path(name).name.lower()
    binary = entry.get("binary")
    if isinstance(binary, str) and binary:
        return Path(binary).name.lower()
    argv = entry.get("argv")
    if isinstance(argv, list) and argv:
        return Path(str(argv[0])).name.lower()
    return ""


def compact_process(entry: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    pid = as_int(entry.get("pid"))
    if pid is not None:
        compact["pid"] = pid
    ppid = as_int(entry.get("ppid"))
    if ppid is not None:
        compact["ppid"] = ppid
    uid = as_int(entry.get("uid"))
    if uid is not None:
        compact["uid"] = uid
    name = entry.get("name")
    if isinstance(name, str) and name:
        compact["name"] = name
    binary = entry.get("binary")
    if isinstance(binary, str) and binary:
        compact["binary"] = binary
    cwd = entry.get("cwd")
    if isinstance(cwd, str) and cwd:
        compact["cwd"] = cwd
    return compact


def process_to_ocsf(entry: dict[str, Any], include_lineage: bool) -> dict[str, Any]:
    process: dict[str, Any] = {}
    pid = as_int(entry.get("pid"))
    if pid is not None:
        process["pid"] = pid
    uid = as_int(entry.get("uid"))
    if uid is not None:
        process["uid"] = uid
    name = entry.get("name")
    if isinstance(name, str) and name:
        process["name"] = name
    binary = entry.get("binary")
    if isinstance(binary, str) and binary:
        process["file"] = {"path": binary}
    argv = entry.get("argv")
    if isinstance(argv, list) and argv:
        process["cmd_line"] = " ".join(shlex.quote(str(arg)) for arg in argv)
    cwd = entry.get("cwd")
    if isinstance(cwd, str) and cwd:
        process["cwd"] = cwd
    if include_lineage:
        lineage = entry.get("lineage")
        if isinstance(lineage, list) and lineage:
            process["lineage"] = lineage
    return process


def build_lineage(ppid: int | None, process_catalog: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    lineage: list[dict[str, Any]] = []
    visited: set[int] = set()
    current = ppid
    while current is not None and current > 0 and current not in visited and len(lineage) < MAX_PROCESS_LINEAGE_DEPTH:
        visited.add(current)
        parent = process_catalog.get(current)
        if parent is None:
            break
        lineage.append(compact_process(parent))
        current = as_int(parent.get("ppid"))
    return lineage


def parse_exec_observation(
    record: dict[str, Any],
    line_number: int,
    raw_line: str,
    exec_path: Path,
) -> dict[str, Any]:
    ts = record_time_seconds(record, exec_path, line_number)

    pid = first_int(record, ["pid", "tgid"])
    if pid is None:
        raise ValueError(f"{exec_path}:{line_number}: required field 'pid' is missing or invalid")

    ppid = first_int(record, ["ppid"])
    uid = first_int(record, ["uid"])
    binary = first_str(record, ["binary", "exe", "pathname", "path", "filename"])
    argv = normalize_argv(first_value(record, ["argv", "args"]))
    cwd = first_str(record, ["cwd", "pwd", "workdir"])
    comm = first_str(record, ["comm", "process_name", "name"])
    if binary is None and argv:
        binary = argv[0]
    name = normalize_process_name(comm, binary, argv)

    return {
        "ts": ts,
        "line_number": line_number,
        "raw_line": raw_line,
        "record": record,
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "name": name,
        "binary": binary,
        "argv": argv,
        "cwd": cwd,
    }


def map_exec_event(observation: dict[str, Any], exec_uri: str) -> tuple[str, dict[str, Any]]:
    ts = observation["ts"]
    time_ms = int(ts * 1000)
    event: dict[str, Any] = {
        "time": time_ms,
        "activity_id": PROCESS_ACTIVITY_ID,
        "category_uid": SYSTEM_ACTIVITY_CATEGORY_UID,
        "class_uid": PROCESS_CLASS_UID,
        "severity_id": PROCESS_SEVERITY_ID,
        "type_uid": PROCESS_TYPE_UID,
        "metadata": metadata("ebpf.exec", "ebpf", exec_uri, time_ms),
        "raw_data": observation["raw_line"].rstrip("\n"),
    }

    process = process_to_ocsf(observation, include_lineage=True)
    if process:
        event["process"] = process

    lineage = observation.get("lineage")
    if isinstance(lineage, list) and lineage:
        event["parent_process"] = lineage[0]

    unmapped = {
        key: value
        for key, value in observation["record"].items()
        if key not in MAPPED_EXEC_KEYS
    }
    if unmapped:
        event["unmapped"] = unmapped

    return partition_date_from_seconds(ts), event


def build_process_activity_bundle(
    exec_path: Path,
    exec_uri: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]], dict[int, dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    for line_number, raw_line, record in read_json_lines(exec_path):
        observation = parse_exec_observation(record, line_number, raw_line, exec_path)
        observations.append(observation)

    observations.sort(key=lambda item: (item["ts"], item["line_number"]))
    process_catalog: dict[int, dict[str, Any]] = {}
    events: list[tuple[str, dict[str, Any]]] = []

    for observation in observations:
        observation["lineage"] = build_lineage(as_int(observation.get("ppid")), process_catalog)
        event_partition, event = map_exec_event(observation, exec_uri)
        events.append((event_partition, event))

        process_catalog[observation["pid"]] = {
            "pid": observation.get("pid"),
            "ppid": observation.get("ppid"),
            "uid": observation.get("uid"),
            "name": observation.get("name"),
            "binary": observation.get("binary"),
            "argv": observation.get("argv"),
            "cwd": observation.get("cwd"),
            "lineage": observation.get("lineage"),
            "ts": observation.get("ts"),
        }
    return events, observations, process_catalog


def decode_open_operations(record: dict[str, Any], flags: Any) -> list[str]:
    operations: set[str] = set()

    read_flag = as_bool(record.get("read"))
    write_flag = as_bool(record.get("write"))
    create_flag = as_bool(record.get("create"))
    truncate_flag = as_bool(record.get("truncate"))

    if read_flag is True:
        operations.add("read")
    if write_flag is True:
        operations.add("write")
    if create_flag is True:
        operations.add("create")
    if truncate_flag is True:
        operations.add("truncate")

    numeric_flags = as_int(flags)
    if numeric_flags is not None:
        access_mode = numeric_flags & 0x3
        if access_mode in (0, 2):
            operations.add("read")
        if access_mode in (1, 2):
            operations.add("write")
        if numeric_flags & 0x40:
            operations.add("create")
        if numeric_flags & 0x200:
            operations.add("truncate")

    if isinstance(flags, str):
        lowered = flags.lower()
        if "rdonly" in lowered or "rdwr" in lowered:
            operations.add("read")
        if "wronly" in lowered or "rdwr" in lowered or "append" in lowered:
            operations.add("write")
        if "creat" in lowered:
            operations.add("create")
        if "trunc" in lowered:
            operations.add("truncate")

    return sorted(operations)


def normalize_file_activity_name(value: Any) -> str:
    if not isinstance(value, str):
        return "open"
    normalized = value.strip().lower()
    if not normalized:
        return "open"
    if normalized in {"open", "openat"}:
        return "open"
    if normalized in {"delete", "unlink", "unlinkat", "remove"}:
        return "delete"
    if normalized in {"rename", "renameat", "renameat2", "move"}:
        return "rename"
    return normalized


def parse_file_observation(
    record: dict[str, Any],
    line_number: int,
    raw_line: str,
    fileaccess_path: Path,
    process_catalog: dict[int, dict[str, Any]],
) -> dict[str, Any] | None:
    ts = record_time_seconds(record, fileaccess_path, line_number)

    pid = first_int(record, ["pid", "tgid"])
    if pid is None:
        raise ValueError(f"{fileaccess_path}:{line_number}: required field 'pid' is missing or invalid")

    activity_name = normalize_file_activity_name(first_value(record, ["operation", "activity_name", "op"]))
    path = first_str(
        record,
        ["path", "file", "filename", "target_path", "old_path", "oldname", "src_path", "source_path"],
    )
    if path is None:
        return None

    flags = first_value(record, ["flags", "open_flags"])
    operations: list[str]
    if activity_name == "open":
        operations = decode_open_operations(record, flags)
    else:
        operations = [activity_name]
    target_path = first_str(record, ["new_path", "newname", "dst_path", "destination_path"])
    process_state = process_catalog.get(pid, {})

    ppid = first_int(record, ["ppid"])
    if ppid is None:
        ppid = as_int(process_state.get("ppid"))
    uid = first_int(record, ["uid"])
    if uid is None:
        uid = as_int(process_state.get("uid"))
    name = first_str(record, ["comm", "process_name", "name"])
    if name is None:
        state_name = process_state.get("name")
        if isinstance(state_name, str):
            name = state_name
    binary = first_str(record, ["binary", "exe"])
    if binary is None:
        state_binary = process_state.get("binary")
        if isinstance(state_binary, str):
            binary = state_binary
    argv = normalize_argv(first_value(record, ["argv", "args"]))
    if not argv:
        state_argv = process_state.get("argv")
        if isinstance(state_argv, list):
            argv = [str(item) for item in state_argv]
    if name is None:
        name = normalize_process_name(None, binary, argv)

    lineage = process_state.get("lineage")
    return {
        "ts": ts,
        "line_number": line_number,
        "raw_line": raw_line,
        "record": record,
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "name": name,
        "binary": binary,
        "argv": argv,
        "path": path,
        "target_path": target_path,
        "flags": flags,
        "activity_name": activity_name,
        "operations": operations,
        "lineage": lineage if isinstance(lineage, list) else [],
    }


def map_file_activity_event(observation: dict[str, Any], fileaccess_uri: str) -> tuple[str, dict[str, Any]]:
    ts = observation["ts"]
    time_ms = int(ts * 1000)
    event: dict[str, Any] = {
        "time": time_ms,
        "activity_id": FILE_ACTIVITY_ID,
        "category_uid": SYSTEM_ACTIVITY_CATEGORY_UID,
        "class_uid": FILE_CLASS_UID,
        "severity_id": FILE_SEVERITY_ID,
        "type_uid": FILE_TYPE_UID,
        "metadata": metadata("ebpf.fileaccess", "ebpf", fileaccess_uri, time_ms),
        "activity_name": observation["activity_name"],
        "file": {"path": observation["path"]},
        "raw_data": observation["raw_line"].rstrip("\n"),
    }

    process = process_to_ocsf(observation, include_lineage=True)
    if process:
        event["process"] = process

    unmapped: dict[str, Any] = {}
    if observation["flags"] is not None:
        unmapped["open_flags"] = observation["flags"]
    target_path = observation.get("target_path")
    if isinstance(target_path, str) and target_path:
        unmapped["target_path"] = target_path
    if observation["operations"]:
        unmapped["file_ops"] = observation["operations"]
    extras = {
        key: value
        for key, value in observation["record"].items()
        if key not in MAPPED_FILEACCESS_KEYS
    }
    if extras:
        unmapped["record_extras"] = extras
    if unmapped:
        event["unmapped"] = unmapped

    return partition_date_from_seconds(ts), event


def build_file_activity_events(
    fileaccess_path: Path,
    fileaccess_uri: str,
    process_catalog: dict[int, dict[str, Any]],
) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    observations: list[dict[str, Any]] = []
    events: list[tuple[str, dict[str, Any]]] = []
    for line_number, raw_line, record in read_json_lines(fileaccess_path):
        observation = parse_file_observation(record, line_number, raw_line, fileaccess_path, process_catalog)
        if observation is None:
            continue
        observations.append(observation)
        events.append(map_file_activity_event(observation, fileaccess_uri))
    return events, observations


def normalize_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_connect_observation(
    record: dict[str, Any],
    line_number: int,
    connect_path: Path,
    process_catalog: dict[int, dict[str, Any]],
) -> dict[str, Any] | None:
    ts = record_time_seconds(record, connect_path, line_number)

    pid = first_int(record, ["pid", "tgid"])
    if pid is None:
        raise ValueError(f"{connect_path}:{line_number}: required field 'pid' is missing or invalid")

    dst_ip = normalize_ip(first_str(record, ["dst_ip", "daddr", "remote_ip", "id.resp_h"]))
    dst_port = first_int(record, ["dst_port", "dport", "remote_port", "id.resp_p"])
    if dst_ip is None or dst_port is None:
        return None

    process_state = process_catalog.get(pid, {})
    name = first_str(record, ["comm", "process_name", "name"])
    if name is None:
        state_name = process_state.get("name")
        if isinstance(state_name, str):
            name = state_name
    binary = first_str(record, ["binary", "exe"])
    if binary is None:
        state_binary = process_state.get("binary")
        if isinstance(state_binary, str):
            binary = state_binary

    return {
        "ts": ts,
        "pid": pid,
        "name": name,
        "binary": binary,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "record": record,
    }


def load_connect_index(
    connect_path: Path,
    process_catalog: dict[int, dict[str, Any]],
) -> dict[tuple[str, int], list[dict[str, Any]]]:
    index: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for line_number, _, record in read_json_lines(connect_path):
        observation = parse_connect_observation(record, line_number, connect_path, process_catalog)
        if observation is None:
            continue
        index[(observation["dst_ip"], observation["dst_port"])].append(observation)

    for values in index.values():
        values.sort(key=lambda item: item["ts"])
    return index


def resolve_connect_actor(
    connect_index: dict[tuple[str, int], list[dict[str, Any]]],
    dst_ip: Any,
    dst_port: Any,
    conn_ts: float,
) -> dict[str, Any] | None:
    if not isinstance(dst_ip, str):
        return None
    port = as_int(dst_port)
    if port is None:
        return None
    candidates = connect_index.get((dst_ip, port))
    if not candidates:
        return None
    for candidate in reversed(candidates):
        candidate_ts = candidate["ts"]
        if candidate_ts > conn_ts:
            continue
        if conn_ts - candidate_ts > CONNECT_JOIN_WINDOW_SECONDS:
            continue
        actor: dict[str, Any] = {"pid": candidate["pid"]}
        name = candidate.get("name")
        if isinstance(name, str) and name:
            actor["name"] = name
        else:
            actor["name"] = f"pid-{candidate['pid']}"
        return actor
    return None


def map_conn_event(
    record: dict[str, Any],
    raw_line: str,
    conn_uri: str,
    actor_process: dict[str, Any] | None,
) -> tuple[str, float, dict[str, Any]]:
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
        "metadata": metadata("zeek.conn", "zeek", conn_uri, time_ms),
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

    if actor_process:
        event["actor"] = {"process": actor_process}

    unmapped = {key: value for key, value in record.items() if key not in MAPPED_ZEEK_KEYS}
    if unmapped:
        event["unmapped"] = unmapped

    partition_date = partition_date_from_seconds(ts)
    return partition_date, ts, event


def build_network_activity_events(
    conn_path: Path,
    conn_uri: str,
    dns_index: dict[tuple[str, str], list[tuple[float, float, str]]],
    connect_index: dict[tuple[str, int], list[dict[str, Any]]],
    http_index: dict[str, dict[str, Any]],
    ssl_index: dict[str, dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    for line_number, raw_line, record in read_json_lines(conn_path):
        partition_date, conn_ts, event = map_conn_event(record, raw_line, conn_uri, actor_process=None)

        resolved_name = resolve_hostname(
            dns_index=dns_index,
            src_ip=record.get("id.orig_h"),
            dst_ip=record.get("id.resp_h"),
            conn_ts=conn_ts,
        )
        if resolved_name and "dst_endpoint" in event:
            event["dst_endpoint"]["hostname"] = resolved_name

        uid = first_str(record, ["uid"])
        if uid is not None:
            ssl_observation = ssl_index.get(uid)
            if ssl_observation is not None:
                server_name = ssl_observation.get("server_name")
                if (
                    isinstance(server_name, str)
                    and server_name
                    and "dst_endpoint" in event
                    and "hostname" not in event["dst_endpoint"]
                ):
                    event["dst_endpoint"]["hostname"] = server_name

                ssl_unmapped = {key: value for key, value in ssl_observation.items() if key != "ts"}
                if ssl_unmapped:
                    unmapped = event.get("unmapped")
                    if not isinstance(unmapped, dict):
                        unmapped = {}
                    unmapped["zeek_ssl"] = ssl_unmapped
                    event["unmapped"] = unmapped

            http_observation = http_index.get(uid)
            if http_observation is not None:
                host = http_observation.get("host")
                if (
                    isinstance(host, str)
                    and host
                    and "dst_endpoint" in event
                    and "hostname" not in event["dst_endpoint"]
                ):
                    event["dst_endpoint"]["hostname"] = host

                http_unmapped = {key: value for key, value in http_observation.items() if key != "ts"}
                if http_unmapped:
                    unmapped = event.get("unmapped")
                    if not isinstance(unmapped, dict):
                        unmapped = {}
                    unmapped["zeek_http"] = http_unmapped
                    event["unmapped"] = unmapped

        actor_process = resolve_connect_actor(
            connect_index=connect_index,
            dst_ip=record.get("id.resp_h"),
            dst_port=record.get("id.resp_p"),
            conn_ts=conn_ts,
        )
        if actor_process:
            event["actor"] = {"process": actor_process}

        events.append((partition_date, event))
    return events


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


def map_finding_event(
    *,
    detection_time_ms: int,
    severity_id: int,
    rule_uid: str,
    title: str,
    desc: str,
    log_name: str,
    log_source: str,
    unmapped: dict[str, Any],
    actor_process: dict[str, Any] | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "time": detection_time_ms,
        "activity_id": FINDING_ACTIVITY_ID,
        "category_uid": FINDING_CATEGORY_UID,
        "class_uid": FINDING_CLASS_UID,
        "severity_id": severity_id,
        "type_uid": FINDING_TYPE_UID,
        "metadata": metadata(log_name, "open-creel", log_source, detection_time_ms),
        "finding_info": {
            "title": title,
            "desc": desc,
            "uid": rule_uid,
        },
        "unmapped": unmapped,
    }
    if actor_process:
        event["actor"] = {"process": actor_process}
    if file_path:
        event["file"] = {"path": file_path}
    return event


def build_dns_coverage_findings(
    dns_names: list[str],
    latest_dns_ts: float | None,
    dns_uri: str,
) -> list[dict[str, Any]]:
    covered_names, new_names = find_uncovered_dns_name_additions(dns_names)
    if not new_names:
        return []
    detection_ts = latest_dns_ts if latest_dns_ts is not None else datetime.now(tz=timezone.utc).timestamp()
    detection_time_ms = int(detection_ts * 1000)
    return [
        map_finding_event(
            detection_time_ms=detection_time_ms,
            severity_id=FINDING_SEVERITY_LOW_ID,
            rule_uid=DNS_COVERAGE_RULE_UID,
            title=DNS_COVERAGE_RULE_NAME,
            desc="New DNS names were observed that are not covered by existing names in this ingest batch.",
            log_name="open-creel.gold.dns",
            log_source=dns_uri,
            unmapped={
                "existing_dns_names": covered_names,
                "new_dns_names": new_names,
                "new_dns_name_count": len(new_names),
                "rule_uid": DNS_COVERAGE_RULE_UID,
            },
        )
    ]


def entry_has_agent_marker(entry: dict[str, Any]) -> bool:
    cwd = entry.get("cwd")
    if isinstance(cwd, str):
        for prefix in AGENT_TREE_CWD_PREFIXES:
            if cwd.startswith(prefix):
                return True

    string_values: list[str] = []
    for key in ("name", "binary"):
        value = entry.get(key)
        if isinstance(value, str):
            string_values.append(value)
    argv = entry.get("argv")
    if isinstance(argv, list):
        string_values.extend(str(value) for value in argv)

    for value in string_values:
        lowered = value.lower()
        for marker in AGENT_TREE_MARKERS:
            if marker in lowered:
                return True
    return False


def in_agent_tree(entry: dict[str, Any]) -> bool:
    if entry_has_agent_marker(entry):
        return True
    lineage = entry.get("lineage")
    if not isinstance(lineage, list):
        return False
    for ancestor in lineage:
        if isinstance(ancestor, dict) and entry_has_agent_marker(ancestor):
            return True
    return False


def build_unexpected_child_process_findings(
    exec_observations: list[dict[str, Any]],
    exec_uri: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for observation in exec_observations:
        if not in_agent_tree(observation):
            continue
        process_label = canonical_process_label(observation)
        if not process_label or process_label in unexpected_child_process_allowlist():
            continue

        detection_time_ms = int(observation["ts"] * 1000)
        actor_process = process_to_ocsf(observation, include_lineage=False)
        finding = map_finding_event(
            detection_time_ms=detection_time_ms,
            severity_id=FINDING_SEVERITY_MEDIUM_ID,
            rule_uid=UNEXPECTED_CHILD_RULE_UID,
            title=UNEXPECTED_CHILD_RULE_NAME,
            desc="A process outside the allowlist was spawned from the agent or sandbox process tree.",
            log_name="open-creel.gold.unexpected_child_process",
            log_source=exec_uri,
            actor_process=actor_process if actor_process else None,
            unmapped={
                "rule_uid": UNEXPECTED_CHILD_RULE_UID,
                "pid": observation.get("pid"),
                "ppid": observation.get("ppid"),
                "uid": observation.get("uid"),
                "binary": observation.get("binary"),
                "cwd": observation.get("cwd"),
                "argv": observation.get("argv"),
                "lineage": observation.get("lineage"),
                "process_label": process_label,
            },
        )
        findings.append(finding)
    return findings


def is_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    for fragment in sensitive_path_fragments():
        if fragment in lowered:
            return True
    return False


def build_sensitive_file_access_findings(
    file_observations: list[dict[str, Any]],
    fileaccess_uri: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for observation in file_observations:
        operations = observation.get("operations")
        if not isinstance(operations, list) or "read" not in operations:
            continue
        path = observation.get("path")
        if not isinstance(path, str) or not is_sensitive_path(path):
            continue
        process_label = canonical_process_label(observation)
        if process_label in SENSITIVE_FILE_PROCESS_ALLOWLIST:
            continue

        detection_time_ms = int(observation["ts"] * 1000)
        actor_process = process_to_ocsf(observation, include_lineage=False)
        finding = map_finding_event(
            detection_time_ms=detection_time_ms,
            severity_id=FINDING_SEVERITY_MEDIUM_ID,
            rule_uid=SENSITIVE_FILE_RULE_UID,
            title=SENSITIVE_FILE_RULE_NAME,
            desc="A non-allowlisted process read a sensitive credential or transcript path.",
            log_name="open-creel.gold.sensitive_file_access",
            log_source=fileaccess_uri,
            actor_process=actor_process if actor_process else None,
            file_path=path,
            unmapped={
                "rule_uid": SENSITIVE_FILE_RULE_UID,
                "pid": observation.get("pid"),
                "ppid": observation.get("ppid"),
                "uid": observation.get("uid"),
                "binary": observation.get("binary"),
                "path": path,
                "open_flags": observation.get("flags"),
                "open_ops": operations,
                "process_label": process_label,
            },
        )
        findings.append(finding)
    return findings


def write_parquet_records(out_path: Path, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect()
    try:
        conn.execute("CREATE TEMP TABLE events_json(raw_json VARCHAR)")
        rows = [
            (json.dumps(record, separators=(",", ":"), sort_keys=True),)
            for record in records
        ]
        conn.executemany("INSERT INTO events_json VALUES (?)", rows)
        schema_row = conn.execute(
            "SELECT json_group_structure(raw_json::JSON) FROM events_json"
        ).fetchone()
        schema_json = schema_row[0] if schema_row is not None else None
        if not isinstance(schema_json, str) or not schema_json:
            raise ValueError(f"failed to infer json schema for parquet output: {out_path}")
        schema_sql = schema_json.replace("'", "''")
        parquet_uri = str(out_path).replace("'", "''")
        conn.execute(
            f"""
            COPY (
                WITH typed AS (
                    SELECT raw_json::JSON AS raw_json
                    FROM events_json
                ),
                parsed AS (
                    SELECT from_json(raw_json, '{schema_sql}') AS event
                    FROM typed
                )
                SELECT event.*
                FROM parsed
            ) TO '{parquet_uri}' (FORMAT PARQUET, COMPRESSION ZSTD)
            """
        )
    finally:
        conn.close()
    return len(records)


def write_partitioned_events(
    class_root: Path,
    part_name: str,
    events: list[tuple[str, dict[str, Any]]],
) -> tuple[int, int]:
    partitioned_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for partition_date, event in events:
        partitioned_events[partition_date].append(event)

    written = 0
    output_files = 0
    for partition_date in sorted(partitioned_events):
        out_path = class_root / f"date={partition_date}" / part_name
        written += write_parquet_records(out_path, partitioned_events[partition_date])
        output_files += 1
    return written, output_files


def write_gold_findings(
    gold_root: Path,
    part_name: str,
    findings: list[dict[str, Any]],
) -> int:
    class_root = gold_root / f"class_uid={FINDING_CLASS_UID}"
    if class_root.exists():
        shutil.rmtree(class_root)
    if not findings:
        return 0

    partitioned_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        detection_time_ms = as_int(finding.get("time"))
        if detection_time_ms is None:
            continue
        partition_date = datetime.fromtimestamp(
            detection_time_ms / 1000, tz=timezone.utc
        ).strftime("%Y-%m-%d")
        partitioned_findings[partition_date].append(finding)

    written = 0
    for partition_date in sorted(partitioned_findings):
        out_path = class_root / f"date={partition_date}" / part_name
        written += write_parquet_records(out_path, partitioned_findings[partition_date])
    return written


def run_bronze_to_ocsf_pipeline(
    bronze_conn_uri: str,
    bronze_dns_uri: str,
    bronze_http_uri: str,
    bronze_ssl_uri: str,
    bronze_ebpf_exec_uri: str,
    bronze_ebpf_fileaccess_uri: str,
    bronze_ebpf_connect_uri: str,
    silver_uri: str,
    gold_uri: str | None,
    part_name: str,
) -> int:
    if not part_name.endswith(".parquet"):
        raise ValueError(f"part_name must end with .parquet: {part_name}")

    conn_path = resolve_uri(bronze_conn_uri)
    dns_path = resolve_uri(bronze_dns_uri)
    http_path = resolve_uri(bronze_http_uri)
    ssl_path = resolve_uri(bronze_ssl_uri)
    exec_path = resolve_uri(bronze_ebpf_exec_uri)
    fileaccess_path = resolve_uri(bronze_ebpf_fileaccess_uri)
    connect_path = resolve_uri(bronze_ebpf_connect_uri)
    silver_root = resolve_uri(silver_uri)
    gold_root = resolve_uri(gold_uri) if gold_uri else None

    required_inputs = (
        conn_path,
        dns_path,
        http_path,
        ssl_path,
        exec_path,
        fileaccess_path,
        connect_path,
    )
    for input_path in required_inputs:
        if not input_path.exists():
            raise FileNotFoundError(f"bronze input does not exist: {input_path}")

    dns_index, dns_names, latest_dns_ts = load_dns_index(dns_path)
    http_index = load_http_index(http_path)
    ssl_index = load_ssl_index(ssl_path)
    process_events, exec_observations, process_catalog = build_process_activity_bundle(exec_path, bronze_ebpf_exec_uri)
    connect_index = load_connect_index(connect_path, process_catalog)
    network_events = build_network_activity_events(conn_path, bronze_conn_uri, dns_index, connect_index, http_index, ssl_index)
    file_events, file_observations = build_file_activity_events(fileaccess_path, bronze_ebpf_fileaccess_uri, process_catalog)

    class_roots = {
        NETWORK_CLASS_UID: silver_root / f"class_uid={NETWORK_CLASS_UID}",
        PROCESS_CLASS_UID: silver_root / f"class_uid={PROCESS_CLASS_UID}",
        FILE_CLASS_UID: silver_root / f"class_uid={FILE_CLASS_UID}",
    }

    for class_root in class_roots.values():
        if class_root.exists():
            shutil.rmtree(class_root)
        class_root.mkdir(parents=True, exist_ok=True)

    network_written, network_output_files = write_partitioned_events(
        class_roots[NETWORK_CLASS_UID], part_name, network_events
    )
    process_written, process_output_files = write_partitioned_events(
        class_roots[PROCESS_CLASS_UID], part_name, process_events
    )
    file_written, file_output_files = write_partitioned_events(
        class_roots[FILE_CLASS_UID], part_name, file_events
    )

    gold_detections = 0
    if gold_root is not None:
        findings: list[dict[str, Any]] = []
        findings.extend(build_dns_coverage_findings(dns_names, latest_dns_ts, bronze_dns_uri))
        findings.extend(build_unexpected_child_process_findings(exec_observations, bronze_ebpf_exec_uri))
        findings.extend(build_sensitive_file_access_findings(file_observations, bronze_ebpf_fileaccess_uri))
        gold_detections = write_gold_findings(gold_root, part_name, findings)

    total_processed = network_written + process_written + file_written
    total_output_files = network_output_files + process_output_files + file_output_files
    print(
        "pipeline complete",
        f"network_events={network_written}",
        f"process_events={process_written}",
        f"file_events={file_written}",
        f"processed_total={total_processed}",
        f"silver_output_files={total_output_files}",
        f"silver_root={silver_root}",
        f"gold_detections={gold_detections}",
        f"gold_root={gold_root}" if gold_root is not None else "gold_root=disabled",
    )
    return total_processed
