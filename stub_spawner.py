#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Spawn the stub OCSF worker.")
    parser.add_argument("--bronze-conn-uri", required=True, help="Input Zeek conn.log path or dbfs:/ URI.")
    parser.add_argument("--bronze-dns-uri", required=True, help="Input Zeek dns.log path or dbfs:/ URI.")
    parser.add_argument("--bronze-ebpf-exec-uri", required=True, help="Input eBPF exec.log path or dbfs:/ URI.")
    parser.add_argument(
        "--bronze-ebpf-fileaccess-uri",
        required=True,
        help="Input eBPF fileaccess.log path or dbfs:/ URI.",
    )
    parser.add_argument(
        "--bronze-ebpf-connect-uri",
        required=True,
        help="Input eBPF connect.log path or dbfs:/ URI.",
    )
    parser.add_argument("--silver-uri", required=True, help="Output silver root path or dbfs:/ URI.")
    parser.add_argument("--gold-uri", help="Output gold root path or dbfs:/ URI.")
    parser.add_argument("--part-name", default="part-00000.parquet", help="Output parquet filename per partition.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    worker_path = Path(__file__).with_name("stub_worker.py")
    cmd = [
        sys.executable,
        str(worker_path),
        "--bronze-conn-uri",
        args.bronze_conn_uri,
        "--bronze-dns-uri",
        args.bronze_dns_uri,
        "--bronze-ebpf-exec-uri",
        args.bronze_ebpf_exec_uri,
        "--bronze-ebpf-fileaccess-uri",
        args.bronze_ebpf_fileaccess_uri,
        "--bronze-ebpf-connect-uri",
        args.bronze_ebpf_connect_uri,
        "--silver-uri",
        args.silver_uri,
    ]
    if args.gold_uri:
        cmd.extend(["--gold-uri", args.gold_uri])
    cmd.extend(
        [
            "--part-name",
            args.part_name,
        ]
    )
    print(f"spawner running: {' '.join(shlex.quote(part) for part in cmd)}", flush=True)
    result = subprocess.run(cmd, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
