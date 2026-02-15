from __future__ import annotations

import argparse

from . import pipeline, reports


def _non_empty(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise argparse.ArgumentTypeError("value must be non-empty")
    return normalized


def _add_bronze_args(parser: argparse.ArgumentParser) -> None:
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


def _add_common_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--silver-uri", required=True, help="Output silver root path or dbfs:/ URI.")
    parser.add_argument("--part-name", default="part-00000.parquet", help="Output parquet filename per partition.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenCreel OCSF pipeline and report commands."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    silver_parser = subparsers.add_parser("silver", help="Map bronze logs to OCSF silver parquet.")
    _add_bronze_args(silver_parser)
    _add_common_output_args(silver_parser)

    gold_parser = subparsers.add_parser("gold", help="Map bronze logs to OCSF silver parquet and gold findings.")
    _add_bronze_args(gold_parser)
    _add_common_output_args(gold_parser)
    gold_parser.add_argument("--gold-uri", required=True, help="Output gold root path or dbfs:/ URI.")

    silver_show_latest_parser = subparsers.add_parser(
        "silver-show-latest",
        aliases=["silver-proof"],
        help="Show latest mapped OCSF silver records.",
    )
    silver_show_latest_parser.add_argument("--silver-uri", required=True)

    silver_network_summary_parser = subparsers.add_parser(
        "silver-network-summary",
        help="Summarize OCSF silver network activity records.",
    )
    silver_network_summary_parser.add_argument("--silver-uri", required=True)

    silver_top_dst_hour_parser = subparsers.add_parser(
        "silver-network-top-dst-hour",
        aliases=["silver-top-dst-hour"],
        help="Top destination IPs by bytes in the latest hour.",
    )
    silver_top_dst_hour_parser.add_argument("--silver-uri", required=True)

    silver_domain_check_parser = subparsers.add_parser(
        "silver-domain-check",
        help="Search silver network hostnames for a domain.",
    )
    silver_domain_check_parser.add_argument("--silver-uri", required=True)
    silver_domain_check_parser.add_argument("--domain", required=True, type=_non_empty)

    gold_show_latest_parser = subparsers.add_parser(
        "gold-show-latest",
        aliases=["gold-proof"],
        help="Show latest mapped OCSF gold detection record.",
    )
    gold_show_latest_parser.add_argument("--gold-uri", required=True)

    gold_list_parser = subparsers.add_parser(
        "gold-list",
        help="List all mapped OCSF gold detection records.",
    )
    gold_list_parser.add_argument("--gold-uri", required=True)

    gold_severity_parser = subparsers.add_parser(
        "gold-list-severity-ge3",
        aliases=["gold-severity-ge3"],
        help="List gold detections where severity_id >= 3.",
    )
    gold_severity_parser.add_argument("--gold-uri", required=True)

    bronze_dns_domain_check_parser = subparsers.add_parser(
        "bronze-dns-domain-check",
        help="Search bronze DNS queries for a domain.",
    )
    bronze_dns_domain_check_parser.add_argument("--bronze-dns-uri", required=True)
    bronze_dns_domain_check_parser.add_argument("--domain", required=True, type=_non_empty)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "silver":
        pipeline.run_bronze_to_ocsf_pipeline(
            bronze_conn_uri=args.bronze_conn_uri,
            bronze_dns_uri=args.bronze_dns_uri,
            bronze_ebpf_exec_uri=args.bronze_ebpf_exec_uri,
            bronze_ebpf_fileaccess_uri=args.bronze_ebpf_fileaccess_uri,
            bronze_ebpf_connect_uri=args.bronze_ebpf_connect_uri,
            silver_uri=args.silver_uri,
            gold_uri=None,
            part_name=args.part_name,
        )
        return 0

    if args.command == "gold":
        pipeline.run_bronze_to_ocsf_pipeline(
            bronze_conn_uri=args.bronze_conn_uri,
            bronze_dns_uri=args.bronze_dns_uri,
            bronze_ebpf_exec_uri=args.bronze_ebpf_exec_uri,
            bronze_ebpf_fileaccess_uri=args.bronze_ebpf_fileaccess_uri,
            bronze_ebpf_connect_uri=args.bronze_ebpf_connect_uri,
            silver_uri=args.silver_uri,
            gold_uri=args.gold_uri,
            part_name=args.part_name,
        )
        return 0

    if args.command in {"silver-show-latest", "silver-proof"}:
        return reports.silver_show_latest(args.silver_uri)

    if args.command == "silver-network-summary":
        return reports.silver_network_summary(args.silver_uri)

    if args.command in {"silver-network-top-dst-hour", "silver-top-dst-hour"}:
        return reports.silver_network_top_dst_hour(args.silver_uri)

    if args.command == "silver-domain-check":
        return reports.silver_domain_check(args.silver_uri, args.domain)

    if args.command in {"gold-show-latest", "gold-proof"}:
        return reports.gold_show_latest(args.gold_uri)

    if args.command == "gold-list":
        return reports.gold_list(args.gold_uri)

    if args.command in {"gold-list-severity-ge3", "gold-severity-ge3"}:
        return reports.gold_list_severity_ge3(args.gold_uri)

    if args.command == "bronze-dns-domain-check":
        return reports.bronze_dns_domain_check(args.bronze_dns_uri, args.domain)

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
