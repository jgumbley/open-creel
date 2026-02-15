from __future__ import annotations

import argparse
import sys
import unittest
from unittest.mock import patch

from open_creel import cli


class NonEmptyTests(unittest.TestCase):
    def test_non_empty_strips_whitespace(self) -> None:
        self.assertEqual(cli._non_empty("  value  "), "value")

    def test_non_empty_rejects_blank_value(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            cli._non_empty("   ")


class MainDispatchTests(unittest.TestCase):
    def test_main_silver_dispatches_pipeline(self) -> None:
        argv = [
            "open-creel",
            "silver",
            "--bronze-conn-uri",
            "/tmp/conn.log",
            "--bronze-dns-uri",
            "/tmp/dns.log",
            "--bronze-http-uri",
            "/tmp/http.log",
            "--bronze-ssl-uri",
            "/tmp/ssl.log",
            "--bronze-ebpf-exec-uri",
            "/tmp/exec.log",
            "--bronze-ebpf-fileaccess-uri",
            "/tmp/fileaccess.log",
            "--bronze-ebpf-connect-uri",
            "/tmp/connect.log",
            "--silver-uri",
            "/tmp/silver",
            "--part-name",
            "custom.parquet",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("open_creel.cli.pipeline.run_bronze_to_ocsf_pipeline") as run_pipeline,
        ):
            rc = cli.main()

        self.assertEqual(rc, 0)
        run_pipeline.assert_called_once_with(
            bronze_conn_uri="/tmp/conn.log",
            bronze_dns_uri="/tmp/dns.log",
            bronze_http_uri="/tmp/http.log",
            bronze_ssl_uri="/tmp/ssl.log",
            bronze_ebpf_exec_uri="/tmp/exec.log",
            bronze_ebpf_fileaccess_uri="/tmp/fileaccess.log",
            bronze_ebpf_connect_uri="/tmp/connect.log",
            silver_uri="/tmp/silver",
            gold_uri=None,
            part_name="custom.parquet",
        )

    def test_main_gold_dispatches_pipeline(self) -> None:
        argv = [
            "open-creel",
            "gold",
            "--bronze-conn-uri",
            "/tmp/conn.log",
            "--bronze-dns-uri",
            "/tmp/dns.log",
            "--bronze-http-uri",
            "/tmp/http.log",
            "--bronze-ssl-uri",
            "/tmp/ssl.log",
            "--bronze-ebpf-exec-uri",
            "/tmp/exec.log",
            "--bronze-ebpf-fileaccess-uri",
            "/tmp/fileaccess.log",
            "--bronze-ebpf-connect-uri",
            "/tmp/connect.log",
            "--silver-uri",
            "/tmp/silver",
            "--gold-uri",
            "/tmp/gold",
            "--part-name",
            "part-00001.parquet",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("open_creel.cli.pipeline.run_bronze_to_ocsf_pipeline") as run_pipeline,
        ):
            rc = cli.main()

        self.assertEqual(rc, 0)
        run_pipeline.assert_called_once_with(
            bronze_conn_uri="/tmp/conn.log",
            bronze_dns_uri="/tmp/dns.log",
            bronze_http_uri="/tmp/http.log",
            bronze_ssl_uri="/tmp/ssl.log",
            bronze_ebpf_exec_uri="/tmp/exec.log",
            bronze_ebpf_fileaccess_uri="/tmp/fileaccess.log",
            bronze_ebpf_connect_uri="/tmp/connect.log",
            silver_uri="/tmp/silver",
            gold_uri="/tmp/gold",
            part_name="part-00001.parquet",
        )

    def test_main_silver_proof_alias_dispatches_report(self) -> None:
        argv = ["open-creel", "silver-proof", "--silver-uri", "/tmp/silver"]
        with (
            patch.object(sys, "argv", argv),
            patch("open_creel.cli.reports.silver_show_latest", return_value=7) as show_latest,
        ):
            rc = cli.main()

        self.assertEqual(rc, 7)
        show_latest.assert_called_once_with("/tmp/silver")

    def test_main_silver_domain_check_dispatches_report(self) -> None:
        argv = [
            "open-creel",
            "silver-domain-check",
            "--silver-uri",
            "/tmp/silver",
            "--domain",
            "  Example.com  ",
        ]
        with (
            patch.object(sys, "argv", argv),
            patch("open_creel.cli.reports.silver_domain_check", return_value=5) as domain_check,
        ):
            rc = cli.main()

        self.assertEqual(rc, 5)
        domain_check.assert_called_once_with("/tmp/silver", "Example.com")


if __name__ == "__main__":
    unittest.main()
