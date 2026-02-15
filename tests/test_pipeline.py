from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from open_creel import pipeline


def _write_stub_json(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")


class PipelineRuleTests(unittest.TestCase):
    def test_find_uncovered_dns_name_additions_detects_new_root_domain(self) -> None:
        covered_names, new_names = pipeline.find_uncovered_dns_name_additions(
            [
                "example.com",
                "api.example.com",
                "other.net",
                "sub.other.net",
            ]
        )

        self.assertEqual(new_names, ["other.net"])
        self.assertEqual(covered_names, ["example.com", "api.example.com", "sub.other.net"])

    def test_build_unexpected_child_process_findings_skips_allowlisted_processes(self) -> None:
        findings = pipeline.build_unexpected_child_process_findings(
            [
                {
                    "ts": 1.0,
                    "binary": "/usr/bin/bash",
                    "argv": ["bash", "-lc", "echo hi"],
                    "cwd": "/home/system/wip/open-creel",
                },
                {
                    "ts": 2.0,
                    "pid": 4242,
                    "uid": 1000,
                    "binary": "/usr/bin/netcat",
                    "argv": ["netcat", "127.0.0.1", "8080"],
                    "cwd": "/home/system/wip/open-creel",
                },
            ],
            exec_uri="/tmp/exec.log",
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["finding_info"]["uid"], pipeline.UNEXPECTED_CHILD_RULE_UID)
        self.assertEqual(finding["severity_id"], pipeline.FINDING_SEVERITY_MEDIUM_ID)
        self.assertEqual(finding["actor"]["process"]["pid"], 4242)
        self.assertEqual(finding["unmapped"]["process_label"], "netcat")

    def test_build_sensitive_file_access_findings_flags_non_allowlisted_reader(self) -> None:
        findings = pipeline.build_sensitive_file_access_findings(
            [
                {
                    "ts": 1.0,
                    "binary": "/usr/bin/python3",
                    "argv": ["python3", "script.py"],
                    "operations": ["read"],
                    "path": "/home/system/.aws/credentials",
                },
                {
                    "ts": 2.0,
                    "pid": 991,
                    "uid": 1000,
                    "binary": "/tmp/stealer",
                    "argv": ["/tmp/stealer"],
                    "operations": ["read"],
                    "path": "/home/system/.ssh/id_rsa",
                },
                {
                    "ts": 3.0,
                    "binary": "/tmp/stealer",
                    "argv": ["/tmp/stealer"],
                    "operations": ["write"],
                    "path": "/home/system/.ssh/id_rsa",
                },
            ],
            fileaccess_uri="/tmp/fileaccess.log",
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["finding_info"]["uid"], pipeline.SENSITIVE_FILE_RULE_UID)
        self.assertEqual(finding["severity_id"], pipeline.FINDING_SEVERITY_MEDIUM_ID)
        self.assertEqual(finding["file"]["path"], "/home/system/.ssh/id_rsa")
        self.assertEqual(finding["unmapped"]["process_label"], "stealer")

    def test_parse_file_observation_maps_delete_activity(self) -> None:
        observation = pipeline.parse_file_observation(
            {
                "time_ns": 1700000000000000000,
                "pid": 99,
                "ppid": 55,
                "uid": 1000,
                "comm": "openclaw",
                "operation": "unlink",
                "path": "/tmp/secret.txt",
            },
            line_number=1,
            raw_line='{"operation":"unlink"}\n',
            fileaccess_path=Path("/tmp/fileaccess.log"),
            process_catalog={},
        )

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["activity_name"], "delete")
        self.assertEqual(observation["operations"], ["delete"])
        self.assertEqual(observation["path"], "/tmp/secret.txt")
        self.assertIsNone(observation["target_path"])

    def test_parse_file_observation_maps_rename_activity(self) -> None:
        observation = pipeline.parse_file_observation(
            {
                "time_ns": 1700000000000000000,
                "pid": 99,
                "ppid": 55,
                "uid": 1000,
                "comm": "openclaw",
                "operation": "rename",
                "path": "/tmp/old.txt",
                "new_path": "/tmp/new.txt",
            },
            line_number=1,
            raw_line='{"operation":"rename"}\n',
            fileaccess_path=Path("/tmp/fileaccess.log"),
            process_catalog={},
        )

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["activity_name"], "rename")
        self.assertEqual(observation["operations"], ["rename"])
        self.assertEqual(observation["path"], "/tmp/old.txt")
        self.assertEqual(observation["target_path"], "/tmp/new.txt")

    def test_parse_file_observation_includes_truncate_operation(self) -> None:
        observation = pipeline.parse_file_observation(
            {
                "time_ns": 1700000000000000000,
                "pid": 99,
                "ppid": 55,
                "uid": 1000,
                "comm": "openclaw",
                "operation": "open",
                "path": "/tmp/target.txt",
                "flags": 512,
                "truncate": True,
            },
            line_number=1,
            raw_line='{"operation":"open","truncate":true}\n',
            fileaccess_path=Path("/tmp/fileaccess.log"),
            process_catalog={},
        )

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["activity_name"], "open")
        self.assertIn("truncate", observation["operations"])
        self.assertEqual(observation["path"], "/tmp/target.txt")

    def test_build_network_activity_events_enriches_with_ssl_and_http(self) -> None:
        with TemporaryDirectory() as tmpdir:
            conn_path = Path(tmpdir) / "conn.log"
            conn_path.write_text(
                (
                    '{"ts":1700000000.0,"uid":"C1","id.orig_h":"10.0.0.10","id.orig_p":55555,'
                    '"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","ip_proto":6}\n'
                ),
                encoding="utf-8",
            )

            events = pipeline.build_network_activity_events(
                conn_path=conn_path,
                conn_uri=str(conn_path),
                dns_index={},
                connect_index={},
                http_index={
                    "C1": {
                        "ts": 1700000000.0,
                        "host": "api.example.com",
                        "method": "GET",
                        "uri": "/x",
                    }
                },
                ssl_index={
                    "C1": {
                        "ts": 1700000000.0,
                        "server_name": "tls.example.com",
                        "version": "TLSv1.3",
                    }
                },
            )

        self.assertEqual(len(events), 1)
        _, event = events[0]
        self.assertEqual(event["dst_endpoint"]["hostname"], "tls.example.com")
        self.assertEqual(event["unmapped"]["zeek_ssl"]["server_name"], "tls.example.com")
        self.assertEqual(event["unmapped"]["zeek_http"]["host"], "api.example.com")


class PipelineOrchestrationTests(unittest.TestCase):
    def test_run_pipeline_rejects_non_parquet_part_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "part_name must end with .parquet"):
            pipeline.run_bronze_to_ocsf_pipeline(
                bronze_conn_uri="/tmp/conn.log",
                bronze_dns_uri="/tmp/dns.log",
                bronze_http_uri="/tmp/http.log",
                bronze_ssl_uri="/tmp/ssl.log",
                bronze_ebpf_exec_uri="/tmp/exec.log",
                bronze_ebpf_fileaccess_uri="/tmp/fileaccess.log",
                bronze_ebpf_connect_uri="/tmp/connect.log",
                silver_uri="/tmp/silver",
                gold_uri=None,
                part_name="part-00000",
            )

    def test_run_pipeline_calls_stage_functions_and_returns_processed_total(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            conn_path = root / "conn.log"
            dns_path = root / "dns.log"
            http_path = root / "http.log"
            ssl_path = root / "ssl.log"
            exec_path = root / "exec.log"
            fileaccess_path = root / "fileaccess.log"
            connect_path = root / "connect.log"
            silver_root = root / "silver"
            gold_root = root / "gold"

            for path in (conn_path, dns_path, http_path, ssl_path, exec_path, fileaccess_path, connect_path):
                _write_stub_json(path)

            with (
                patch("open_creel.pipeline.load_dns_index") as load_dns_index,
                patch("open_creel.pipeline.load_http_index") as load_http_index,
                patch("open_creel.pipeline.load_ssl_index") as load_ssl_index,
                patch("open_creel.pipeline.build_process_activity_bundle") as build_process_activity_bundle,
                patch("open_creel.pipeline.load_connect_index") as load_connect_index,
                patch("open_creel.pipeline.build_network_activity_events") as build_network_activity_events,
                patch("open_creel.pipeline.build_file_activity_events") as build_file_activity_events,
                patch("open_creel.pipeline.write_partitioned_events") as write_partitioned_events,
                patch("open_creel.pipeline.build_dns_coverage_findings") as build_dns_coverage_findings,
                patch("open_creel.pipeline.build_unexpected_child_process_findings")
                as build_unexpected_child_process_findings,
                patch("open_creel.pipeline.build_sensitive_file_access_findings")
                as build_sensitive_file_access_findings,
                patch("open_creel.pipeline.write_gold_findings", return_value=3) as write_gold_findings,
            ):
                load_dns_index.return_value = ({}, ["example.com"], 1700000000.0)
                load_http_index.return_value = {"http": "idx"}
                load_ssl_index.return_value = {"ssl": "idx"}
                build_process_activity_bundle.return_value = (
                    [("2026-01-01", {"time": 1000})],
                    [{"ts": 1.0}],
                    {100: {"pid": 100}},
                )
                load_connect_index.return_value = {"idx": "connect"}
                build_network_activity_events.return_value = [
                    ("2026-01-01", {"time": 2000}),
                    ("2026-01-01", {"time": 3000}),
                ]
                build_file_activity_events.return_value = (
                    [("2026-01-01", {"time": 4000})],
                    [{"ts": 2.0}],
                )
                write_partitioned_events.side_effect = [(2, 1), (1, 1), (3, 1)]
                build_dns_coverage_findings.return_value = [{"rule": "dns"}]
                build_unexpected_child_process_findings.return_value = [{"rule": "exec"}]
                build_sensitive_file_access_findings.return_value = [{"rule": "file"}]

                total_processed = pipeline.run_bronze_to_ocsf_pipeline(
                    bronze_conn_uri=str(conn_path),
                    bronze_dns_uri=str(dns_path),
                    bronze_http_uri=str(http_path),
                    bronze_ssl_uri=str(ssl_path),
                    bronze_ebpf_exec_uri=str(exec_path),
                    bronze_ebpf_fileaccess_uri=str(fileaccess_path),
                    bronze_ebpf_connect_uri=str(connect_path),
                    silver_uri=str(silver_root),
                    gold_uri=str(gold_root),
                    part_name="part-00000.parquet",
                )

            self.assertEqual(total_processed, 6)
            self.assertEqual(write_partitioned_events.call_count, 3)
            load_http_index.assert_called_once_with(http_path)
            load_ssl_index.assert_called_once_with(ssl_path)
            build_network_activity_events.assert_called_once_with(
                conn_path,
                str(conn_path),
                {},
                {"idx": "connect"},
                {"http": "idx"},
                {"ssl": "idx"},
            )
            self.assertTrue((silver_root / f"class_uid={pipeline.NETWORK_CLASS_UID}").is_dir())
            self.assertTrue((silver_root / f"class_uid={pipeline.PROCESS_CLASS_UID}").is_dir())
            self.assertTrue((silver_root / f"class_uid={pipeline.FILE_CLASS_UID}").is_dir())
            write_gold_findings.assert_called_once_with(
                gold_root,
                "part-00000.parquet",
                [{"rule": "dns"}, {"rule": "exec"}, {"rule": "file"}],
            )


if __name__ == "__main__":
    unittest.main()
