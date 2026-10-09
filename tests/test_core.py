from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scopesieve.cli import main
from scopesieve.core import Rule, Scope, ScopeError, audit_artifact


class RuleTests(unittest.TestCase):
    def test_exact_and_wildcard_domain_rules(self) -> None:
        exact = Rule.parse("example.com")
        wildcard = Rule.parse("*.example.com")
        self.assertTrue(exact.matches("EXAMPLE.COM."))
        self.assertFalse(exact.matches("api.example.com"))
        self.assertTrue(wildcard.matches("api.example.com"))
        self.assertFalse(wildcard.matches("example.com"))
        self.assertFalse(wildcard.matches("example.net"))

    def test_ip_and_cidr_rules(self) -> None:
        host = Rule.parse("192.0.2.7")
        network = Rule.parse("192.0.2.0/24")
        self.assertTrue(host.matches("192.0.2.7"))
        self.assertFalse(host.matches("192.0.2.8"))
        self.assertTrue(network.matches("192.0.2.8"))
        self.assertFalse(network.matches("198.51.100.8"))

    def test_deny_takes_precedence_and_default_is_deny(self) -> None:
        scope = Scope(
            name="test",
            allow=(Rule.parse("*.example.com"), Rule.parse("192.0.2.0/24")),
            deny=(Rule.parse("admin.example.com"),),
        )
        self.assertEqual(scope.classify("api.example.com")[0], "IN_SCOPE")
        self.assertEqual(scope.classify("admin.example.com")[0], "OUT_OF_SCOPE")
        self.assertEqual(scope.classify("outside.example.net")[0], "OUT_OF_SCOPE")
        self.assertEqual(scope.classify("not a host")[0], "AMBIGUOUS")

    def test_invalid_rules_are_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Rule.parse("https://example.com/path")
        with self.assertRaises(ScopeError):
            Rule.parse("*.192.0.2.1")

    def test_scope_load_hashes_the_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            raw = b'name = "test"\nallow = ["example.com"]\n'
            path.write_bytes(raw)
            scope = Scope.load(path)
            self.assertEqual(scope.source_sha256, hashlib.sha256(raw).hexdigest())

    def test_scope_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.toml"
            path.write_text('name = "test"\nallow = ["example.com"]\n', encoding="utf-8")
            with patch("scopesieve.core.MAX_SCOPE_BYTES", 4):
                with self.assertRaises(ScopeError):
                    Scope.load(path)


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.scope = Scope(
            name="test",
            allow=(Rule.parse("example.com"), Rule.parse("*.example.com"), Rule.parse("192.0.2.0/24")),
            deny=(Rule.parse("admin.example.com"),),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_nmap_xml_artifact(self) -> None:
        artifact = self.directory / "scan.xml"
        artifact.write_text(
            '<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4" />'
            '<hostnames><hostname name="api.example.com" /></hostnames></host>'
            '<host><address addr="198.51.100.5" addrtype="ipv4" /></host></nmaprun>',
            encoding="utf-8",
        )
        result = audit_artifact(artifact, self.scope)
        self.assertEqual([item["status"] for item in result["targets"]], ["IN_SCOPE", "IN_SCOPE", "OUT_OF_SCOPE"])
        self.assertEqual(result["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
        self.assertEqual(result["format"], "nmap-xml")

    def test_har_artifact(self) -> None:
        artifact = self.directory / "capture.har"
        artifact.write_text(
            json.dumps({"log": {"entries": [
                {"request": {"url": "https://shop.example.com/a"}},
                {"request": {"url": "https://admin.example.com/"}},
                {"request": {"url": "https://198.51.100.5/"}},
            ]}}),
            encoding="utf-8",
        )
        result = audit_artifact(artifact, self.scope)
        self.assertEqual([item["status"] for item in result["targets"]], ["IN_SCOPE", "OUT_OF_SCOPE", "OUT_OF_SCOPE"])

    def test_target_list_with_comments(self) -> None:
        artifact = self.directory / "targets.txt"
        artifact.write_text("# comment\napi.example.com\nhttps://outside.example.net/path\n", encoding="utf-8")
        result = audit_artifact(artifact, self.scope)
        self.assertEqual([item["status"] for item in result["targets"]], ["IN_SCOPE", "OUT_OF_SCOPE"])
        self.assertEqual(result["targets"][0]["location"], "line[2]")

    def test_non_nmap_xml_is_rejected(self) -> None:
        artifact = self.directory / "other.xml"
        artifact.write_text("<not-nmap />", encoding="utf-8")
        with self.assertRaises(ValueError):
            audit_artifact(artifact, self.scope)

    def test_nmap_mac_address_is_not_a_target(self) -> None:
        artifact = self.directory / "mac.xml"
        artifact.write_text(
            '<nmaprun><host><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" />'
            '<address addr="192.0.2.15" addrtype="ipv4" /></host></nmaprun>',
            encoding="utf-8",
        )
        result = audit_artifact(artifact, self.scope)
        self.assertEqual([item["target"] for item in result["targets"]], ["192.0.2.15"])

    def test_malformed_har_structure_is_rejected(self) -> None:
        artifact = self.directory / "bad.har"
        artifact.write_text('{"log": []}', encoding="utf-8")
        with self.assertRaises(ValueError):
            audit_artifact(artifact, self.scope)

    def test_empty_target_list_warns(self) -> None:
        artifact = self.directory / "empty.targets"
        artifact.write_text("# comments only\n", encoding="utf-8")
        result = audit_artifact(artifact, self.scope)
        self.assertEqual(result["targets"], [])
        self.assertTrue(result["warnings"])

    def test_xml_dtd_is_rejected(self) -> None:
        artifact = self.directory / "dtd.xml"
        artifact.write_text(
            '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            '<nmaprun><host><address addr="&x;" addrtype="ipv4" /></host></nmaprun>',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "DTD and entity"):
            audit_artifact(artifact, self.scope)

    def test_artifact_size_limit(self) -> None:
        artifact = self.directory / "targets.txt"
        artifact.write_text("example.com\n", encoding="utf-8")
        with patch("scopesieve.core.MAX_ARTIFACT_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                audit_artifact(artifact, self.scope)

    def test_artifact_target_count_limit(self) -> None:
        artifact = self.directory / "targets.txt"
        artifact.write_text("example.com\napi.example.com\n", encoding="utf-8")
        with patch("scopesieve.core.MAX_TARGETS_PER_ARTIFACT", 1):
            with self.assertRaisesRegex(ValueError, "target limit"):
                audit_artifact(artifact, self.scope)

    def test_cli_refuses_to_overwrite_an_input(self) -> None:
        scope_path = self.directory / "scope.toml"
        scope_path.write_text('name = "test"\nallow = ["example.com"]\n', encoding="utf-8")
        artifact = self.directory / "targets.txt"
        original = b"example.com\n"
        artifact.write_bytes(original)
        stderr = StringIO()
        with redirect_stderr(stderr):
            status = main(["audit", "--scope", str(scope_path), "--output", str(artifact), str(artifact)])
        self.assertEqual(status, 2)
        self.assertEqual(artifact.read_bytes(), original)

    def test_cli_refuses_to_overwrite_the_scope_manifest(self) -> None:
        scope_path = self.directory / "scope.toml"
        original = b'name = "test"\nallow = ["example.com"]\n'
        scope_path.write_bytes(original)
        artifact = self.directory / "targets.txt"
        artifact.write_text("example.com\n", encoding="utf-8")
        stderr = StringIO()
        with redirect_stderr(stderr):
            status = main(["audit", "--scope", str(scope_path), "--output", str(scope_path), str(artifact)])
        self.assertEqual(status, 2)
        self.assertEqual(scope_path.read_bytes(), original)

    def test_cli_writes_json_report(self) -> None:
        scope_path = self.directory / "scope.toml"
        scope_path.write_text('name = "test"\nallow = ["example.com"]\n', encoding="utf-8")
        artifact = self.directory / "targets.txt"
        artifact.write_text("example.com\n", encoding="utf-8")
        output = self.directory / "report.json"
        with redirect_stdout(StringIO()):
            status = main(["audit", "--scope", str(scope_path), "--output", str(output), str(artifact)])
        self.assertEqual(status, 0)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["IN_SCOPE"], 1)

    def test_cli_escapes_terminal_control_characters(self) -> None:
        scope_path = self.directory / "scope.toml"
        scope_path.write_text('name = "test"\nallow = ["example.com"]\n', encoding="utf-8")
        artifact = self.directory / "targets.txt"
        artifact.write_text("\x1b[31mexample.com\n", encoding="utf-8")
        stdout = StringIO()
        with redirect_stdout(stdout):
            status = main(["audit", "--scope", str(scope_path), str(artifact)])
        self.assertEqual(status, 1)
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertIn("\\u001b", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
