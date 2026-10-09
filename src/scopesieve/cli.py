"""Command-line interface for ScopeSieve."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import Scope, ScopeError, build_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopesieve",
        description="Audit existing security-test artifacts against an authorized scope (offline).",
    )
    parser.add_argument("--version", action="version", version=f"ScopeSieve {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser("audit", help="check Nmap XML, HAR, or target-list files")
    audit.add_argument("--scope", required=True, type=Path, help="TOML file with allow and deny rules")
    audit.add_argument("--output", type=Path, help="write the JSON audit report to this path")
    audit.add_argument("--format", choices=("text", "json"), default="text", help="stdout report format")
    audit.add_argument("artifacts", nargs="+", type=Path, help=".xml, .har, .txt, .list, or .targets files")
    return parser


def _print_text(report: dict) -> None:
    summary = report["summary"]
    print(f"ScopeSieve audit — {_display(report['scope']['name'])}")
    print(
        "Targets: "
        f"{summary['IN_SCOPE']} in scope, "
        f"{summary['OUT_OF_SCOPE']} out of scope, "
        f"{summary['AMBIGUOUS']} ambiguous"
    )
    print(f"Artifacts: {summary['artifacts']} ({summary['artifact_errors']} errors)")
    if summary["artifact_warnings"]:
        print(f"Warnings: {summary['artifact_warnings']}")

    for artifact in report["artifacts"]:
        print(f"\n[{artifact['format'] or 'error'}] {_display(artifact['source'])}")
        if artifact["error"]:
            print(f"  ERROR: {_display(artifact['error'])}")
            continue
        for decision in artifact["targets"]:
            rule = f" — rule: {_display(decision['matched_rule'])}" if decision["matched_rule"] else ""
            print(
                f"  {decision['status']}: {_display(decision['target'])} "
                f"({_display(decision['location'])}){rule}"
            )
        for warning in artifact["warnings"]:
            print(f"  WARNING: {_display(warning)}")


def _display(value: object) -> str:
    """Escape control and formatting characters before terminal output."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in str(value)
    )


def _same_file_path(left: Path, right: Path) -> bool:
    if left.resolve(strict=False) == right.resolve(strict=False):
        return True
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _validate_output_path(output: Path, inputs: list[Path]) -> None:
    for input_path in inputs:
        try:
            same_file = _same_file_path(output, input_path)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"cannot safely compare output and input paths: {exc}") from exc
        if same_file:
            raise ValueError(f"report output must not overwrite an input file: {input_path}")


def _write_json_report(output: Path, report: dict) -> None:
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, output)
    except OSError:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command != "audit":
        parser.error("unknown command")

    if args.output:
        try:
            _validate_output_path(args.output, [args.scope, *args.artifacts])
        except ValueError as exc:
            print(f"scopesieve: error: {_display(exc)}", file=sys.stderr)
            return 2

    try:
        scope = Scope.load(args.scope)
        report = build_report(args.scope, scope, args.artifacts)
    except ScopeError as exc:
        print(f"scopesieve: error: {_display(exc)}", file=sys.stderr)
        return 2

    if args.output:
        try:
            _write_json_report(args.output, report)
        except OSError as exc:
            print(f"scopesieve: error: cannot write {_display(args.output)}: {_display(exc)}", file=sys.stderr)
            return 2

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_text(report)
        if args.output:
            print(f"\nJSON report saved to {_display(args.output)}")

    if report["summary"]["artifact_errors"] or report["summary"]["artifact_warnings"]:
        return 2
    if report["summary"]["OUT_OF_SCOPE"] or report["summary"]["AMBIGUOUS"]:
        return 1
    return 0
