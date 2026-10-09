"""Core parsing and scope-matching logic. This module performs no network I/O."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import stat
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__

MAX_SCOPE_BYTES = 1 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TARGETS_PER_ARTIFACT = 100_000
MAX_HOST_LENGTH = 1024
_XML_DTD_OR_ENTITY = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


class ScopeError(ValueError):
    """Raised when the scope manifest is invalid."""


def _read_limited(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if metadata.st_size > limit:
            raise ValueError(f"{label} exceeds the {limit}-byte limit")
        with path.open("rb") as source:
            raw = source.read(limit + 1)
    except OSError:
        raise
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds the {limit}-byte limit")
    return raw


@dataclass(frozen=True)
class Rule:
    raw: str
    kind: str
    value: Any

    @classmethod
    def parse(cls, raw: str) -> Rule:
        if not isinstance(raw, str) or not raw.strip():
            raise ScopeError("scope rules must be non-empty strings")
        text = raw.strip()

        if "/" in text:
            try:
                return cls(raw=text, kind="network", value=ipaddress.ip_network(text, strict=False))
            except ValueError as exc:
                raise ScopeError(f"invalid IP network rule: {text}") from exc

        try:
            return cls(raw=text, kind="ip", value=ipaddress.ip_address(text))
        except ValueError:
            pass

        wildcard = text.startswith("*.")
        domain = text[2:] if wildcard else text
        if "*" in domain or any(char in domain for char in "/:@?#[]"):
            raise ScopeError(f"invalid domain rule: {text}")
        normalized = normalize_host(domain)
        if normalized is None or _is_ip(normalized):
            raise ScopeError(f"invalid domain rule: {text}")
        return cls(raw=text, kind="wildcard_domain" if wildcard else "domain", value=normalized)

    def matches(self, target: str) -> bool:
        normalized = normalize_host(target)
        if normalized is None:
            return False

        address = _parse_ip(normalized)
        if self.kind == "ip":
            return address == self.value
        if self.kind == "network":
            return address is not None and address.version == self.value.version and address in self.value
        if address is not None:
            return False
        if self.kind == "domain":
            return normalized == self.value
        return normalized.endswith("." + self.value)


@dataclass(frozen=True)
class Scope:
    name: str
    allow: tuple[Rule, ...]
    deny: tuple[Rule, ...]
    source_sha256: str | None = None

    @classmethod
    def load(cls, path: Path) -> Scope:
        try:
            raw = _read_limited(path, MAX_SCOPE_BYTES, "scope file")
        except OSError as exc:
            raise ScopeError(f"cannot read scope file {path}: {exc}") from exc
        except ValueError as exc:
            raise ScopeError(str(exc)) from exc
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ScopeError(f"scope file is not valid UTF-8: {exc}") from exc
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError) as exc:
            raise ScopeError(f"invalid TOML in {path}: {exc}") from exc

        name = data.get("name", "Unnamed assessment")
        if not isinstance(name, str) or not name.strip():
            raise ScopeError("scope name must be a non-empty string")

        allow_values = data.get("allow", [])
        deny_values = data.get("deny", [])
        if not isinstance(allow_values, list) or not isinstance(deny_values, list):
            raise ScopeError("allow and deny must be arrays of strings")

        allow = tuple(Rule.parse(value) for value in allow_values)
        deny = tuple(Rule.parse(value) for value in deny_values)
        if not allow:
            raise ScopeError("scope must contain at least one allow rule")
        return cls(
            name=name.strip(),
            allow=allow,
            deny=deny,
            source_sha256=hashlib.sha256(raw).hexdigest(),
        )

    def classify(self, target: str) -> tuple[str, str | None, str]:
        normalized = normalize_host(target)
        if normalized is None:
            return "AMBIGUOUS", None, "Target could not be normalized as a host or IP address."

        for rule in self.deny:
            if rule.matches(normalized):
                return "OUT_OF_SCOPE", rule.raw, "Matched an explicit deny rule."
        for rule in self.allow:
            if rule.matches(normalized):
                return "IN_SCOPE", rule.raw, "Matched an allow rule."
        return "OUT_OF_SCOPE", None, "No allow rule matched (default deny)."


@dataclass(frozen=True)
class TargetDecision:
    target: str
    status: str
    matched_rule: str | None
    reason: str
    location: str


def normalize_host(value: str) -> str | None:
    """Normalize a bare host or IP literal without resolving it."""
    text = value.strip()
    if not text:
        return None
    if len(text) > MAX_HOST_LENGTH:
        return None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    try:
        return ipaddress.ip_address(text).compressed.lower()
    except ValueError:
        pass

    text = text.rstrip(".")
    if not text or any(char.isspace() for char in text):
        return None
    try:
        host = text.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
        return None
    if any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None for label in host.split(".")):
        return None
    return host


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    return _parse_ip(value) is not None


def _target_from_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        return normalize_host(parsed.hostname or "")
    except ValueError:
        return None


def _nmap_targets(raw: bytes) -> tuple[list[tuple[str, str]], list[str]]:
    targets: list[tuple[str, str]] = []
    warnings: list[str] = []
    try:
        xml_text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Nmap XML must be UTF-8") from exc
    if _XML_DTD_OR_ENTITY.search(xml_text):
        raise ValueError("XML DTD and entity declarations are not supported")
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("XML root element is not nmaprun")
    hosts = root.findall(".//host")
    for host_index, host in enumerate(hosts, start=1):
        addresses = host.findall("address")
        hostnames = host.findall("./hostnames/hostname")
        found_host_target = False
        for index, address in enumerate(addresses, start=1):
            value = address.get("addr", "").strip()
            addrtype = address.get("addrtype", "").lower()
            if value and addrtype in {"ipv4", "ipv6"}:
                targets.append((value, f"host[{host_index}].address[{index}]"))
                found_host_target = True
                if len(targets) > MAX_TARGETS_PER_ARTIFACT:
                    raise ValueError(f"artifact exceeds the {MAX_TARGETS_PER_ARTIFACT}-target limit")
        for index, hostname in enumerate(hostnames, start=1):
            value = hostname.get("name", "").strip()
            if value:
                targets.append((value, f"host[{host_index}].hostname[{index}]"))
                found_host_target = True
                if len(targets) > MAX_TARGETS_PER_ARTIFACT:
                    raise ValueError(f"artifact exceeds the {MAX_TARGETS_PER_ARTIFACT}-target limit")
        if not found_host_target:
            warnings.append(f"host[{host_index}] had no IPv4/IPv6 address or hostname")
    if not hosts:
        warnings.append("Nmap XML contained no host records")
    return targets, warnings


def _har_targets(raw: bytes) -> tuple[list[tuple[str, str]], list[str]]:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"cannot parse HAR JSON: {exc}") from exc
    log = data.get("log") if isinstance(data, dict) else None
    if not isinstance(log, dict):
        raise ValueError("HAR document must contain a log object")
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be an array")
    if len(entries) > MAX_TARGETS_PER_ARTIFACT:
        raise ValueError(f"artifact exceeds the {MAX_TARGETS_PER_ARTIFACT}-entry limit")

    targets: list[tuple[str, str]] = []
    warnings: list[str] = []
    if not entries:
        warnings.append("HAR contained no request entries")
    for index, entry in enumerate(entries, start=1):
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        url = request.get("url", "") if isinstance(request, dict) else ""
        target = _target_from_url(url) if isinstance(url, str) else None
        if target:
            targets.append((target, f"log.entries[{index}].request.url"))
        else:
            warnings.append(f"log.entries[{index}] had no parseable request URL")
    return targets, warnings


def _list_targets(raw: bytes) -> tuple[list[tuple[str, str]], list[str]]:
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError as exc:
        raise ValueError(f"target list is not valid UTF-8: {exc}") from exc
    targets: list[tuple[str, str]] = []
    for line_number, line in enumerate(lines, start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "://" in value:
            value = _target_from_url(value) or ""
        targets.append((value, f"line[{line_number}]"))
        if len(targets) > MAX_TARGETS_PER_ARTIFACT:
            raise ValueError(f"artifact exceeds the {MAX_TARGETS_PER_ARTIFACT}-target limit")
    warnings = [] if targets else ["target list contained no targets"]
    return targets, warnings


def audit_artifact(path: Path, scope: Scope) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        artifact_format = "nmap-xml"
        parser = _nmap_targets
    elif suffix == ".har":
        artifact_format = "har"
        parser = _har_targets
    elif suffix in {".txt", ".list", ".targets"}:
        artifact_format = "target-list"
        parser = _list_targets
    else:
        raise ValueError(f"unsupported file type {suffix or '(no extension)'}; use .xml, .har, .txt, .list, or .targets")

    raw = _read_limited(path, MAX_ARTIFACT_BYTES, "artifact")
    digest = hashlib.sha256(raw).hexdigest()
    targets, warnings = parser(raw)

    decisions = []
    for target, location in targets:
        status, matched_rule, reason = scope.classify(target)
        decisions.append(asdict(TargetDecision(target, status, matched_rule, reason, location)))

    return {
        "source": str(path),
        "format": artifact_format,
        "sha256": digest,
        "targets": decisions,
        "warnings": warnings,
        "error": None,
    }


def build_report(scope_path: Path, scope: Scope, artifact_paths: list[Path]) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for path in artifact_paths:
        try:
            artifacts.append(audit_artifact(path, scope))
        except (OSError, ValueError, ET.ParseError, RecursionError) as exc:
            artifacts.append({"source": str(path), "format": None, "sha256": None, "targets": [], "warnings": [], "error": str(exc)})

    decisions = [decision for artifact in artifacts for decision in artifact["targets"]]
    counts = {name: sum(item["status"] == name for item in decisions) for name in ("IN_SCOPE", "OUT_OF_SCOPE", "AMBIGUOUS")}
    errors = sum(artifact["error"] is not None for artifact in artifacts)
    warnings = sum(len(artifact["warnings"]) for artifact in artifacts)
    return {
        "schema_version": 1,
        "tool": "ScopeSieve",
        "tool_version": __version__,
        "scope": {
            "name": scope.name,
            "source": str(scope_path),
            "sha256": scope.source_sha256,
            "allow": [rule.raw for rule in scope.allow],
            "deny": [rule.raw for rule in scope.deny],
        },
        "summary": {**counts, "artifacts": len(artifacts), "artifact_errors": errors, "artifact_warnings": warnings},
        "artifacts": artifacts,
    }
