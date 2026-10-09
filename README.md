# ScopeSieve

**An offline scope auditor for authorized security assessments.** ScopeSieve checks existing Nmap XML, Burp-style HAR, and plain target-list files against an engagement's allow and deny rules. It does not scan hosts, resolve DNS, or make network connections.

The first useful check is simple: after collecting output from different tools, find targets that were explicitly excluded, never authorized, or could not be interpreted safely. Each decision includes the source artifact, record location, and matching rule. JSON reports include SHA-256 hashes for the scope file and every artifact.

## Quick start

Requires Python 3.11 or newer. The runtime uses only the Python standard library.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
scopesieve audit --scope examples/scope.toml examples/sample.nmap.xml examples/sample.har
```

The sample intentionally contains out-of-scope targets, so the command exits with status `1`. Try the in-scope target list for a clean audit:

```sh
scopesieve audit --scope examples/scope.toml examples/in-scope.targets
```

Write a machine-readable report as well as the terminal summary:

```sh
scopesieve audit --scope examples/scope.toml --output audit.json examples/sample.nmap.xml examples/sample.har
```

## Scope manifest

ScopeSieve reads TOML. Explicit deny rules always win. Anything that does not match an allow rule is out of scope by default.

```toml
name = "Example authorized assessment"
allow = [
  "example.com",
  "*.example.com",
  "192.0.2.0/24",
]
deny = [
  "admin.example.com",
  "192.0.2.9",
]
```

An exact domain rule matches only that domain. A wildcard such as `*.example.com` matches subdomains, not the apex `example.com`. IPv4, IPv6, and CIDR rules are supported. DNS is never queried; hostnames are matched as written in the artifacts.

## Inputs and decisions

| Input | Extracted targets |
| --- | --- |
| Nmap XML (`.xml`) | Host addresses and reported hostnames |
| HAR (`.har`) | Hostnames/IPs from each request URL |
| Target list (`.txt`, `.list`, `.targets`) | One host, IP, or URL per line; blank lines and lines beginning with `#` are ignored |

Each target is classified as:

- `IN_SCOPE`: matched an allow rule and no deny rule.
- `OUT_OF_SCOPE`: matched a deny rule or no allow rule (default deny).
- `AMBIGUOUS`: could not be normalized as a hostname or IP; review it manually.

Exit codes are `0` for a clean audit, `1` when any target is out of scope or ambiguous, and `2` when an input, manifest, or report operation fails. Parser warnings also return `2`, so incomplete artifacts are not reported as clean.

## Safety and limits

- ScopeSieve is read-only and performs no active testing or network I/O.
- Each artifact is parsed from the same byte snapshot that is hashed, so the report digest identifies the content actually audited.
- Scope manifests are limited to 1 MiB; artifacts are limited to 64 MiB and 100,000 extracted entries. XML DTD and entity declarations are rejected.
- The report writer refuses paths that resolve to the scope manifest or an input artifact, and replaces output atomically.
- Non-printing and Unicode formatting characters are escaped in terminal output.
- It audits only targets visible in the supported artifact formats. It cannot prove that every action taken during an assessment was captured in those artifacts.
- It checks hostnames and IPs, not URL paths or ports. It does not resolve DNS, expand wildcard rules, infer authorization, or decide whether a contract permits a test. Human review and written authorization remain essential.
- SHA-256 values identify the bytes that were read; reports are not signed and do not prove who created the source artifacts.
- Reports contain the supplied artifact paths and observed targets. Review them before sharing.

## Development

Run the tests without installing dependencies:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

ScopeSieve is an early MVP. The initial goal is reliable, explainable scope checking for a small set of common exports, not a scanner or a replacement for engagement management platforms.

See [SECURITY.md](SECURITY.md) for input-handling notes and the tool's limits.

## License

MIT. See [LICENSE](LICENSE).
