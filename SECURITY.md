# Security notes

ScopeSieve is an offline parser and scope auditor. It does not open sockets, resolve DNS, run scanners, or execute input files.

Input artifacts and scope manifests are untrusted data. The parser rejects XML DTD/entity declarations, applies file and entry-count limits, and escapes terminal control/formatting characters in text output. JSON output escapes control characters according to the JSON format.

ScopeSieve does not enforce authorization at scan time. It only classifies targets present in the artifacts supplied to it, so it cannot prove that an engagement stayed in scope if relevant actions were not captured. Review ambiguous and out-of-scope results manually, and keep the written authorization for the assessment.

The current scope model checks hostnames and IP addresses. It does not enforce URL path or port restrictions. SHA-256 digests identify the input bytes read by the tool, but reports are not signed and do not prove artifact origin or authenticity.

Reports contain observed targets, local source paths, and hashes. Treat them as engagement data and review them before sharing.

Use synthetic examples and fixtures in issues or pull requests. Do not publish client artifacts, credentials, personal data, or other confidential assessment material.
