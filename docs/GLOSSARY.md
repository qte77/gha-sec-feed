# Glossary

Acronyms used in this repo, its handoff, and the producer's documentation.
Each row links to the publishing organisation's first-party source where
one exists.

## Vulnerability data sources

| Term | Expansion | Publisher | What it provides |
|---|---|---|---|
| **NVD** | National Vulnerability Database | [NIST](https://nvd.nist.gov/) | Canonical CVE database; broadest coverage |
| **KEV** | [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CISA (US gov) | Curated list of actively-exploited CVEs |
| **CISA** | [Cybersecurity and Infrastructure Security Agency](https://www.cisa.gov/) | US gov | Publisher of KEV |
| **NIST** | [National Institute of Standards and Technology](https://www.nist.gov/) | US gov | Publisher of NVD |
| **CVE** | [Common Vulnerabilities and Exposures](https://www.cve.org/) | MITRE | Per-vuln identifier (`CVE-YYYY-NNNNN`) |
| **CVSS** | [Common Vulnerability Scoring System](https://www.first.org/cvss/) | FIRST.org | 0-10 severity score per CVE |
| **EPSS** | [Exploit Prediction Scoring System](https://www.first.org/epss/) | FIRST.org | 0-1 probability of exploit (orthogonal to CVSS) |
| **GHSA** | [GitHub Security Advisories](https://github.com/advisories) | GitHub | Ecosystem-tagged advisories (npm / PyPI / Go / RubyGems) |
| **OSV** | [Open Source Vulnerabilities](https://osv.dev/) | Google | Distributed vuln DB |
| **RHSA** | [Red Hat Security Advisory](https://access.redhat.com/security/security-updates) | Red Hat | RHEL / UBI advisories |
| **USN** | [Ubuntu Security Notice](https://ubuntu.com/security/notices) | Canonical | Ubuntu advisories |
| **IOC** | Indicator of Compromise | (industry) | Non-CVE threat data (URLs, IPs, samples) |

The v0.1.0 floor ships only **NVD + KEV**. Other sources are documented in
the brief and deferred until a concrete consumer needs them.

## Project contracts and artifacts

| Term | Meaning |
|---|---|
| **C1** | This producer's external contract — `data/feed.jsonl` row shape + `data/feed-meta.json`. Locked at `schema_version` v1.0.0. |
| **JSONL** | [JSON Lines](https://jsonlines.org/) — newline-delimited JSON; one row per line; aka **NDJSON** |
| **NDJSON** | [Newline-Delimited JSON](http://ndjson.org/) (= JSONL) |

## Supply chain and security

| Term | Meaning |
|---|---|
| **SBOM** | [Software Bill of Materials](https://www.cisa.gov/sbom) |
| **SLSA** | [Supply-chain Levels for Software Artifacts](https://slsa.dev/) |
| **SHA** | [Secure Hash Algorithm](https://csrc.nist.gov/projects/hash-functions) — here, a git commit hash used to pin GitHub Actions `uses:` |
| **SAST** | Static Application Security Testing (e.g., [CodeQL](https://codeql.github.com/)) |
| **OWASP** | [Open Worldwide Application Security Project](https://owasp.org/) |

## MITRE frameworks (consumed downstream, not by this producer)

| Term | Meaning |
|---|---|
| **ATT&CK** | [Adversarial Tactics, Techniques, and Common Knowledge](https://attack.mitre.org/) |
| **D3FEND** | [Defensive countermeasure ontology](https://d3fend.mitre.org/) |
