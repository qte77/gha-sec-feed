# Glossary

Acronyms used in this repo, its handoff, and the producer's documentation.

## Vulnerability data sources

| Term | Expansion | Publisher | What it provides |
|---|---|---|---|
| **NVD** | National Vulnerability Database | NIST (US gov) | Canonical CVE database; broadest coverage |
| **KEV** | Known Exploited Vulnerabilities | CISA (US gov) | Curated list of actively-exploited CVEs |
| **CISA** | Cybersecurity and Infrastructure Security Agency | US gov | Publisher of KEV |
| **NIST** | National Institute of Standards and Technology | US gov | Publisher of NVD |
| **CVE** | Common Vulnerabilities and Exposures | MITRE | Per-vuln identifier (`CVE-YYYY-NNNNN`) |
| **CVSS** | Common Vulnerability Scoring System | FIRST.org | 0-10 severity score per CVE |
| **EPSS** | Exploit Prediction Scoring System | FIRST.org | 0-1 probability of exploit (orthogonal to CVSS) |
| **GHSA** | GitHub Security Advisories | GitHub | Ecosystem-tagged advisories (npm / PyPI / Go / RubyGems) |
| **OSV** | Open Source Vulnerabilities | Google | Distributed vuln DB |
| **RHSA** | Red Hat Security Advisory | Red Hat | RHEL / UBI advisories |
| **USN** | Ubuntu Security Notice | Canonical | Ubuntu advisories |
| **IOC** | Indicator of Compromise | (industry) | Non-CVE threat data (URLs, IPs, samples) |

The v0.1.0 floor ships only **NVD + KEV**. Other sources are documented in
the brief and deferred per KISS until a concrete consumer needs them.

## Project contracts and artifacts

| Term | Meaning |
|---|---|
| **C1** | This producer's external contract — `data/feed.jsonl` row shape + `data/feed-meta.json`. Locked at `schema_version` v1.0.0. |
| **JSONL** | JSON Lines — newline-delimited JSON; one row per line; aka **NDJSON** |
| **NDJSON** | Newline-Delimited JSON (= JSONL) |

## Supply chain and security

| Term | Meaning |
|---|---|
| **SBOM** | Software Bill of Materials |
| **SLSA** | Supply-chain Levels for Software Artifacts |
| **SHA** | Secure Hash Algorithm — here, a git commit hash used to pin GitHub Actions `uses:` |
| **SAST** | Static Application Security Testing (e.g., CodeQL) |
| **OWASP** | Open Worldwide Application Security Project |

## MITRE frameworks (consumed downstream, not by this producer)

| Term | Meaning |
|---|---|
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge |
| **D3FEND** | Defensive countermeasure ontology |
