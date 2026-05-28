# Security policy

## Reporting a vulnerability

Please report security issues privately by opening a security advisory in GitHub, or by emailing the maintainer address listed in the repository profile once this project is published.

Include:

- affected version or commit SHA
- reproduction steps
- impact
- any logs or reports needed to understand the issue

Do not include real secrets in bug reports. Redact tokens, private keys, customer data, and internal hostnames.

## Project security goals

ZT-Slop should not become the supply-chain risk it is trying to detect. The scanner is designed to:

- avoid runtime dependencies
- avoid executing untrusted PR code
- avoid installing packages from the repository under review
- keep network access limited to advisory lookups unless disabled
- redact possible secrets in output

## Out of scope

- Reports that require running arbitrary code from a pull request
- Vulnerabilities in third-party package registries or advisory databases
- False positives that do not create a security issue in ZT-Slop itself
