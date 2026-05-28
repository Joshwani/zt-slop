# Roadmap

## v0.1

- npm package-lock and package.json checks
- simple requirements.txt checks
- OSV lookups for new npm/PyPI package versions
- GitHub Actions privilege-drift checks
- secret-pattern and exfil-path checks
- Markdown, JSON, and SARIF reports

## v0.2

- pnpm/yarn lockfile package extraction
- poetry.lock and uv.lock package extraction
- allowlists for specific packages, workflows, and domains
- better severity policy configuration

## v0.3

- release provenance and trusted-publishing hints
- package age / newly published version checks
- richer GitHub annotations and PR comments

## v1.0

- signed releases
- generated SBOM
- SLSA provenance
- GitHub Marketplace listing
- stable rule IDs and config schema
