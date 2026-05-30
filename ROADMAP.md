# Roadmap

## v0.1 (released)

- [x] npm package-lock and package.json checks
- [x] simple requirements.txt checks
- [x] OSV lookups for new npm/PyPI package versions
- [x] GitHub Actions privilege-drift checks
- [x] secret-pattern and exfil-path checks
- [x] Markdown, JSON, and SARIF reports

## v0.2 (released)

- [x] CI/CD supply-chain rules (`ci.*`): third-party package repos, downloaded
      signing keys/bootstrap installers, unpinned high-impact tool installs,
      floating tool container images, and unpinned high-impact GitHub Actions
- [x] broader CI/release file detection beyond GitHub Actions workflows
- [x] publish/secret-context severity escalation for CI/release files
- [x] allowlists for package-repo domains and `exclude_paths` for files
- [~] better severity policy configuration (per-rule toggles; full policy config pending)

## v0.3

- pnpm/yarn lockfile package extraction
- poetry.lock and uv.lock package extraction
- per-package and per-workflow allowlists
- release provenance and trusted-publishing hints
- package age / newly published version checks
- richer GitHub annotations and PR comments

## v1.0

- signed releases
- generated SBOM
- SLSA provenance
- GitHub Marketplace listing
- stable rule IDs and config schema
