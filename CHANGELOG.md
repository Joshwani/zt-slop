# Changelog

All notable changes to ZT-Slop are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is in `0.x`, rule IDs and the config schema may still change.

## [Unreleased]

## [0.2.1] - 2026-05-31

### Added

- Inline suppression: a diff line containing `zt-slop:ignore` (or a region wrapped
  in `zt-slop:ignore-start` / `zt-slop:ignore-end`) is skipped by every analyzer,
  including the secret/network co-occurrence rule.

### Changed

- ZT-Slop now scans its own source, tests, and demo with no path exclusions. The
  repo's `exclude_paths` entries were removed in favor of line-precise inline
  suppression on the specific pattern-definition and attack-fixture lines.

## [0.2.0] - 2026-05-30

### Added

- New `ci_supply_chain` rule family for CI/CD and release automation files,
  inspecting only added diff lines:
  - `ci.third_party_package_repo` — a mutable third-party apt/yum/dnf/zypper/apk/brew
    repository is added in CI.
  - `ci.downloaded_package_key_or_bootstrap` — a package signing key or bootstrap
    installer is downloaded or piped into a shell at CI runtime.
  - `ci.unpinned_high_impact_tool_install` — a high-impact security/release tool is
    installed without an exact version or digest.
  - `ci.floating_high_impact_tool_image` — a high-impact tool container is run by
    `latest` or an implicit tag instead of a digest.
  - `ci.high_impact_action_not_sha_pinned` — a high-impact GitHub Action is not pinned
    to a full 40-character commit SHA.
- `is_ci_or_release_file()` detection covering GitHub Actions, CircleCI, GitLab CI,
  Jenkins, Azure/Bitbucket/Buildkite pipelines, `Taskfile`/`Makefile`, and
  release/publish shell scripts. `.github/workflows/*` remains a subset, so existing
  `workflow.*` rules are unchanged.
- Publish/secret-context escalation: a `warn`-level CI finding becomes a `block` when
  the file is publish-capable or secret-bearing, with an explanatory note.
- `allowed_package_repo_domains` config: hostname-based allowlist (parsed via
  `urllib.parse`, never substring) that downgrades third-party repo findings to `warn`.
- `exclude_paths` config: globs and directory prefixes that opt files out of all
  analyzers (useful for vendored code and fixtures containing attack-pattern literals).

### Changed

- The `ci_supply_chain` config section is added to defaults and is backward compatible;
  omitting it uses the built-in defaults.
- The moving `v0` tag now tracks this release, so consumers pinned to
  `Joshwani/zt-slop@v0` receive these rules automatically.

## [0.1.0] - 2026-05-28

### Added

- Initial release: deterministic PR supply-chain scanner that does not execute PR code.
- npm `package.json` and lockfile checks, `requirements.txt` checks, and OSV lookups for
  newly introduced npm/PyPI package versions.
- GitHub Actions privilege-drift checks, secret-pattern detection, and secret-exfil-path
  detection.
- Markdown, JSON, and SARIF reports, plus GitHub annotations.

[Unreleased]: https://github.com/Joshwani/zt-slop/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Joshwani/zt-slop/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Joshwani/zt-slop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Joshwani/zt-slop/releases/tag/v0.1.0
