# Threat model

ZT-Slop is a merge-time tripwire for PR-introduced supply-chain risk.

## Threats in scope

- A PR adds or updates a dependency to a known malicious package version.
- A PR changes a lockfile so a dependency resolves to a non-registry URL.
- A PR adds install-time execution through npm lifecycle scripts.
- A PR changes a GitHub Actions workflow to run with more privilege.
- A PR adds a workflow path that can read secrets and send them out over the network.
- A PR accidentally commits an obvious token or private key.

## Threats out of scope for v0

- Full malware deobfuscation.
- Runtime sandboxing of tests or builds.
- Complete semantic analysis of every language.
- Proving that a dependency is safe.
- Detecting malicious maintainers who already control the base repository.

## Non-goals

ZT-Slop does not replace code review, branch protection, least-privilege CI tokens, dependency pinning, provenance, or release signing. It is designed to give maintainers a high-signal warning before they merge a risky diff.

## Core safety invariant

ZT-Slop must never execute code from the pull request under review.
