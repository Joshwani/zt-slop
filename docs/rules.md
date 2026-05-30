# Rule reference

Severity values:

- `block`: intended to fail the PR by default
- `warn`: visible in output, but does not fail by default
- `info`: diagnostic context

## Blocking rules

| Rule ID | Meaning |
|---|---|
| `osv.malicious_package` | Newly introduced dependency matched a malicious package advisory from OSV |
| `lockfile.remote_dependency` | Lockfile added a remote/local dependency source such as `git+ssh`, `github:`, or `file:` |
| `lockfile.insecure_url` | Lockfile added an `http://` URL |
| `lockfile.untrusted_registry_domain` | Lockfile added a URL outside `allowed_registry_domains` |
| `workflow.pull_request_target` | Workflow added `pull_request_target` |
| `workflow.write_all_permissions` | Workflow added `permissions: write-all` |
| `workflow.secret_exfil_path` | Workflow diff contains both secret/env access and network transfer commands |
| `workflow.pr_target_checkout_head` | Workflow adds `pull_request_target` and appears to reference PR-controlled head code |
| `package_json.lifecycle_script` | package.json adds or changes npm install-time lifecycle scripts |
| `package_json.remote_dependency` | package.json adds a dependency spec pointing to remote/local source |
| `requirements.remote_dependency` | requirements file adds a remote/local source |
| `secret.*` | known token/private-key pattern added to the diff |
| `code.exfil_path` | changed file adds secret/env access and outbound network behavior |
| `ci.third_party_package_repo` | CI/release file adds a mutable third-party package repository (apt/yum/dnf/zypper/apk/brew) |
| `ci.downloaded_package_key_or_bootstrap` | CI/release file downloads a package signing key or pipes a bootstrap installer into a shell |
| `ci.unpinned_high_impact_tool_install` | CI/release file installs a high-impact security/release tool without an exact version or digest |
| `ci.floating_high_impact_tool_image` | CI/release file runs a high-impact tool container by `latest` or an implicit tag instead of a digest |
| `ci.high_impact_action_not_sha_pinned` | CI/release file uses a high-impact GitHub Action not pinned to a full 40-character commit SHA |

## Warning rules

| Rule ID | Meaning |
|---|---|
| `workflow.unpinned_action` | Workflow uses an action ref that is not a full commit SHA |
| `workflow.write_permission` | Workflow adds a write-scoped token permission |
| `workflow.persist_credentials` | Workflow enables checkout credential persistence |
| `workflow.publish_step` | Workflow adds a publish-like command |
| `workflow.untrusted_context_in_run` | Workflow directly interpolates PR context into a shell run step |
| `lockfile.integrity_removed` | Lockfile removes integrity metadata |
| `package_json.floating_dependency` | package.json uses `latest`, `next`, `canary`, or `*` |
| `osv.vulnerable_package` | Newly introduced dependency matched a non-malicious OSV vulnerability |
| `code.dangerous_shell` | Added line contains shell/eval behavior commonly used in droppers |

## CI/CD supply-chain rules

The `ci.*` rules only inspect added lines in CI/release automation files. The
matched paths include `.github/workflows/*`, `.circleci/config.y(a)ml`,
`.gitlab-ci.y(a)ml`, `.gitlab/ci/*`, `Jenkinsfile`, `azure-pipelines.y(a)ml`,
`bitbucket-pipelines.y(a)ml`, `buildkite.y(a)ml`, `.buildkite/*`,
`Taskfile.y(a)ml`, `Makefile`, and release/publish shell scripts under
`ci/`, `ci_cd/`, and `scripts/`. `.github/workflows/*` remains a subset, so the
existing `workflow.*` rules still apply.

These rules target the LiteLLM-style failure mode where a PR adds a CI job that
installs a mutable third-party security/release tool at runtime from an external
package source. The problem is not the tool itself; it is installing a
high-impact tool from a mutable source without an exact pinned version and
verification.

Contextual escalation: if a CI/release file is publish-capable or
secret-bearing (it contains things like `twine upload`, `docker push`,
`gh release`, `id-token: write`, `permissions: write-all`, or token names such
as `NPM_TOKEN`/`PYPI_TOKEN`/`AWS_ACCESS_KEY_ID`), a `warn`-level finding is
escalated to `block` and annotated with an explanation that mutable tool
installation can expose release credentials.

Allowlisting: `allowed_package_repo_domains` may downgrade a third-party repo
finding to `warn` when every URL on the line resolves (by parsed hostname, never
substring) to an allowlisted domain. It still warns, because mutable repos
remain risky.
