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
