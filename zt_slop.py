#!/usr/bin/env python3
"""
ZT-Slop: a deterministic PR check for supply-chain risk.

This scanner is intentionally boring:
- It parses git diffs and manifests.
- It optionally queries OSV for newly introduced packages.
- It never installs dependencies, imports project code, or runs PR code.
- It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import json
import os
import re
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


VERSION = "0.2.0"

# High-impact CLI tools whose unpinned installation in CI is a supply-chain risk.
HIGH_IMPACT_TOOLS: List[str] = [
    # Security/release scanners and signing tools.
    "trivy",
    "grype",
    "syft",
    "osv-scanner",
    "cosign",
    "snyk",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "checkov",
    "terrascan",
    # Release / publish / cloud tooling.
    "twine",
    "build",
    "wheel",
    "setuptools",
    "hatch",
    "poetry",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "goreleaser",
    "docker",
    "kubectl",
    "helm",
    "gh",
    "awscli",
    "aws",
    "gcloud",
    "az",
]

# Narrower set used when matching floating container image names, to avoid
# false positives from generic words like "build" or "npm".
FLOATING_IMAGE_TOOLS: List[str] = [
    "trivy",
    "grype",
    "syft",
    "cosign",
    "goreleaser",
    "kubectl",
    "helm",
    "aws",
    "gcloud",
    "azure",
    "snyk",
    "semgrep",
]

# High-impact GitHub Actions that should be pinned to a full commit SHA.
HIGH_IMPACT_ACTIONS: List[str] = [
    "aquasecurity/trivy-action",
    "aquasecurity/setup-trivy",
    "docker/login-action",
    "docker/build-push-action",
    "pypa/gh-action-pypi-publish",
    "softprops/action-gh-release",
    "goreleaser/goreleaser-action",
    "sigstore/cosign-installer",
    "snyk/actions",
    "github/codeql-action",
    "google-github-actions/auth",
    "aws-actions/configure-aws-credentials",
    "azure/login",
]

DEFAULT_CONFIG: Dict[str, Any] = {
    "exclude_paths": [],
    "allowed_registry_domains": [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "files.pythonhosted.org",
    ],
    "osv": {
        "enabled": True,
        "warn_on_vulnerabilities": True,
        "timeout_seconds": 12,
    },
    "workflow": {
        "warn_on_unpinned_actions": True,
    },
    "ci_supply_chain": {
        "enabled": True,
        "block_third_party_package_repos": True,
        "block_downloaded_package_keys": True,
        "block_unpinned_high_impact_tools": True,
        "block_floating_tool_images": True,
        "block_high_impact_actions_not_sha_pinned": True,
        "high_impact_tools": list(HIGH_IMPACT_TOOLS),
        "high_impact_actions": list(HIGH_IMPACT_ACTIONS),
        "additional_ci_paths": [],
        "allowed_package_repo_domains": [],
        "allowed_bootstrap_domains": [],
    },
}

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
DEPENDENCY_FIELDS = {
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundledDependencies",
    "bundleDependencies",
}

LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
}

WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")
URL_RE = re.compile(r"https?://[^\s\"'<>),]+", re.IGNORECASE)
REMOTE_SPEC_RE = re.compile(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|ssh:|http:|https:|file:)", re.IGNORECASE)
WILDCARD_SPEC_RE = re.compile(r"^(?:\*|latest|next|canary)$", re.IGNORECASE)
EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")

NETWORK_SINK_RE = re.compile(
    r"\b(?:curl|wget|nc|netcat|Invoke-WebRequest|iwr|fetch\s*\(|axios\.(?:post|put|request)\s*\(|"
    r"requests\.(?:post|put|request)\s*\(|urllib\.request|http\.client|new\s+WebClient|dns\.resolve|"
    r"socket\.socket|net/http|http\.Post|http\.NewRequest)\b",
    re.IGNORECASE,
)
SECRET_SOURCE_RE = re.compile(
    r"(?:\bsecrets\.|\bprocess\.env\b|\bos\.environ\b|\benv\[[\"']|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|"
    r"\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY|API_KEY)[A-Z0-9_]*\b)",
    re.IGNORECASE,
)
DANGEROUS_SHELL_RE = re.compile(
    r"(?:curl\b[^\n|;]*\|\s*(?:sh|bash)|wget\b[^\n|;]*\|\s*(?:sh|bash)|"
    r"base64\s+-d\b|eval\s*\(|Function\s*\(|child_process\.(?:exec|execSync|spawn)\s*\(|"
    r"powershell\b.*(?:FromBase64String|Invoke-Expression))",
    re.IGNORECASE,
)
PUBLISH_RE = re.compile(
    r"\b(?:npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|twine\s+upload|python\s+-m\s+twine\s+upload|"
    r"cargo\s+publish|gem\s+push|docker\s+push|goreleaser\b)",
    re.IGNORECASE,
)

# --- CI/CD supply-chain detection ---------------------------------------------

# CI/release files we inspect. `.github/workflows/*` is a subset handled by
# is_workflow(); these patterns broaden coverage without replacing it.
CI_FILE_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"),
    re.compile(r"(^|/)\.circleci/config\.ya?ml$"),
    re.compile(r"(^|/)\.gitlab-ci\.ya?ml$"),
    re.compile(r"(^|/)\.gitlab/ci/[^/]+\.ya?ml$"),
    re.compile(r"(^|/)Jenkinsfile(\.[^/]+)?$"),
    re.compile(r"(^|/)azure-pipelines\.ya?ml$"),
    re.compile(r"(^|/)bitbucket-pipelines\.ya?ml$"),
    re.compile(r"(^|/)buildkite\.ya?ml$"),
    re.compile(r"(^|/)\.buildkite/[^/]+\.ya?ml$"),
    re.compile(r"(^|/)Taskfile\.ya?ml$"),
    re.compile(r"(^|/)Makefile$"),
    re.compile(r"(^|/)ci/[^/]+\.sh$"),
    re.compile(r"(^|/)ci_cd/[^/]+\.sh$"),
    re.compile(r"(^|/)scripts/ci[^/]*\.sh$"),
    re.compile(r"(^|/)scripts/release[^/]*\.sh$"),
    re.compile(r"(^|/)scripts/publish[^/]*\.sh$"),
]

# A third-party OS package repository is being added.
PACKAGE_REPO_RE = re.compile(
    r"(add-apt-repository"
    r"|/etc/apt/sources\.list"  # covers sources.list and sources.list.d/
    r"|rpm\s+--import"
    r"|yum-config-manager\s+--add-repo"
    r"|dnf\s+config-manager\s+--add-repo"
    r"|zypper\s+addrepo"
    r"|apk\s+add\s+--repository"
    r"|brew\s+tap)",
    re.IGNORECASE,
)

# A signing key or installer bootstrap is being downloaded/piped.
PACKAGE_KEY_OR_BOOTSTRAP_RE = re.compile(
    r"(apt-key\s+add"
    r"|gpg\s+--dearmor"
    r"|(?:curl|wget)\b[^\n|]*\bgpg\b"
    r"|(?:curl|wget)\b[^\n]*public\.key"
    r"|(?:curl|wget)\b[^\n]*install\.sh"
    r"|(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b)",
    re.IGNORECASE,
)

# Package-manager install verbs. The captured `rest` holds the arguments that
# may name a high-impact tool.
INSTALL_COMMAND_RE = re.compile(
    r"\b("
    r"apt-get\s+install|apt\s+install|aptitude\s+install|"
    r"yum\s+install|dnf\s+install|zypper\s+install|apk\s+add|"
    r"brew\s+install|"
    r"pipx\s+install|python[0-9.]*\s+-m\s+pip\s+install|pip[0-9.]*\s+install|"
    r"npm\s+install\s+-g|npm\s+install\s+--global|npm\s+i\s+-g|"
    r"pnpm\s+add\s+-g|pnpm\s+add\s+--global|"
    r"yarn\s+global\s+add|"
    r"go\s+install|cargo\s+install"
    r")\b(?P<rest>[^\n]*)",
    re.IGNORECASE,
)

# `image:` step keys (GitLab/Buildkite/etc.) referencing a container image.
IMAGE_KEY_RE = re.compile(r"\bimage\s*:\s*[\"']?([^\s\"']+)", re.IGNORECASE)
DOCKER_RUN_RE = re.compile(r"\bdocker\s+run\b(?P<rest>[^\n]*)", re.IGNORECASE)
IMAGE_LIKE_RE = re.compile(
    r"^[A-Za-z0-9][\w./-]*(?::[\w.][\w.-]*)?(?:@sha256:[0-9a-fA-F]+)?$"
)

# `uses: owner/repo@ref` GitHub Action references.
USES_ACTION_RE = re.compile(r"\buses\s*:\s*[\"']?([^@\s\"']+)@([^\s\"'#]+)")

# A sha256 digest reference, e.g. an image pinned by digest.
SHA256_RE = re.compile(r"\bsha256:[0-9a-fA-F]{64}\b", re.IGNORECASE)
# A full 40-character git commit SHA.
FULL_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# An exact version/digest pin attached via ==, =, or @ (requires major.minor).
EXACT_PIN_RE = re.compile(r"(?:==|=|@)v?\d+\.\d+(?:\.\d+)?(?:[-.+][0-9A-Za-z.-]+)?\b")

# Indicators that a CI/release file is publish-capable or secret-bearing.
PUBLISH_OR_SECRET_CONTEXT_RE = re.compile(
    r"(twine\s+upload|npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|cargo\s+publish"
    r"|docker\s+push|goreleaser|gh\s+release|pypa/gh-action-pypi-publish"
    r"|id-token\s*:\s*write|permissions\s*:\s*write-all|packages\s*:\s*write|contents\s*:\s*write"
    r"|\bNPM_TOKEN\b|\bPYPI_TOKEN\b|\bTWINE_PASSWORD\b|\bGITHUB_TOKEN\b|\bAWS_ACCESS_KEY_ID\b"
    r"|\bAWS_SECRET_ACCESS_KEY\b|\bGOOGLE_APPLICATION_CREDENTIALS\b|\bAZURE_CLIENT_SECRET\b|secrets\.)",
    re.IGNORECASE,
)

PUBLISH_CONTEXT_NOTE = (
    "This CI/release file appears publish-capable or secret-bearing, so mutable "
    "tool installation can expose release credentials."
)

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "block"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"), "block"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "block"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "block"),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "block"),
    (
        "generic_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|token|secret|password|private[_-]?key)\b\s*[:=]\s*[\"'][A-Za-z0-9_./+=:-]{24,}[\"']"
        ),
        "warn",
    ),
]


@dataclasses.dataclass(frozen=True)
class ChangedLine:
    kind: str  # "add" or "remove"
    path: str
    line: Optional[int]
    text: str


@dataclasses.dataclass
class ChangedFile:
    path: str
    added: List[ChangedLine] = dataclasses.field(default_factory=list)
    removed: List[ChangedLine] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Finding:
    severity: str  # block, warn, info
    rule_id: str
    title: str
    file: Optional[str]
    line: Optional[int]
    evidence: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class ScanError(RuntimeError):
    pass


def run_git(args: Sequence[str], cwd: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise ScanError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def load_config(path: Optional[str]) -> Dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if not path:
        return config
    p = Path(path)
    if not p.exists():
        return config
    try:
        with p.open("r", encoding="utf-8") as f:
            user_config = json.load(f)
    except Exception as exc:
        raise ScanError(f"failed to parse config {path}: {exc}") from exc
    return deep_merge(config, user_config)


def deep_merge(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def git_diff(base: str, head: str) -> str:
    # Prefer three-dot PR semantics. Fall back to two-dot for local use or shallow repos.
    attempts: List[List[str]] = [
        ["diff", "--no-color", "--no-ext-diff", "--unified=0", f"{base}...{head}"],
        ["diff", "--no-color", "--no-ext-diff", "--unified=0", base, head],
    ]
    errors: List[str] = []
    for args in attempts:
        proc = run_git(args, check=False)
        if proc.returncode == 0:
            return proc.stdout
        errors.append(proc.stderr.strip())
    raise ScanError("unable to compute git diff: " + " | ".join(e for e in errors if e))


def parse_diff(diff_text: str) -> Dict[str, ChangedFile]:
    files: Dict[str, ChangedFile] = {}
    current_path: Optional[str] = None
    old_line: Optional[int] = None
    new_line: Optional[int] = None

    hunk_re = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            current_path = None
            old_line = None
            new_line = None
            continue
        if raw.startswith("+++ "):
            path = raw[4:]
            if path == "/dev/null":
                current_path = None
            else:
                if path.startswith("b/"):
                    path = path[2:]
                current_path = path
                files.setdefault(current_path, ChangedFile(path=current_path))
            continue
        if raw.startswith("@@ "):
            m = hunk_re.search(raw)
            if m:
                old_line = int(m.group(1))
                new_line = int(m.group(2))
            continue
        if current_path is None or old_line is None or new_line is None:
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            text = raw[1:]
            files[current_path].added.append(ChangedLine("add", current_path, new_line, text))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            text = raw[1:]
            files[current_path].removed.append(ChangedLine("remove", current_path, old_line, text))
            old_line += 1
        else:
            # Context lines are uncommon with --unified=0, but handle them anyway.
            if raw.startswith(" "):
                old_line += 1
                new_line += 1

    return files


def git_show_text(rev: str, path: str) -> Optional[str]:
    proc = run_git(["show", f"{rev}:{path}"], check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_show_json(rev: str, path: str) -> Optional[Any]:
    text = git_show_text(rev, path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def is_workflow(path: str) -> bool:
    return bool(WORKFLOW_RE.search(path))


def is_lockfile(path: str) -> bool:
    name = Path(path).name
    return name in LOCKFILE_NAMES or name.startswith("requirements") and name.endswith(".txt")


def is_probably_docs(path: str) -> bool:
    lower = path.lower()
    return lower.endswith((".md", ".markdown", ".rst", ".txt")) and not Path(path).name.startswith("requirements")


def allowed_domain(host: str, allowed_domains: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for allowed in allowed_domains:
        allowed = str(allowed).lower().rstrip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def is_excluded(path: str, config: Optional[Dict[str, Any]]) -> bool:
    """True if `path` matches a configured `exclude_paths` glob/prefix.

    Excluded files are skipped by every analyzer. This is how a project opts a
    file out of scanning, e.g. the scanner's own pattern-definition source or
    test fixtures that intentionally contain attack-pattern literals.
    """
    globs = (config or {}).get("exclude_paths", []) or []
    name = Path(path).name
    for pat in globs:
        pat = str(pat)
        if pat.endswith("/"):
            if path == pat[:-1] or path.startswith(pat):
                return True
            continue
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(name, pat) or path == pat:
            return True
    return False


def is_ci_or_release_file(path: str, config: Optional[Dict[str, Any]] = None) -> bool:
    """True if `path` is a CI/CD or release automation file.

    `.github/workflows/*` is intentionally a subset of this matcher, not a
    replacement for is_workflow().
    """
    for pattern in CI_FILE_PATTERNS:
        if pattern.search(path):
            return True
    if config:
        additional = config.get("ci_supply_chain", {}).get("additional_ci_paths", []) or []
        name = Path(path).name
        for glob_pat in additional:
            glob_pat = str(glob_pat)
            if fnmatch.fnmatch(path, glob_pat) or fnmatch.fnmatch(name, glob_pat) or path == glob_pat:
                return True
    return False


def line_has_exact_version_or_digest(line: str) -> bool:
    """Conservatively detect an exact version or digest pin on a line.

    Returns True for things like `trivy=0.69.3`, `twine==5.1.1`, `tool@1.2.3`,
    and `@sha256:<64 hex>`. When in doubt we return False so the caller flags it.
    """
    if SHA256_RE.search(line):
        return True
    if EXACT_PIN_RE.search(line):
        return True
    return False


def extract_urls(line: str) -> List[str]:
    return URL_RE.findall(line)


def hostname_allowed(url: str, allowed_domains: Iterable[str]) -> bool:
    """Parse a URL and compare its hostname against an allowlist.

    Comparison is by hostname (never substring) using urllib.parse.
    """
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return False
    if not host:
        return False
    return allowed_domain(host, allowed_domains)


def ci_file_has_publish_or_secret_context(changed: "ChangedFile") -> bool:
    """True if the diff for this CI/release file shows publish/secret indicators."""
    for line in changed.added:
        if PUBLISH_OR_SECRET_CONTEXT_RE.search(line.text):
            return True
    for line in changed.removed:
        if PUBLISH_OR_SECRET_CONTEXT_RE.search(line.text):
            return True
    return False


def _install_tool_names(token: str) -> Set[str]:
    """Extract candidate tool names from an install argument token.

    Strips version/digest separators and splits path-like specs so that
    `aquasec/trivy@1.2.3` and `github.com/aquasecurity/trivy/cmd/trivy@latest`
    both yield `trivy`.
    """
    base = re.split(r"[=@:]", token, 1)[0].strip().lower()
    names: Set[str] = set()
    if base:
        names.add(base)
        for seg in base.split("/"):
            seg = seg.strip()
            if seg:
                names.add(seg)
    return names


def _high_impact_install_on_line(line: str, high_impact_tools: Sequence[str]) -> Optional[str]:
    """Return the high-impact tool name installed on this line, or None.

    Only matches recognized package-manager install verbs so ordinary commands
    like `npm ci`, `poetry install`, or `cargo build` are ignored.
    """
    tool_set = {str(t).lower() for t in high_impact_tools}
    for m in INSTALL_COMMAND_RE.finditer(line):
        rest = m.group("rest") or ""
        for token in rest.split():
            if token.startswith("-"):
                continue
            for name in _install_tool_names(token):
                if name in tool_set:
                    return name
    return None


def _image_refs_on_line(line: str) -> List[str]:
    """Collect candidate container image references from a line."""
    refs: List[str] = []
    m_run = DOCKER_RUN_RE.search(line)
    if m_run:
        for token in (m_run.group("rest") or "").split():
            if token.startswith("-") or "=" in token:
                continue
            if IMAGE_LIKE_RE.match(token):
                refs.append(token)
                break  # first positional arg to `docker run` is the image
    m_img = IMAGE_KEY_RE.search(line)
    if m_img:
        refs.append(m_img.group(1))
    return refs


def _image_is_floating(image: str, floating_tools: Sequence[str]) -> bool:
    """True if `image` references a high-impact tool and is not digest/tag pinned."""
    if SHA256_RE.search(image):
        return False
    name_part = image.split("@", 1)[0]
    repo, _, tag = name_part.partition(":")
    repo_lower = repo.lower()
    if not any(tool in repo_lower for tool in floating_tools):
        return False
    # No tag, or an explicitly floating `latest` tag, is unpinned.
    if not tag or tag.lower() == "latest":
        return True
    return False


def redact(text: str) -> str:
    redacted = text
    for _, pattern, _ in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: mask_secret(m.group(0)), redacted)
    redacted = re.sub(
        r"(?i)(\b(?:token|secret|password|api[_-]?key|private[_-]?key)\b\s*[:=]\s*[\"']?)([^\"'\s]{8,})([\"']?)",
        lambda m: f"{m.group(1)}{mask_secret(m.group(2))}{m.group(3)}",
        redacted,
    )
    return redacted


def mask_secret(value: str) -> str:
    if len(value) <= 12:
        return "[REDACTED]"
    return f"{value[:4]}…REDACTED…{value[-4:]}"


def add_finding(findings: List[Finding], finding: Finding) -> None:
    key = (finding.severity, finding.rule_id, finding.file, finding.line, finding.evidence)
    for existing in findings:
        if (existing.severity, existing.rule_id, existing.file, existing.line, existing.evidence) == key:
            return
    findings.append(finding)


def analyze_workflows(files: Dict[str, ChangedFile], findings: List[Finding], config: Dict[str, Any]) -> None:
    warn_unpinned = bool(config.get("workflow", {}).get("warn_on_unpinned_actions", True))

    for path, changed in files.items():
        if not is_workflow(path):
            continue
        added_text = "\n".join(line.text for line in changed.added)
        has_added_secret_source = any(SECRET_SOURCE_RE.search(line.text) for line in changed.added)
        has_added_network_sink = any(NETWORK_SINK_RE.search(line.text) for line in changed.added)
        has_added_pull_request_target = any(re.search(r"\bpull_request_target\b", line.text) for line in changed.added)

        for line in changed.added:
            stripped = line.text.strip()
            if re.search(r"\bpull_request_target\b", stripped):
                add_finding(
                    findings,
                    Finding(
                        "block",
                        "workflow.pull_request_target",
                        "Workflow adds pull_request_target",
                        path,
                        line.line,
                        "A PR changed a workflow to use pull_request_target, which runs in the base repository context.",
                        "Use pull_request for untrusted PR code, or split privileged work into a separate trusted workflow.",
                    ),
                )

            if re.search(r"\bpermissions\s*:\s*write-all\b", stripped):
                add_finding(
                    findings,
                    Finding(
                        "block",
                        "workflow.write_all_permissions",
                        "Workflow grants write-all token permissions",
                        path,
                        line.line,
                        "The workflow adds permissions: write-all.",
                        "Grant only the specific read/write scopes required by the job.",
                    ),
                )

            m_perm = re.search(
                r"\b(contents|packages|actions|checks|deployments|id-token|issues|pull-requests|statuses)\s*:\s*write\b",
                stripped,
            )
            if m_perm:
                severity = "block" if has_added_pull_request_target else "warn"
                add_finding(
                    findings,
                    Finding(
                        severity,
                        "workflow.write_permission",
                        "Workflow adds write-scoped token permission",
                        path,
                        line.line,
                        f"The workflow adds `{m_perm.group(1)}: write`.",
                        "Keep GITHUB_TOKEN permissions read-only in PR workflows unless write access is strictly required.",
                    ),
                )

            if warn_unpinned:
                m_uses = re.search(r"\buses\s*:\s*[\"']?([^@\s\"']+)@([^\s\"'#]+)", stripped)
                if m_uses:
                    action_name = m_uses.group(1)
                    action_ref = m_uses.group(2)
                    if not re.fullmatch(r"[0-9a-fA-F]{40}", action_ref):
                        add_finding(
                            findings,
                            Finding(
                                "warn",
                                "workflow.unpinned_action",
                                "Workflow uses an unpinned action ref",
                                path,
                                line.line,
                                f"`{action_name}@{action_ref}` is not pinned to a full commit SHA.",
                                "Pin third-party actions to a full commit SHA where practical.",
                            ),
                        )

            if re.search(r"\bpersist-credentials\s*:\s*true\b", stripped, flags=re.IGNORECASE):
                add_finding(
                    findings,
                    Finding(
                        "warn",
                        "workflow.persist_credentials",
                        "Checkout persists credentials",
                        path,
                        line.line,
                        "The workflow enables persist-credentials: true.",
                        "Set persist-credentials: false unless later steps need the checkout token.",
                    ),
                )

            if PUBLISH_RE.search(stripped):
                add_finding(
                    findings,
                    Finding(
                        "warn",
                        "workflow.publish_step",
                        "Workflow adds a publishing command",
                        path,
                        line.line,
                        f"Added publish-like command: `{redact(stripped)[:180]}`.",
                        "Review release conditions, token scopes, and trusted publishing before merging.",
                    ),
                )

            if "${{" in stripped and re.search(r"github\.(event\.)?pull_request|github\.head_ref|github\.event\.issue", stripped):
                if stripped.startswith("run:") or " run:" in stripped:
                    add_finding(
                        findings,
                        Finding(
                            "warn",
                            "workflow.untrusted_context_in_run",
                            "Workflow interpolates untrusted PR context into a run step",
                            path,
                            line.line,
                            f"Added run step uses GitHub context: `{redact(stripped)[:180]}`.",
                            "Pass untrusted values through environment variables and quote them carefully; avoid direct shell interpolation.",
                        ),
                    )

        if has_added_secret_source and has_added_network_sink:
            add_finding(
                findings,
                Finding(
                    "block",
                    "workflow.secret_exfil_path",
                    "Workflow change combines secrets/env access with network egress",
                    path,
                    first_line(changed.added),
                    "The workflow diff contains both secret/env access and network transfer commands.",
                    "Separate secret handling from untrusted code and review any outbound network transfer.",
                ),
            )

        if has_added_pull_request_target and re.search(r"github\.event\.pull_request\.head|head\.sha|head_ref", added_text):
            add_finding(
                findings,
                Finding(
                    "block",
                    "workflow.pr_target_checkout_head",
                    "pull_request_target workflow appears to use PR-controlled code",
                    path,
                    first_line(changed.added),
                    "The diff adds pull_request_target and references pull request head data.",
                    "Do not checkout or execute untrusted PR head code in a pull_request_target workflow.",
                ),
            )


def first_line(lines: Sequence[ChangedLine]) -> Optional[int]:
    return lines[0].line if lines else None


def analyze_lockfiles(files: Dict[str, ChangedFile], findings: List[Finding], config: Dict[str, Any]) -> None:
    allowed_domains = config.get("allowed_registry_domains", DEFAULT_CONFIG["allowed_registry_domains"])
    for path, changed in files.items():
        if not is_lockfile(path):
            continue
        for line in changed.added:
            stripped = line.text.strip()
            if REMOTE_SPEC_RE.search(strip_quotes(stripped)) or re.search(r"\b(?:git\+ssh|git\+https|github:|gitlab:|bitbucket:|file:)\b", stripped, re.IGNORECASE):
                add_finding(
                    findings,
                    Finding(
                        "block",
                        "lockfile.remote_dependency",
                        "Lockfile adds a remote or local dependency source",
                        path,
                        line.line,
                        f"Added lockfile line references a remote/local source: `{redact(stripped)[:180]}`.",
                        "Use package registry artifacts from trusted registries, or explicitly allowlist this source after review.",
                    ),
                )

            for url in URL_RE.findall(stripped):
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname or ""
                if parsed.scheme.lower() == "http":
                    add_finding(
                        findings,
                        Finding(
                            "block",
                            "lockfile.insecure_url",
                            "Lockfile adds an insecure HTTP URL",
                            path,
                            line.line,
                            f"Added URL uses http: `{url}`.",
                            "Use HTTPS registry URLs and verify the lockfile was generated by a trusted package manager.",
                        ),
                    )
                elif host and not allowed_domain(host, allowed_domains):
                    add_finding(
                        findings,
                        Finding(
                            "block",
                            "lockfile.untrusted_registry_domain",
                            "Lockfile adds a URL outside allowed registry domains",
                            path,
                            line.line,
                            f"Added URL host `{host}` is not in allowed_registry_domains.",
                            "Review the source and add the domain to zt-slop.json only if it is expected.",
                        ),
                    )

        removed_integrity = any("integrity" in line.text for line in changed.removed)
        added_integrity = any("integrity" in line.text for line in changed.added)
        if removed_integrity and not added_integrity and Path(path).name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}:
            add_finding(
                findings,
                Finding(
                    "warn",
                    "lockfile.integrity_removed",
                    "Lockfile removes integrity metadata",
                    path,
                    first_line(changed.removed),
                    "The diff removes integrity metadata without adding replacement integrity metadata in the same file diff.",
                    "Regenerate the lockfile from a trusted environment and confirm package integrity entries are present.",
                ),
            )


def strip_quotes(text: str) -> str:
    return text.strip().strip("'\"")


def analyze_package_json(files: Dict[str, ChangedFile], base: str, head: str, findings: List[Finding]) -> List[Tuple[str, str, str, str]]:
    osv_candidates: List[Tuple[str, str, str, str]] = []
    changed_package_jsons = [path for path in files if Path(path).name == "package.json"]
    for path in changed_package_jsons:
        base_json = git_show_json(base, path) or {}
        head_json = git_show_json(head, path)
        if head_json is None:
            add_finding(
                findings,
                Finding(
                    "warn",
                    "package_json.invalid",
                    "package.json is not valid JSON at head",
                    path,
                    None,
                    "ZT-Slop could not parse the changed package.json at the PR head.",
                    "Verify package.json syntax before merging.",
                ),
            )
            continue
        if not isinstance(head_json, dict):
            continue
        if not isinstance(base_json, dict):
            base_json = {}

        base_scripts = base_json.get("scripts") if isinstance(base_json.get("scripts"), dict) else {}
        head_scripts = head_json.get("scripts") if isinstance(head_json.get("scripts"), dict) else {}
        for script in sorted(LIFECYCLE_SCRIPTS):
            if script in head_scripts and head_scripts.get(script) != base_scripts.get(script):
                cmd = str(head_scripts.get(script, ""))
                add_finding(
                    findings,
                    Finding(
                        "block",
                        "package_json.lifecycle_script",
                        f"package.json adds or changes `{script}` lifecycle script",
                        path,
                        find_added_line(files[path], script),
                        f"Lifecycle script `{script}` changed to: `{redact(cmd)[:180]}`.",
                        "Review install-time execution carefully; avoid lifecycle scripts unless they are required and audited.",
                    ),
                )
                if NETWORK_SINK_RE.search(cmd) or DANGEROUS_SHELL_RE.search(cmd):
                    add_finding(
                        findings,
                        Finding(
                            "block",
                            "package_json.lifecycle_network_or_shell",
                            f"Lifecycle script `{script}` contains network or shell-execution behavior",
                            path,
                            find_added_line(files[path], script),
                            f"Lifecycle script command: `{redact(cmd)[:180]}`.",
                            "Do not run network-fetching or shell-evaluating commands during dependency installation.",
                        ),
                    )

        for field in sorted(DEPENDENCY_FIELDS):
            base_deps = base_json.get(field) if isinstance(base_json.get(field), dict) else {}
            head_deps = head_json.get(field) if isinstance(head_json.get(field), dict) else {}
            for name, spec_value in sorted(head_deps.items()):
                spec = str(spec_value)
                if base_deps.get(name) == spec:
                    continue
                line_no = find_added_line(files[path], name)
                if REMOTE_SPEC_RE.search(spec):
                    add_finding(
                        findings,
                        Finding(
                            "block",
                            "package_json.remote_dependency",
                            "package.json adds a remote or local dependency spec",
                            path,
                            line_no,
                            f"Dependency `{name}` in `{field}` uses spec `{redact(spec)}`.",
                            "Use a registry version range and lockfile integrity metadata unless this source is explicitly trusted.",
                        ),
                    )
                elif WILDCARD_SPEC_RE.search(spec):
                    add_finding(
                        findings,
                        Finding(
                            "warn",
                            "package_json.floating_dependency",
                            "package.json adds a floating dependency spec",
                            path,
                            line_no,
                            f"Dependency `{name}` in `{field}` uses floating spec `{spec}`.",
                            "Pin to a bounded semver range or exact version and commit the generated lockfile.",
                        ),
                    )
                elif EXACT_VERSION_RE.search(spec):
                    osv_candidates.append(("npm", name, normalize_npm_version(spec), path))

    return osv_candidates


def find_added_line(changed: ChangedFile, needle: str) -> Optional[int]:
    for line in changed.added:
        if needle in line.text:
            return line.line
    return first_line(changed.added)


def normalize_npm_version(spec: str) -> str:
    return spec[1:] if spec.startswith("v") else spec


def analyze_requirements(files: Dict[str, ChangedFile], findings: List[Finding]) -> List[Tuple[str, str, str, str]]:
    candidates: List[Tuple[str, str, str, str]] = []
    for path, changed in files.items():
        name = Path(path).name.lower()
        if not (name.startswith("requirements") and name.endswith(".txt")):
            continue
        for line in changed.added:
            stripped = line.text.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("--"):
                continue
            if re.search(r"(?:^|\s)(?:-e\s+)?(?:git\+|https?://|ssh://|file:)", stripped, re.IGNORECASE) or " @ http" in stripped:
                add_finding(
                    findings,
                    Finding(
                        "block",
                        "requirements.remote_dependency",
                        "requirements file adds a remote or local dependency source",
                        path,
                        line.line,
                        f"Added requirement: `{redact(stripped)[:180]}`.",
                        "Use pinned packages from a trusted package index unless this source is explicitly reviewed.",
                    ),
                )
            parsed = parse_pinned_requirement(stripped)
            if parsed:
                pkg, version = parsed
                candidates.append(("PyPI", pkg, version, path))
    return candidates


def parse_pinned_requirement(line: str) -> Optional[Tuple[str, str]]:
    # Handles simple cases like requests==2.31.0 or pkg[extra]==1.2.3; ignores markers after ;.
    line = line.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*={2,3}\s*([A-Za-z0-9_.!+\-]+)", line)
    if not m:
        return None
    return canonical_pypi_name(m.group(1)), m.group(2)


def canonical_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def collect_npm_lock_candidates(files: Dict[str, ChangedFile], base: str, head: str) -> List[Tuple[str, str, str, str]]:
    candidates: List[Tuple[str, str, str, str]] = []
    for path in files:
        if Path(path).name not in {"package-lock.json", "npm-shrinkwrap.json"}:
            continue
        base_json = git_show_json(base, path)
        head_json = git_show_json(head, path)
        if head_json is None:
            continue
        base_pkgs = collect_npm_lock_packages(base_json) if base_json is not None else set()
        head_pkgs = collect_npm_lock_packages(head_json)
        for name, version in sorted(head_pkgs - base_pkgs):
            if name and version:
                candidates.append(("npm", name, version, path))
    return candidates


def collect_npm_lock_packages(lock_json: Any) -> Set[Tuple[str, str]]:
    pkgs: Set[Tuple[str, str]] = set()
    if not isinstance(lock_json, dict):
        return pkgs

    packages = lock_json.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not package_path or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            name = package_name_from_lock_path(package_path)
            if name:
                pkgs.add((name, version))

    deps = lock_json.get("dependencies")
    if isinstance(deps, dict):
        walk_npm_deps(deps, pkgs)
    return pkgs


def package_name_from_lock_path(package_path: str) -> Optional[str]:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    after = package_path.split(marker)[-1].strip("/")
    if not after:
        return None
    parts = after.split("/")
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def walk_npm_deps(deps: Dict[str, Any], pkgs: Set[Tuple[str, str]]) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str):
            pkgs.add((str(name), version))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            walk_npm_deps(nested, pkgs)


def analyze_secrets_and_exfil(files: Dict[str, ChangedFile], findings: List[Finding]) -> None:
    for path, changed in files.items():
        if is_probably_docs(path):
            continue

        secret_lines: List[ChangedLine] = []
        network_lines: List[ChangedLine] = []

        for line in changed.added:
            text = line.text
            for name, pattern, severity in SECRET_PATTERNS:
                if pattern.search(text):
                    add_finding(
                        findings,
                        Finding(
                            severity,
                            f"secret.{name}",
                            "Potential secret added in diff",
                            path,
                            line.line,
                            f"Matched {name} pattern in added line: `{redact(text.strip())[:180]}`.",
                            "Remove the secret, rotate it if real, and use a secret manager or CI secret store instead.",
                        ),
                    )
            if SECRET_SOURCE_RE.search(text):
                secret_lines.append(line)
            if NETWORK_SINK_RE.search(text):
                network_lines.append(line)
            if DANGEROUS_SHELL_RE.search(text):
                severity = "block" if is_workflow(path) or Path(path).name in {"package.json", "Dockerfile"} else "warn"
                add_finding(
                    findings,
                    Finding(
                        severity,
                        "code.dangerous_shell",
                        "Added line contains dangerous shell/eval behavior",
                        path,
                        line.line,
                        f"Added line: `{redact(text.strip())[:180]}`.",
                        "Avoid piping network content into shells, base64-decoded execution, eval, or child process execution without review.",
                    ),
                )

        if secret_lines and network_lines:
            add_finding(
                findings,
                Finding(
                    "block",
                    "code.exfil_path",
                    "Diff combines secret/env access with outbound network behavior",
                    path,
                    first_line(secret_lines) or first_line(network_lines),
                    "The changed file has added lines that read secrets/env and added lines that send data over the network.",
                    "Review for credential or data exfiltration; keep secrets away from untrusted code paths.",
                ),
            )


def _action_is_high_impact(action_name: str, high_impact_actions: Sequence[str]) -> bool:
    name = action_name.lower()
    for action in high_impact_actions:
        action = str(action).lower()
        if name == action or name.startswith(action + "/"):
            return True
    return False


def scan_ci_supply_chain(changed_files: Dict[str, "ChangedFile"], config: Dict[str, Any]) -> List[Finding]:
    """Inspect added lines in CI/release files for mutable supply-chain risk.

    This never executes anything; it only matches added diff lines against
    deterministic patterns for third-party repos, downloaded signing keys,
    unpinned high-impact tool installs, floating images, and unpinned actions.
    """
    cfg = (config or {}).get("ci_supply_chain", {}) or {}
    if not cfg.get("enabled", True):
        return []

    high_impact_tools = cfg.get("high_impact_tools", HIGH_IMPACT_TOOLS)
    high_impact_actions = cfg.get("high_impact_actions", HIGH_IMPACT_ACTIONS)
    allowed_repo_domains = cfg.get("allowed_package_repo_domains", []) or []

    block_repo = bool(cfg.get("block_third_party_package_repos", True))
    block_keys = bool(cfg.get("block_downloaded_package_keys", True))
    block_tools = bool(cfg.get("block_unpinned_high_impact_tools", True))
    block_images = bool(cfg.get("block_floating_tool_images", True))
    block_actions = bool(cfg.get("block_high_impact_actions_not_sha_pinned", True))

    findings: List[Finding] = []

    for path, changed in changed_files.items():
        if not is_ci_or_release_file(path, config):
            continue
        publish_context = ci_file_has_publish_or_secret_context(changed)

        def finalize(base_block: bool, recommendation: str) -> Tuple[str, str]:
            severity = "block" if base_block else "warn"
            recommendation_out = recommendation
            if publish_context:
                if severity == "warn":
                    severity = "block"
                recommendation_out = f"{recommendation} {PUBLISH_CONTEXT_NOTE}"
            return severity, recommendation_out

        for line in changed.added:
            text = line.text
            evidence_line = redact(text.strip())[:200]

            # Rule A: third-party package repository added.
            if PACKAGE_REPO_RE.search(text):
                urls = extract_urls(text)
                allow_downgrade = (
                    bool(allowed_repo_domains)
                    and bool(urls)
                    and all(hostname_allowed(u, allowed_repo_domains) for u in urls)
                )
                rec = (
                    "Do not add mutable third-party package repositories in CI. Prefer "
                    "pinned artifacts with verified SHA256/signature, pinned container "
                    "digests, or a prebuilt trusted CI image."
                )
                severity, rec = finalize(block_repo and not allow_downgrade, rec)
                findings.append(
                    Finding(
                        severity,
                        "ci.third_party_package_repo",
                        "CI adds third-party package repository",
                        path,
                        line.line,
                        f"Added CI line adds a third-party package repository: `{evidence_line}`.",
                        rec,
                    )
                )

            # Rule B: downloaded package signing key or installer bootstrap.
            if PACKAGE_KEY_OR_BOOTSTRAP_RE.search(text):
                severity, rec = finalize(
                    block_keys,
                    "Do not download and trust package signing keys or pipe bootstrap "
                    "installers into a shell at CI runtime. Fetch pinned artifacts and "
                    "verify them by SHA256/signature, or use a prebuilt trusted CI image.",
                )
                findings.append(
                    Finding(
                        severity,
                        "ci.downloaded_package_key_or_bootstrap",
                        "CI downloads package signing key or bootstrap script",
                        path,
                        line.line,
                        f"Added CI line downloads a signing key or bootstrap installer: `{evidence_line}`.",
                        rec,
                    )
                )

            # Rule C: unpinned high-impact tool installation.
            tool = _high_impact_install_on_line(text, high_impact_tools)
            if tool and not line_has_exact_version_or_digest(text):
                severity, rec = finalize(
                    block_tools,
                    f"Pin `{tool}` to an exact version or digest (for example "
                    f"`{tool}==X.Y.Z`, `{tool}=X.Y.Z`, or `image@sha256:...`) and verify "
                    "its checksum or signature. Installing a high-impact tool from a "
                    "mutable source lets an attacker swap the binary.",
                )
                findings.append(
                    Finding(
                        severity,
                        "ci.unpinned_high_impact_tool_install",
                        "CI installs high-impact tool without an exact version",
                        path,
                        line.line,
                        f"Added CI line installs `{tool}` without an exact version or digest: `{evidence_line}`.",
                        rec,
                    )
                )

            # Rule D: floating container image for a high-impact tool.
            for image in _image_refs_on_line(text):
                if _image_is_floating(image, FLOATING_IMAGE_TOOLS):
                    severity, rec = finalize(
                        block_images,
                        "Pin container images by digest, for example image@sha256:..., "
                        "not by latest or an implicit mutable tag.",
                    )
                    findings.append(
                        Finding(
                            severity,
                            "ci.floating_high_impact_tool_image",
                            "CI uses floating container image for high-impact tool",
                            path,
                            line.line,
                            f"Added CI line uses floating image `{image}` for a high-impact tool: `{evidence_line}`.",
                            rec,
                        )
                    )

            # Rule E: high-impact GitHub Action not pinned to a full commit SHA.
            m_uses = USES_ACTION_RE.search(text)
            if m_uses:
                action_name = m_uses.group(1)
                action_ref = m_uses.group(2)
                if _action_is_high_impact(action_name, high_impact_actions) and not FULL_GIT_SHA_RE.match(action_ref):
                    severity, rec = finalize(
                        block_actions,
                        "Pin high-impact GitHub Actions to a full 40-character commit SHA "
                        "rather than a branch or version tag, since tags and branches are mutable.",
                    )
                    findings.append(
                        Finding(
                            severity,
                            "ci.high_impact_action_not_sha_pinned",
                            "High-impact GitHub Action is not pinned to a commit SHA",
                            path,
                            line.line,
                            f"Added CI line uses high-impact action `{action_name}@{action_ref}`, "
                            "which is not pinned to a full commit SHA.",
                            rec,
                        )
                    )

    return findings


def query_osv(candidates: Sequence[Tuple[str, str, str, str]], config: Dict[str, Any], findings: List[Finding]) -> None:
    osv_config = config.get("osv", {})
    if not osv_config.get("enabled", True) or not candidates:
        return

    timeout = int(osv_config.get("timeout_seconds", 12))
    warn_on_vulns = bool(osv_config.get("warn_on_vulnerabilities", True))
    deduped: List[Tuple[str, str, str, str]] = []
    seen: Set[Tuple[str, str, str]] = set()
    for ecosystem, name, version, source_file in candidates:
        key = (ecosystem, name, version)
        if key not in seen:
            seen.add(key)
            deduped.append((ecosystem, name, version, source_file))

    for chunk_start in range(0, len(deduped), 100):
        chunk = deduped[chunk_start : chunk_start + 100]
        payload = {
            "queries": [
                {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                for ecosystem, name, version, _ in chunk
            ]
        }
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": f"zt-slop/{VERSION}"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
            result = json.loads(body)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            add_finding(
                findings,
                Finding(
                    "info",
                    "osv.unavailable",
                    "OSV query was unavailable",
                    None,
                    None,
                    f"OSV query failed: {type(exc).__name__}.",
                    "Re-run the scan when network access is available; this does not prove the dependency is safe.",
                ),
            )
            return

        results = result.get("results", [])
        for idx, item in enumerate(results):
            if idx >= len(chunk):
                break
            ecosystem, name, version, source_file = chunk[idx]
            vulns = item.get("vulns") or []
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "UNKNOWN")
                summary = str(vuln.get("summary") or vuln.get("details") or "").strip()
                evidence = f"{ecosystem} package `{name}@{version}` matched OSV advisory `{vuln_id}`"
                if summary:
                    evidence += f": {summary[:220]}"
                if is_malicious_osv(vuln):
                    add_finding(
                        findings,
                        Finding(
                            "block",
                            "osv.malicious_package",
                            "Known malicious package introduced",
                            source_file,
                            None,
                            evidence,
                            "Remove this package/version and investigate why it was introduced.",
                        ),
                    )
                elif warn_on_vulns:
                    add_finding(
                        findings,
                        Finding(
                            "warn",
                            "osv.vulnerable_package",
                            "Known vulnerable package introduced or updated",
                            source_file,
                            None,
                            evidence,
                            "Upgrade to a non-vulnerable version or document why this advisory is not applicable.",
                        ),
                    )


def is_malicious_osv(vuln: Dict[str, Any]) -> bool:
    vuln_id = str(vuln.get("id") or "")
    if vuln_id.startswith("MAL-"):
        return True
    aliases = vuln.get("aliases") or []
    if any(str(alias).startswith("MAL-") for alias in aliases):
        return True
    haystack = " ".join(
        str(vuln.get(key) or "")
        for key in ("summary", "details")
    ).lower()
    if "malicious" in haystack or "malware" in haystack:
        return True
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        db_text = json.dumps(database_specific).lower()
        if "malicious" in db_text or "malware" in db_text:
            return True
    return False


def severity_rank(severity: str) -> int:
    return {"block": 0, "warn": 1, "info": 2}.get(severity, 3)


def summarize_status(findings: Sequence[Finding]) -> str:
    if any(f.severity == "block" for f in findings):
        return "BLOCK"
    if any(f.severity == "warn" for f in findings):
        return "WARN"
    return "PASS"


def write_json_report(path: str, findings: Sequence[Finding], base: str, head: str, elapsed: float) -> None:
    report = {
        "tool": "zt-slop",
        "version": VERSION,
        "status": summarize_status(findings),
        "base": base,
        "head": head,
        "elapsed_seconds": round(elapsed, 3),
        "finding_count": len(findings),
        "counts": {
            "block": sum(1 for f in findings if f.severity == "block"),
            "warn": sum(1 for f in findings if f.severity == "warn"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "findings": [f.to_dict() for f in sorted_findings(findings)],
    }
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sorted_findings(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (severity_rank(f.severity), f.file or "", f.line or 0, f.rule_id))


def write_markdown_report(path: str, findings: Sequence[Finding], base: str, head: str, elapsed: float) -> None:
    status = summarize_status(findings)
    blocks = sum(1 for f in findings if f.severity == "block")
    warns = sum(1 for f in findings if f.severity == "warn")
    infos = sum(1 for f in findings if f.severity == "info")
    lines: List[str] = []
    lines.append(f"# ZT-Slop PR report: {status}")
    lines.append("")
    lines.append(f"Scanned `{base}...{head}` in {elapsed:.2f}s without executing PR code.")
    lines.append("")
    lines.append(f"**Findings:** {blocks} block / {warns} warn / {infos} info")
    lines.append("")

    if not findings or (blocks == 0 and warns == 0):
        lines.append("No blocking or warning-level supply-chain findings were introduced by this diff.")
    else:
        for i, f in enumerate(sorted_findings(findings), 1):
            if f.severity == "info" and blocks + warns > 0:
                # Keep PR summaries focused; JSON/SARIF still contain info findings.
                continue
            loc = f.file or "repository"
            if f.line:
                loc += f":{f.line}"
            lines.append(f"## {i}. {f.title}")
            lines.append("")
            lines.append(f"- **Severity:** `{f.severity}`")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **Location:** `{loc}`")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append(f"- **Fix:** {f.recommendation}")
            lines.append("")

    Path(path).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_sarif_report(path: str, findings: Sequence[Finding]) -> None:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in sorted_findings(findings):
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "help": {"text": f.recommendation},
            },
        )
        level = "error" if f.severity == "block" else "warning" if f.severity == "warn" else "note"
        result: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f"{f.title}: {f.evidence} Fix: {f.recommendation}"},
        }
        if f.file:
            region: Dict[str, Any] = {}
            if f.line:
                region["startLine"] = max(1, int(f.line))
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": region,
                    }
                }
            ]
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ZT-Slop",
                        "version": VERSION,
                        "informationUri": "https://github.com/Joshwani/zt-slop",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    Path(path).write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def emit_github_annotations(findings: Sequence[Finding]) -> None:
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    for f in sorted_findings(findings):
        if f.severity == "info":
            continue
        command = "error" if f.severity == "block" else "warning"
        props: List[str] = []
        if f.file:
            props.append(f"file={escape_annotation_prop(f.file)}")
        if f.line:
            props.append(f"line={f.line}")
        prop_text = ",".join(props)
        message = f"{f.title}: {f.evidence} Fix: {f.recommendation}"
        print(f"::{command} {prop_text}::{escape_annotation_message(message)}")


def escape_annotation_prop(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def escape_annotation_message(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def scan(args: argparse.Namespace) -> Tuple[List[Finding], float]:
    start = time.time()
    config = load_config(args.config)
    if args.no_network:
        config.setdefault("osv", {})["enabled"] = False

    diff_text = git_diff(args.base, args.head)
    files = parse_diff(diff_text)
    files = {path: changed for path, changed in files.items() if not is_excluded(path, config)}
    findings: List[Finding] = []

    analyze_workflows(files, findings, config)
    analyze_lockfiles(files, findings, config)
    analyze_secrets_and_exfil(files, findings)
    for ci_finding in scan_ci_supply_chain(files, config):
        add_finding(findings, ci_finding)

    osv_candidates: List[Tuple[str, str, str, str]] = []
    osv_candidates.extend(analyze_package_json(files, args.base, args.head, findings))
    osv_candidates.extend(analyze_requirements(files, findings))
    osv_candidates.extend(collect_npm_lock_candidates(files, args.base, args.head))
    query_osv(osv_candidates, config, findings)

    elapsed = time.time() - start
    return sorted_findings(findings), elapsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deterministic PR guard for supply-chain risk. Does not execute PR code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              zt_slop.py --base origin/main --head HEAD
              zt_slop.py --base HEAD~1 --head HEAD --no-network --fail-on warn
            """
        ),
    )
    parser.add_argument("--base", default="HEAD~1", help="Base git ref/sha for the diff. Default: HEAD~1")
    parser.add_argument("--head", default="HEAD", help="Head git ref/sha for the diff. Default: HEAD")
    parser.add_argument("--config", default="zt-slop.json", help="Optional JSON config file. Default: zt-slop.json")
    parser.add_argument("--fail-on", choices=["block", "warn", "none"], default="block", help="Exit non-zero on block, warn, or never.")
    parser.add_argument("--json-report", default="zt-slop-report.json", help="Write JSON report to this path.")
    parser.add_argument("--markdown-report", default="zt-slop-report.md", help="Write Markdown report to this path.")
    parser.add_argument("--sarif-report", default="zt-slop-report.sarif", help="Write SARIF report to this path.")
    parser.add_argument("--no-network", action="store_true", help="Disable OSV network lookups.")
    parser.add_argument("--version", action="version", version=f"zt-slop {VERSION}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        findings, elapsed = scan(args)
        write_json_report(args.json_report, findings, args.base, args.head, elapsed)
        write_markdown_report(args.markdown_report, findings, args.base, args.head, elapsed)
        write_sarif_report(args.sarif_report, findings)
        emit_github_annotations(findings)

        status = summarize_status(findings)
        print(f"ZT-Slop status: {status} ({len(findings)} findings)")
        for f in sorted_findings(findings):
            if f.severity == "info":
                continue
            loc = f.file or "repository"
            if f.line:
                loc += f":{f.line}"
            print(f"[{f.severity.upper()}] {f.rule_id} {loc}: {f.title}")

        if args.fail_on == "none":
            return 0
        if args.fail_on == "warn" and any(f.severity in {"block", "warn"} for f in findings):
            return 1
        if args.fail_on == "block" and any(f.severity == "block" for f in findings):
            return 1
        return 0
    except ScanError as exc:
        print(f"ZT-Slop error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
