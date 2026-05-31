#!/usr/bin/env bash
#
# Demo: ZT-Slop blocks the LiteLLM-style CI supply-chain attack.
#
# This builds a throwaway git repo, simulates a pull request that adds a
# mutable third-party tool install to .circleci/config.yml (the real LiteLLM
# pattern), and runs ZT-Slop against the diff. It then simulates a *safe*
# remediation PR and shows that ZT-Slop passes it.
#
# Nothing here installs anything or runs the PR's code. ZT-Slop only reads the
# git diff. Usage:
#
#   bash demo/litellm_attack_demo.sh
#
set -uo pipefail

# Resolve the repo root from this script's location so the demo is portable.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ZT_SLOP="$REPO_ROOT/zt_slop.py"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
rule() { printf '%s\n' "------------------------------------------------------------"; }

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

git init -q
git config user.email demo@example.com
git config user.name "ZT-Slop Demo"

mkdir -p .circleci

# --- Base: a benign CircleCI config that everyone is happy with. -------------
cat > .circleci/config.yml <<'YAML'
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/base:2024.01
    steps:
      - checkout
      - run: echo "build the project"
YAML
git add -A
git commit -qm "base: benign CI config"
BASE="$(git rev-parse HEAD)"

run_scan() {
  # Runs ZT-Slop against the latest commit and returns its exit code.
  python3 "$ZT_SLOP" \
    --base "$BASE" \
    --head HEAD \
    --no-network \
    --fail-on block \
    --config "$REPO_ROOT/zt-slop.json" \
    --json-report "$WORKDIR/report.json" \
    --markdown-report "$WORKDIR/report.md" \
    --sarif-report "$WORKDIR/report.sarif"
}

echo
bold "SCENARIO 1: malicious PR (the LiteLLM pattern)"
rule
echo "The PR adds a third-party apt repo, a downloaded signing key, and an"
echo "unpinned install of Trivy in .circleci/config.yml:"
echo

# --- Attack PR: the exact LiteLLM-style Trivy bootstrap. ----------------------
cat >> .circleci/config.yml <<'YAML'
      - run:
          name: Install and run Trivy
          command: |
            sudo apt-get update
            sudo apt-get install wget apt-transport-https gnupg lsb-release
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update
            sudo apt-get install trivy
            trivy fs --no-progress /
YAML
git add -A
git commit -qm "ci: add trivy scan"

run_scan
ATTACK_EXIT=$?
echo
if [ "$ATTACK_EXIT" -ne 0 ]; then
  bold "==> ZT-Slop BLOCKED the attack PR (exit $ATTACK_EXIT). Correct."
else
  bold "==> UNEXPECTED: attack PR was not blocked (exit $ATTACK_EXIT)."
fi

# Reset back to the benign base so scenario 2 is a clean, separate PR.
git reset -q --hard "$BASE"

echo
bold "SCENARIO 2: safe remediation PR"
rule
echo "Same goal (run Trivy in CI), but pinned by container digest with no"
echo "mutable apt repo, downloaded key, or unpinned install:"
echo

# A digest pin is what makes this safe; the value below is a demo placeholder.
DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
cat >> .circleci/config.yml <<YAML
      - run:
          name: Run Trivy (pinned by digest)
          command: |
            docker run --rm ghcr.io/aquasecurity/trivy@${DIGEST} fs --no-progress /
YAML
git add -A
git commit -qm "ci: run trivy pinned by digest"

run_scan
SAFE_EXIT=$?
echo
if [ "$SAFE_EXIT" -eq 0 ]; then
  bold "==> ZT-Slop PASSED the safe PR (exit $SAFE_EXIT). Correct."
else
  bold "==> UNEXPECTED: safe PR was blocked (exit $SAFE_EXIT)."
fi

echo
rule
bold "Takeaway"
echo "The problem is not 'Trivy is bad'. The attack PR installs a high-impact"
echo "tool from a MUTABLE third-party source with no pinned version or"
echo "verification, so an attacker who controls that source controls your CI."
echo "Pinning by digest/SHA + verification (Scenario 2) is allowed."

# Exit non-zero if the demo did not behave as expected.
if [ "$ATTACK_EXIT" -ne 0 ] && [ "$SAFE_EXIT" -eq 0 ]; then
  exit 0
fi
exit 1
