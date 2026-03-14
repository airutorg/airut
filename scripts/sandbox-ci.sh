#!/usr/bin/env bash
# Wrapper script for running CI inside the Airut sandbox.
# Runs inside the container with /workspace mounted from the host.
#
# Usage: sandbox-ci.sh <commit-sha>
#
# The host checks out the default branch. This script fetches and
# checks out the PR commit inside the container, then runs ci.py.

set -euo pipefail

COMMIT_SHA="${1:?Usage: sandbox-ci.sh <commit-sha>}"

# Fetch and check out the PR commit
git fetch origin "$COMMIT_SHA"
git checkout "$COMMIT_SHA"

# Install dependencies and run CI
uv sync
uv run scripts/ci.py --verbose --timeout 0
