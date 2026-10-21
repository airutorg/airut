#!/bin/bash
# Wrapper script to invoke mock_podman.py with the test interpreter.
# This allows CONTAINER_COMMAND to be a single executable path.
#
# MOCK_PODMAN_PYTHON is set by conftest.py to the pytest interpreter.
# Using it directly (rather than `uv run python`) matters: the gateway
# invokes the container command thousands of times per integration run,
# and `uv run`'s per-call environment check adds ~10ms of CPU each time.
exec "${MOCK_PODMAN_PYTHON:?must be set by conftest.py}" \
    -m tests.integration.gateway.mock_podman "$@"
