#!/bin/sh
# Wrapper script to invoke mock_podman.py with the test interpreter.
# This allows CONTAINER_COMMAND to be a single executable path.
#
# MOCK_PODMAN_PYTHON is set by conftest.py to the pytest interpreter.
# Using it directly (rather than `uv run python`) matters: the gateway
# invokes the container command thousands of times per integration run,
# and `uv run`'s per-call environment check adds ~10ms of CPU each time.
# For the same reason, -S skips the site module (~8ms per call): the
# mock needs only the standard library and the project root, which
# conftest.py puts on PYTHONPATH.
exec "${MOCK_PODMAN_PYTHON:?must be set by conftest.py}" -S \
    -m tests.integration.gateway.mock_podman "$@"
