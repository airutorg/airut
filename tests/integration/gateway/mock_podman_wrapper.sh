#!/bin/bash
# Wrapper script to invoke mock_podman.py via uv
# This allows CONTAINER_COMMAND to be a single executable path
exec uv run python -m tests.integration.gateway.mock_podman "$@"
