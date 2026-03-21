# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for container resource limits.

Tests the resource limits configuration flow end-to-end:
1. Server config specifies per-repo resource_limits
2. Server config specifies global resource_limits ceilings
3. Effective limits are clamped and threaded to sandbox.create_task()
4. Task applies limits as podman flags

Since integration tests use mock_podman (which wraps `uv run`), we cannot
verify actual cgroup enforcement.  Instead, we verify that:
- Resource limits from server config are threaded through to create_task
- Server-side ceilings clamp per-repo values
"""

import sys
import threading
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.gateway.config import GlobalConfig
from airut.sandbox.types import ResourceLimits

from .conftest import (
    get_message_text,
    wait_for_conv_completion,
)
from .environment import IntegrationEnvironment


class TestResourceLimits:
    """Test resource limits configuration end-to-end."""

    def test_resource_limits_passed_to_create_task(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Resource limits from server config are passed to create_task.

        Sets resource_limits on the RepoServerConfig, then verifies
        that sandbox.create_task() receives a ResourceLimits object with
        the configured values.
        """
        msg = create_email(
            subject="Resource limits test",
            body="Hello, world!",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()

        # Set resource limits on the repo handler's config
        repo_handler = service.repo_handlers["test"]
        object.__setattr__(
            repo_handler.config,
            "resource_limits",
            ResourceLimits(timeout=120, memory="2g", cpus=1.5, pids_limit=256),
        )

        # Spy on create_task to capture the resource_limits argument
        original_create_task = service.sandbox.create_task
        captured_limits: list[ResourceLimits] = []

        def spy_create_task(**kwargs):
            rl = kwargs.get("resource_limits")
            if rl is not None:
                captured_limits.append(rl)
            return original_create_task(**kwargs)

        service.sandbox.create_task = spy_create_task

        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            # Wait for acknowledgment
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None, "Did not receive acknowledgment email"
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            # Wait for completion
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=30.0
            )
            assert task is not None

            # Verify resource limits were captured
            assert len(captured_limits) >= 1
            rl = captured_limits[0]
            assert rl.timeout == 120
            assert rl.memory == "2g"
            assert rl.cpus == 1.5
            assert rl.pids_limit == 256

        finally:
            service.stop()
            service_thread.join(timeout=10.0)

    def test_server_ceiling_clamps_repo_limits(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """Server resource_limits ceiling clamps per-repo values.

        Sets per-repo timeout=7200 but server ceiling timeout=300.
        Verifies effective timeout is 300.
        """
        msg = create_email(
            subject="Server ceiling test",
            body="Hello, world!",
        )
        integration_env.email_server.inject_message(msg)

        service = integration_env.create_service()

        # Set per-repo resource limits (high values)
        repo_handler = service.repo_handlers["test"]
        object.__setattr__(
            repo_handler.config,
            "resource_limits",
            ResourceLimits(timeout=7200, memory="16g"),
        )

        # Set server-wide ceilings (lower values)
        server_limits = ResourceLimits(timeout=300, memory="4g")
        original_global = service.global_config
        service.global_config = GlobalConfig(
            max_concurrent_executions=original_global.max_concurrent_executions,
            shutdown_timeout_seconds=original_global.shutdown_timeout_seconds,
            conversation_max_age_days=original_global.conversation_max_age_days,
            dashboard_enabled=original_global.dashboard_enabled,
            dashboard_host=original_global.dashboard_host,
            dashboard_port=original_global.dashboard_port,
            dashboard_base_url=original_global.dashboard_base_url,
            container_command=original_global.container_command,
            upstream_dns=original_global.upstream_dns,
            resource_limits=server_limits,
        )

        original_create_task = service.sandbox.create_task
        captured_limits: list[ResourceLimits] = []

        def spy_create_task(**kwargs):
            rl = kwargs.get("resource_limits")
            if rl is not None:
                captured_limits.append(rl)
            return original_create_task(**kwargs)

        service.sandbox.create_task = spy_create_task

        service_thread = threading.Thread(target=service.start, daemon=True)
        service_thread.start()

        try:
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None

            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=30.0
            )
            assert task is not None
            assert len(captured_limits) >= 1
            rl = captured_limits[0]
            assert rl.timeout == 300  # Clamped from 7200 to 300
            assert rl.memory == "4g"  # Clamped from 16g to 4g

        finally:
            service.stop()
            service_thread.join(timeout=10.0)
