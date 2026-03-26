# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for config live reload.

Tests verify config reload by externally observable behavior — tracker
state, email processing, dashboard accessibility, conversation store.
Each test starts a full GatewayService with a YAML config file, modifies
the file, and observes the change took effect.

Matches the test plan in ``spec/config-reload.md``:
  A1-A5: TASK-scope changes
  B1-B7: REPO-scope changes
  C1-C4: SERVER-scope changes
  D1-D6: Error handling and edge cases
"""

import hashlib
import json
import os
import socket
import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.config.source import YamlConfigSource
from airut.conversation import ConversationStore
from airut.dashboard.tracker import BootPhase
from airut.gateway.config import (
    EmailChannelConfig,
    ServerConfig,
    get_storage_dir,
)
from airut.gateway.service import GatewayService
from airut.yaml_env import EnvVar, VarRef

from .conftest import (
    MOCK_CONTAINER_COMMAND,
    get_message_text,
    wait_for_conv_completion,
    wait_for_task,
)
from .email_server import TestEmailServer as _TestEmailServer
from .environment import IntegrationEnvironment, create_test_repo


# ------------------------------------------------------------------ #
# Test infrastructure
# ------------------------------------------------------------------ #


class ConfigFile:
    """Write and modify config YAML files for testing."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = {}

    @classmethod
    def from_env(
        cls,
        env: IntegrationEnvironment,
        path: Path,
    ) -> "ConfigFile":
        """Build a ConfigFile from an IntegrationEnvironment."""
        cf = cls(path)
        cf._data = _config_to_yaml(env)
        cf.write()
        return cf

    def write(self) -> None:
        """Write current config to YAML. Triggers inotify."""
        source = YamlConfigSource(self.path)
        source.save(self._data)

    def _set_in_memory(self, dotpath: str, value: object) -> None:
        """Set a dot-path value without writing to disk."""
        keys = dotpath.split(".")
        d = self._data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value

    def set(self, dotpath: str, value: object) -> None:
        """Update a nested path (dot-separated) and write.

        WARNING: Each call triggers one inotify event.  When multiple
        fields must change atomically, use ``set_many()`` instead so
        ``wait_for_reload`` observes the complete state.
        """
        self._set_in_memory(dotpath, value)
        self.write()

    def set_many(self, updates: dict[str, object]) -> None:
        """Update multiple dot-paths in memory, then write once.

        Avoids the race where separate ``set()`` calls each trigger an
        inotify event and an intermediate reload can bump the config
        generation before all fields are updated.
        """
        for dotpath, value in updates.items():
            self._set_in_memory(dotpath, value)
        self.write()

    def delete(self, dotpath: str) -> None:
        """Delete a nested path and write."""
        keys = dotpath.split(".")
        d = self._data
        for k in keys[:-1]:
            d = d[k]
        del d[keys[-1]]
        self.write()

    def reload(self) -> None:
        """Re-read _data from disk (sync after external writes)."""
        source = YamlConfigSource(self.path)
        self._data = source.load()

    @property
    def data(self) -> dict[str, Any]:
        """Return the raw YAML dict."""
        return self._data


def _config_to_yaml(env: IntegrationEnvironment) -> dict[str, Any]:
    """Convert an IntegrationEnvironment to a YAML-serializable dict."""
    gc = env.config.global_config
    result: dict[str, Any] = {
        "container_command": gc.container_command,
        "execution": {
            "max_concurrent": gc.max_concurrent_executions,
            "shutdown_timeout": gc.shutdown_timeout_seconds,
        },
        "dashboard": {
            "enabled": gc.dashboard_enabled,
            "host": gc.dashboard_host,
            "port": gc.dashboard_port,
        },
        "repos": {},
    }

    for repo_id, repo_cfg in env.config.repos.items():
        repo_dict: dict[str, Any] = {
            "git": {"repo_url": repo_cfg.git_repo_url},
            "model": repo_cfg.model,
        }
        if repo_cfg.effort is not None:
            repo_dict["effort"] = repo_cfg.effort
        if repo_cfg.secrets:
            repo_dict["secrets"] = dict(repo_cfg.secrets)

        email_cfg = repo_cfg.channels.get("email")
        if email_cfg is not None:
            assert isinstance(email_cfg, EmailChannelConfig)
            repo_dict["email"] = {
                "imap_server": email_cfg.imap_server,
                "imap_port": email_cfg.imap_port,
                "smtp_server": email_cfg.smtp_server,
                "smtp_port": email_cfg.smtp_port,
                "smtp_require_auth": email_cfg.smtp_require_auth,
                "username": email_cfg.username,
                "password": email_cfg.password,
                "from": email_cfg.from_address,
                "authorized_senders": list(email_cfg.authorized_senders),
                "trusted_authserv_id": email_cfg.trusted_authserv_id,
                "imap": {
                    "use_idle": email_cfg.use_imap_idle,
                    "poll_interval": email_cfg.poll_interval_seconds,
                },
            }

        result["repos"][repo_id] = repo_dict

    return result


def create_file_service(
    config_file: ConfigFile,
    env: IntegrationEnvironment,
) -> GatewayService:
    """Create a GatewayService from a YAML config file with live reload."""
    source = YamlConfigSource(config_file.path)
    snapshot = ServerConfig.from_source(source)
    return GatewayService(
        snapshot.value,
        repo_root=env.repo_root,
        egress_network=env.egress_network,
        config_source=source,
        config_snapshot=snapshot,
    )


def wait_for_reload(
    service: GatewayService,
    generation: int,
    timeout: float = 5.0,
) -> None:
    """Wait until config_generation > generation.

    Uses the service's ``_reload_condition`` for instant wakeup
    instead of polling.
    """
    with service._reload_condition:
        if not service._reload_condition.wait_for(
            lambda: service._config_generation > generation, timeout
        ):
            raise TimeoutError(
                f"Config reload did not complete within {timeout}s "
                f"(generation={service._config_generation}, "
                f"expected>{generation})"
            )


def wait_for_reload_error(
    service: GatewayService,
    timeout: float = 5.0,
) -> None:
    """Wait until _last_reload_error is set (watcher processed a bad config)."""
    with service._reload_condition:
        if not service._reload_condition.wait_for(
            lambda: service._last_reload_error is not None, timeout
        ):
            raise TimeoutError(f"Reload error did not appear within {timeout}s")


def wait_for_pending_server_clear(
    service: GatewayService,
    timeout: float = 5.0,
) -> None:
    """Wait until _pending_server_config is cleared."""
    with service._reload_condition:
        if not service._reload_condition.wait_for(
            lambda: service._pending_server_config is None, timeout
        ):
            raise TimeoutError(
                f"Pending server config was not cleared within {timeout}s"
            )


def wait_for_repo_status(
    service: GatewayService,
    repo_id: str,
    status: str,
    timeout: float = 10.0,
) -> None:
    """Wait until a repo reaches the given status.

    Repo status is set outside the reload path (by listener restart),
    so this still uses polling — but with a short interval.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        repos = service._repos_store.get().value
        for r in repos:
            if r.repo_id == repo_id and r.status.value == status:
                return
        time.sleep(0.05)
    raise TimeoutError(
        f"Repo '{repo_id}' did not reach status '{status}' within {timeout}s"
    )


def _wait_for_service_ready(
    service: GatewayService, timeout: float = 15.0
) -> None:
    """Wait for the service to complete boot."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        boot = service._boot_store.get().value
        if boot.phase == BootPhase.READY:
            return
        if boot.phase == BootPhase.FAILED:
            raise RuntimeError(f"Service boot failed: {boot.error_message}")
        time.sleep(0.05)
    raise TimeoutError(f"Service did not boot within {timeout}s")


def _wait_for_watcher_ready(
    service: GatewayService, timeout: float = 5.0
) -> None:
    """Wait until the config file watcher is listening."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service._watcher is not None:
            remaining = deadline - time.monotonic()
            if service._watcher.ready.wait(max(remaining, 0)):
                return
            break
        time.sleep(0.05)
    raise TimeoutError(f"Config watcher did not start within {timeout}s")


@contextmanager
def running_service(
    config_file: ConfigFile,
    env: IntegrationEnvironment,
) -> Generator[GatewayService]:
    """Start a file-based service in a background thread."""
    service = create_file_service(config_file, env)
    service_thread = threading.Thread(target=service.start, daemon=True)
    service_thread.start()
    try:
        _wait_for_service_ready(service)
        _wait_for_watcher_ready(service)
        yield service
    finally:
        service.stop()
        service_thread.join(timeout=10.0)


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _standard_mock() -> str:
    """Return standard mock code that completes successfully."""
    return """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Task completed"),
    generate_result_event(session_id, "Done"),
]
"""


def _env_capture_mock(*var_names: str) -> str:
    """Return mock code that captures env vars to workspace."""
    items = ", ".join(f'"{v}": os.environ.get("{v}", "")' for v in var_names)
    return f"""
import json
env_data = {{{items}}}
(workspace / "env_capture.json").write_text(json.dumps(env_data))

events = [
    generate_system_event(session_id),
    generate_assistant_event("Done"),
    generate_result_event(session_id, "Done"),
]
"""


def _gate_mock(gate_dir: str) -> str:
    """Return mock code that blocks until a gate file is written.

    The mock writes ``<gate_dir>/ready`` when it starts blocking,
    and polls for ``<gate_dir>/release`` to continue.  This lets
    tests control task duration deterministically instead of using
    ``time.sleep()``.
    """
    return f"""
events = [
    generate_system_event(session_id),
    generate_assistant_event("Working..."),
    generate_result_event(session_id, "Done"),
]

def sync_between_events(event_num):
    if event_num == 1:
        gate = Path("{gate_dir}")
        gate.mkdir(parents=True, exist_ok=True)
        (gate / "ready").write_text("1")
        while not (gate / "release").exists():
            time.sleep(0.05)
"""


def _wait_for_gate(gate_dir: Path, timeout: float = 15.0) -> None:
    """Wait until the gate mock writes its ready file."""
    ready = gate_dir / "ready"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"Gate ready file not created within {timeout}s")


def _release_gate(gate_dir: Path) -> None:
    """Signal the gate mock to continue and complete."""
    gate_dir.mkdir(parents=True, exist_ok=True)
    (gate_dir / "release").write_text("1")


def _read_env_capture(conv_id: str, repo_id: str = "test") -> dict[str, str]:
    """Read captured env vars from a conversation workspace."""
    ws = get_storage_dir(repo_id) / "conversations" / conv_id / "workspace"
    env_file = ws / "env_capture.json"
    assert env_file.exists(), f"env_capture.json not found: {env_file}"
    return json.loads(env_file.read_text())


def _send_and_complete(
    env: IntegrationEnvironment,
    service: GatewayService,
    create_email,
    extract_conversation_id,
    body: str,
    subject: str = "Test message",
    sender: str = "user@test.local",
    inbox: str | None = None,
    timeout: float = 30.0,
) -> str:
    """Send an email, wait for ack+completion, return conversation ID."""
    msg = create_email(subject=subject, body=body, sender=sender)
    if inbox:
        env.email_server.inject_message_to(inbox, msg)
    else:
        env.email_server.inject_message(msg)

    ack = env.email_server.wait_for_sent(
        lambda m: "started working" in get_message_text(m).lower(),
        timeout=timeout,
    )
    assert ack is not None, "No acknowledgment received"
    conv_id = extract_conversation_id(ack["Subject"])
    assert conv_id is not None, f"No conv ID in subject: {ack['Subject']}"

    task = wait_for_conv_completion(service.tracker, conv_id, timeout=timeout)
    assert task is not None, f"Task for {conv_id} did not complete"
    assert task.succeeded, (
        f"Task failed: {task.completion_reason} / {task.completion_detail}"
    )
    return conv_id


# ------------------------------------------------------------------ #
# A. TASK-Scope Changes
# ------------------------------------------------------------------ #


class TestTaskScopeReload:
    """Task-scope changes take effect on the next task."""

    def test_reload_model_change(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A1: Model change applies to next task."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # First task: model = opus (default)
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Model test 1",
            )
            task1 = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task1 is not None
            assert task1.model == "opus"

            # Change model to sonnet
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf.set("repos.test.model", "sonnet")
            wait_for_reload(service, gen)

            # Second task: model = sonnet
            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Model test 2",
            )
            task2 = wait_for_conv_completion(
                service.tracker, conv_id2, timeout=5.0
            )
            assert task2 is not None
            assert task2.model == "sonnet"

    def test_reload_model_via_var_indirection(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A2: Model change via vars section."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        # Set up vars + !var reference
        cf._data["vars"] = {"claude_model": "opus"}
        cf._data["repos"]["test"]["model"] = VarRef("claude_model")
        cf.write()

        with running_service(cf, integration_env) as service:
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Var test 1",
            )
            task1 = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task1 is not None
            assert task1.model == "opus"

            # Change var value
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf.set("vars.claude_model", "sonnet")
            wait_for_reload(service, gen)

            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Var test 2",
            )
            task2 = wait_for_conv_completion(
                service.tracker, conv_id2, timeout=5.0
            )
            assert task2 is not None
            assert task2.model == "sonnet"

    def test_reload_effort(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A3: Effort change applies to next task."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # First task: effort = None (default)
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Effort test 1",
            )
            conv_dir = get_storage_dir("test") / "conversations" / conv_id
            store = ConversationStore(conv_dir)
            assert store.get_effort() is None

            # Set effort = low
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf.set("repos.test.effort", "low")
            wait_for_reload(service, gen)

            # Second task: effort = low
            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Effort test 2",
            )
            conv_dir2 = get_storage_dir("test") / "conversations" / conv_id2
            store2 = ConversationStore(conv_dir2)
            assert store2.get_effort() == "low"

    def test_reload_resource_limits(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """A4: Resource limits change applies to next task."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            gen = service._config_generation
            cf.set(
                "repos.test.resource_limits",
                {"timeout": 30},
            )
            wait_for_reload(service, gen)

            # Verify config was applied (task-scope swap)
            handler = service.repo_handlers["test"]
            assert handler.config.resource_limits.timeout == 30

            # Verify tasks still work with new limits
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Resource limits test",
            )
            assert conv_id is not None


# ------------------------------------------------------------------ #
# B. REPO-Scope Changes
# ------------------------------------------------------------------ #


class TestRepoScopeReload:
    """Repo-scope changes restart the affected repo's listeners."""

    def test_reload_email_credentials(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B1: Email credential change (IMAP/SMTP port switch)."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # Verify original server works
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Cred test 1",
            )
            assert conv_id is not None

            # Start a second email server
            email2 = _TestEmailServer(username="test", password="test")
            smtp2, imap2 = email2.start()
            try:
                # Switch config to second server (single write to avoid
                # an intermediate reload with only imap_port changed)
                gen = service._config_generation
                integration_env.email_server.clear_outbox()
                cf.set_many(
                    {
                        "repos.test.email.imap_port": imap2,
                        "repos.test.email.smtp_port": smtp2,
                    }
                )
                wait_for_reload(service, gen)
                wait_for_repo_status(service, "test", "live")

                # Send via second server
                msg = create_email(subject="Cred test 2", body=_standard_mock())
                email2.inject_message(msg)
                ack = email2.wait_for_sent(
                    lambda m: "started working" in get_message_text(m).lower(),
                    timeout=15.0,
                )
                assert ack is not None
            finally:
                email2.stop()

    def test_reload_authorized_senders(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B2: Authorized senders change."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # Bob is not authorized initially
            msg = create_email(
                subject="Bob's message",
                body=_standard_mock(),
                sender="bob@test.local",
            )
            integration_env.email_server.inject_message(msg)

            task = wait_for_task(
                service.tracker,
                lambda t: (
                    t.completion_reason is not None
                    and t.completion_reason.value == "unauthorized"
                ),
                timeout=15.0,
            )
            assert task is not None

            # Add bob to authorized senders
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf.set(
                "repos.test.email.authorized_senders",
                ["user@test.local", "bob@test.local"],
            )
            wait_for_reload(service, gen)
            wait_for_repo_status(service, "test", "live")

            # Bob is now authorized
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Bob authorized",
                sender="bob@test.local",
            )
            assert conv_id is not None

    def test_reload_add_repo(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B3: Adding a new repo via config reload."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        # Pre-register inbox for new repo
        integration_env.email_server.add_inbox("project-b")

        with running_service(cf, integration_env) as service:
            # Original repo works
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Repo A test",
            )
            assert conv_id is not None

            # Create a second git repo and add it to config
            repo_b_path = create_test_repo(
                integration_env.repo_root / "master_repo_b"
            )
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf._data["repos"]["project-b"] = {
                "git": {"repo_url": str(repo_b_path)},
                "model": "opus",
                "email": {
                    "imap_server": "127.0.0.1",
                    "imap_port": integration_env.imap_port,
                    "smtp_server": "127.0.0.1",
                    "smtp_port": integration_env.smtp_port,
                    "smtp_require_auth": False,
                    "username": "project-b",
                    "password": "test",
                    "from": "project-b <project-b@test.local>",
                    "authorized_senders": ["user@test.local"],
                    "trusted_authserv_id": "test.local",
                    "imap": {"use_idle": False, "poll_interval": 0.1},
                },
            }
            cf.write()
            wait_for_reload(service, gen)
            wait_for_repo_status(service, "project-b", "live")

            # Send to project-b
            msg = create_email(subject="Repo B test", body=_standard_mock())
            integration_env.email_server.inject_message_to("project-b", msg)
            ack = integration_env.email_server.wait_for_sent(
                lambda m: (
                    "repo b test" in m.get("Subject", "").lower()
                    and "started working" in get_message_text(m).lower()
                ),
                timeout=15.0,
            )
            assert ack is not None

    def test_reload_remove_repo(
        self,
        tmp_path: Path,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B4: Removing a repo via config reload."""
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["alpha", "beta"],
            container_command=MOCK_CONTAINER_COMMAND,
        )
        try:
            config_path = tmp_path / "airut.yaml"
            cf = ConfigFile.from_env(env, config_path)

            with running_service(cf, env) as service:
                # Both repos should be live
                wait_for_repo_status(service, "alpha", "live")
                wait_for_repo_status(service, "beta", "live")

                # Remove beta
                gen = service._config_generation
                del cf._data["repos"]["beta"]
                cf.write()
                wait_for_reload(service, gen)

                # alpha still works
                msg = create_email(subject="Alpha test", body=_standard_mock())
                env.email_server.inject_message_to("alpha", msg)
                ack = env.email_server.wait_for_sent(
                    lambda m: "started working" in get_message_text(m).lower(),
                    timeout=15.0,
                )
                assert ack is not None

                # beta is no longer in repo_handlers
                assert "beta" not in service.repo_handlers
        finally:
            env.cleanup()

    def test_reload_repo_deferred_during_task(
        self,
        tmp_path: Path,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B5: Repo reload deferred while task is active."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        gate_dir = tmp_path / "gate_b5"

        with running_service(cf, integration_env) as service:
            # Start a gate-controlled task
            msg = create_email(
                subject="Slow task",
                body=_gate_mock(str(gate_dir)),
            )
            integration_env.email_server.inject_message(msg)

            # Wait for task to start executing
            executing_task = wait_for_task(
                service.tracker,
                lambda t: t.status.value == "executing",
                timeout=15.0,
            )
            assert executing_task is not None
            _wait_for_gate(gate_dir)

            # Modify repo-scope config while task runs
            gen = service._config_generation
            cf.set(
                "repos.test.email.authorized_senders",
                ["user@test.local", "new-user@test.local"],
            )
            wait_for_reload(service, gen)

            # Repo should be pending reload (task still active)
            # Release the gate to let the task complete
            _release_gate(gate_dir)

            # Wait for task to complete — should succeed
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=15.0
            )
            assert task is not None
            assert task.succeeded

            # After task completes, deferred reload should apply
            wait_for_repo_status(service, "test", "live", timeout=10.0)

            # Verify new authorized sender works
            integration_env.email_server.clear_outbox()
            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="New sender test",
                sender="new-user@test.local",
            )
            assert conv_id2 is not None

    def test_reload_secrets(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B6: Secrets change."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set("repos.test.secrets", {"API_KEY": "old-key"})

        with running_service(cf, integration_env) as service:
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _env_capture_mock("API_KEY"),
                subject="Secret test 1",
            )
            env1 = _read_env_capture(conv_id)
            assert env1["API_KEY"] == "old-key"

            # Change secret
            gen = service._config_generation
            integration_env.email_server.clear_outbox()
            cf.set("repos.test.secrets", {"API_KEY": "new-key"})
            wait_for_reload(service, gen)
            wait_for_repo_status(service, "test", "live")

            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _env_capture_mock("API_KEY"),
                subject="Secret test 2",
            )
            env2 = _read_env_capture(conv_id2)
            assert env2["API_KEY"] == "new-key"

    def test_reload_secrets_via_env_indirection(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """B7: Secrets change via !env indirection."""
        os.environ["TEST_API_KEY"] = "key-v1"
        try:
            cf = ConfigFile.from_env(
                integration_env,
                integration_env.repo_root / "airut.yaml",
            )
            cf.set(
                "repos.test.secrets",
                {"API_KEY": EnvVar("TEST_API_KEY")},
            )

            with running_service(cf, integration_env) as service:
                conv_id = _send_and_complete(
                    integration_env,
                    service,
                    create_email,
                    extract_conversation_id,
                    _env_capture_mock("API_KEY"),
                    subject="Env secret test 1",
                )
                env1 = _read_env_capture(conv_id)
                assert env1["API_KEY"] == "key-v1"

                # Change env var and touch config to trigger reload
                os.environ["TEST_API_KEY"] = "key-v2"
                gen = service._config_generation
                integration_env.email_server.clear_outbox()
                cf.write()  # re-write triggers inotify
                wait_for_reload(service, gen)
                wait_for_repo_status(service, "test", "live")

                conv_id2 = _send_and_complete(
                    integration_env,
                    service,
                    create_email,
                    extract_conversation_id,
                    _env_capture_mock("API_KEY"),
                    subject="Env secret test 2",
                )
                env2 = _read_env_capture(conv_id2)
                assert env2["API_KEY"] == "key-v2"
        finally:
            os.environ.pop("TEST_API_KEY", None)


# ------------------------------------------------------------------ #
# C. SERVER-Scope Changes
# ------------------------------------------------------------------ #


class TestServerScopeReload:
    """Server-scope changes are deferred until globally idle."""

    def test_reload_dashboard_port(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """C1: Dashboard port change."""
        port1 = _free_port()
        port2 = _free_port()
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set_many(
            {
                "dashboard.enabled": True,
                "dashboard.port": port1,
            }
        )

        with running_service(cf, integration_env) as service:
            assert service.dashboard is not None
            assert service.dashboard.port == port1

            # Verify dashboard accessible
            with httpx.Client() as client:
                resp = client.get(f"http://127.0.0.1:{port1}/api/version")
                assert resp.status_code == 200

            # Change to a different port
            gen = service._config_generation
            cf.set("dashboard.port", port2)
            wait_for_reload(service, gen)

            # Dashboard should be on the new port
            assert service.dashboard is not None
            assert service.dashboard.port == port2

            # New port accessible
            with httpx.Client() as client:
                resp = client.get(f"http://127.0.0.1:{port2}/api/version")
                assert resp.status_code == 200

    def test_reload_dashboard_toggle(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """C2: Dashboard enable/disable toggle."""
        port1 = _free_port()
        port2 = _free_port()
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set_many(
            {
                "dashboard.enabled": True,
                "dashboard.port": port1,
            }
        )

        with running_service(cf, integration_env) as service:
            assert service.dashboard is not None

            # Verify accessible
            with httpx.Client() as client:
                resp = client.get(f"http://127.0.0.1:{port1}/api/version")
                assert resp.status_code == 200

            # Disable dashboard
            gen = service._config_generation
            cf.set("dashboard.enabled", False)
            wait_for_reload(service, gen)
            assert service.dashboard is None

            # Re-enable dashboard on a different port — single write
            # to avoid a race where the first write (enabled=True,
            # old port) triggers a reload that bumps generation before
            # the port change is written.
            gen2 = service._config_generation
            cf.set_many(
                {
                    "dashboard.enabled": True,
                    "dashboard.port": port2,
                }
            )
            wait_for_reload(service, gen2)
            assert service.dashboard is not None

            with httpx.Client() as client:
                resp = client.get(f"http://127.0.0.1:{port2}/api/version")
                assert resp.status_code == 200

    def test_reload_server_deferred_until_idle(
        self,
        tmp_path: Path,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """C3: Server reload deferred during active task."""
        port1 = _free_port()
        port2 = _free_port()
        gate_dir = tmp_path / "gate_c3"
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set_many(
            {
                "dashboard.enabled": True,
                "dashboard.port": port1,
            }
        )

        with running_service(cf, integration_env) as service:
            assert service.dashboard is not None
            assert service.dashboard.port == port1

            # Start gate-controlled task
            msg = create_email(
                subject="Slow server test",
                body=_gate_mock(str(gate_dir)),
            )
            integration_env.email_server.inject_message(msg)

            # Wait for task to start executing and reach the gate
            executing_task = wait_for_task(
                service.tracker,
                lambda t: t.status.value == "executing",
                timeout=15.0,
            )
            assert executing_task is not None
            _wait_for_gate(gate_dir)

            # Change dashboard port while task runs
            gen = service._config_generation
            cf.set("dashboard.port", port2)
            wait_for_reload(service, gen)

            # Server reload is pending — old dashboard still running
            assert service._pending_server_config is not None
            assert service.dashboard is not None
            assert service.dashboard.port == port1

            # Release the gate to let the task complete
            _release_gate(gate_dir)

            # Wait for task to complete
            ack = integration_env.email_server.wait_for_sent(
                lambda m: "started working" in get_message_text(m).lower(),
                timeout=15.0,
            )
            assert ack is not None
            conv_id = extract_conversation_id(ack["Subject"])
            assert conv_id is not None
            wait_for_conv_completion(service.tracker, conv_id, timeout=15.0)

            # Server reload should now be applied
            wait_for_pending_server_clear(service)
            assert service.dashboard is not None
            assert service.dashboard.port == port2

            # Dashboard accessible on new port
            with httpx.Client() as client:
                resp = client.get(f"http://127.0.0.1:{port2}/api/version")
                assert resp.status_code == 200

    def test_reload_max_concurrent(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """C4: max_concurrent_executions change."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set("execution.max_concurrent", 1)

        with running_service(cf, integration_env) as service:
            # Verify pool has 1 worker
            assert service._executor_pool is not None
            assert service._executor_pool._max_workers == 1

            # Change to 3
            gen = service._config_generation
            cf.set("execution.max_concurrent", 3)
            wait_for_reload(service, gen)

            # Pool should be recreated
            assert service._executor_pool is not None
            assert service._executor_pool._max_workers == 3

            # Verify tasks still work
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Max concurrent test",
            )
            assert conv_id is not None


# ------------------------------------------------------------------ #
# D. Error Handling and Edge Cases
# ------------------------------------------------------------------ #


class TestErrorHandling:
    """Error handling and edge cases."""

    def test_reload_invalid_yaml(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """D1: Invalid YAML keeps current config."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            gen_before = service._config_generation

            # Write invalid YAML — poll for the error instead of sleeping
            cf.path.write_text("invalid: yaml: {{{\n  broken")
            wait_for_reload_error(service)

            # Generation unchanged
            assert service._config_generation == gen_before

            # Service still works
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="After invalid YAML",
            )
            assert conv_id is not None

            # Fix YAML with a real change so reload detects a diff
            cf.set("repos.test.model", "sonnet")
            wait_for_reload(service, gen_before)
            assert service._last_reload_error is None
            handler = service.repo_handlers["test"]
            assert handler.config.model == "sonnet"

    def test_reload_invalid_config(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """D2: Valid YAML but invalid config keeps current config."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            gen_before = service._config_generation

            # Write valid YAML but missing required git.repo_url
            bad_config = {
                "container_command": cf._data["container_command"],
                "repos": {
                    "test": {
                        "email": cf._data["repos"]["test"]["email"],
                    }
                },
            }
            source = YamlConfigSource(cf.path)
            source.save(bad_config)
            wait_for_reload_error(service)

            # Generation unchanged — reload failed
            assert service._config_generation == gen_before
            assert service._last_reload_error is not None

            # Service still works with old config
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="After invalid config",
            )
            assert conv_id is not None

    def test_reload_rapid_writes(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """D3: Rapid writes — only final state takes effect."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # Write three changes in rapid succession
            cf.set("repos.test.model", "haiku")
            cf.set("repos.test.model", "opus")
            cf.set("repos.test.model", "sonnet")

            # Compute the expected hash of the final file on disk.
            # Wait until the service has loaded this exact file content.
            expected_sha = hashlib.sha256(cf.path.read_bytes()).hexdigest()
            with service._reload_condition:
                if not service._reload_condition.wait_for(
                    lambda: service._config_file_sha256 == expected_sha,
                    timeout=10.0,
                ):
                    raise TimeoutError("Service did not load final config file")

            handler = service.repo_handlers["test"]
            assert handler.config.model == "sonnet"

    def test_reload_sighup(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """D4: SIGHUP triggers reload."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            # Capture generation before writing to avoid race where
            # inotify fires before we read the generation counter.
            gen = service._config_generation
            cf.set("repos.test.model", "sonnet")
            wait_for_reload(service, gen)

            # Now test SIGHUP: change config, trigger via event
            gen2 = service._config_generation
            cf.set("repos.test.model", "haiku")
            # In-process: set the reload_requested event directly
            # (same effect as SIGHUP signal handler)
            service._reload_requested.set()
            wait_for_reload(service, gen2)

            handler = service.repo_handlers["test"]
            assert handler.config.model == "haiku"

    def test_reload_no_change(
        self,
        integration_env: IntegrationEnvironment,
    ) -> None:
        """D5: Rewriting identical config bumps gen but skips apply."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )

        with running_service(cf, integration_env) as service:
            gen = service._config_generation

            # Re-write identical content.  The watcher will fire,
            # _on_config_changed will run, detect no effective diff,
            # but still bump generation so the editor sees raw changes.
            cf.write()

            # Wait for the watcher to process the event and bump gen.
            # Cannot wait on SHA since identical content means the SHA
            # already matches from the initial load.
            with service._reload_condition:
                service._reload_condition.wait_for(
                    lambda: service._config_generation > gen,
                    timeout=5.0,
                )

            # Generation bumps even without effective changes so the
            # dashboard editor sees updated raw dicts.
            assert service._config_generation == gen + 1

    def test_reload_mixed_scopes(
        self,
        integration_env: IntegrationEnvironment,
        create_email,
        extract_conversation_id,
    ) -> None:
        """D6: Mixed scope changes in single edit."""
        cf = ConfigFile.from_env(
            integration_env,
            integration_env.repo_root / "airut.yaml",
        )
        cf.set_many(
            {
                "dashboard.enabled": True,
                "dashboard.port": 0,
            }
        )

        with running_service(cf, integration_env) as service:
            assert service.dashboard is not None

            gen = service._config_generation

            # Single edit: TASK + REPO + SERVER
            cf._data["repos"]["test"]["model"] = "sonnet"
            cf._data["repos"]["test"]["email"]["authorized_senders"] = [
                "user@test.local",
                "mixed@test.local",
            ]
            cf._data["dashboard"]["port"] = 0
            cf.write()
            wait_for_reload(service, gen)

            # TASK: model changed immediately
            handler = service.repo_handlers["test"]
            assert handler.config.model == "sonnet"

            # REPO: listeners restarted (authorized_senders changed)
            wait_for_repo_status(service, "test", "live")

            # SERVER: dashboard on new port (applied immediately
            # since service was idle)
            assert service.dashboard is not None

            # Verify model takes effect in actual task
            conv_id = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Mixed scope test",
            )
            task = wait_for_conv_completion(
                service.tracker, conv_id, timeout=5.0
            )
            assert task is not None
            assert task.model == "sonnet"

            # Verify new authorized sender works
            integration_env.email_server.clear_outbox()
            conv_id2 = _send_and_complete(
                integration_env,
                service,
                create_email,
                extract_conversation_id,
                _standard_mock(),
                subject="Mixed sender test",
                sender="mixed@test.local",
            )
            assert conv_id2 is not None
