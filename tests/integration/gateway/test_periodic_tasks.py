# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for periodic scheduled tasks.

Tests exercise the full scheduler → execution → delivery pipeline:
- Scheduler tick dispatches due tasks to the executor pool
- Prompt mode builds prompt and runs run_in_sandbox()
- Script mode runs CommandTask, evaluates output, conditionally runs Claude
- Delivery routes results to the email adapter
- Reply-back works via conversation ID in Message-ID

All tests use far-future crons and manually set next_fire to the past,
then call _tick() directly for deterministic, instant scheduling without
sleeps or timing dependencies.
"""

import re
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from .conftest import (
    MOCK_CONTAINER_COMMAND,
    get_message_text,
    wait_for_boot,
    wait_for_task,
)
from .environment import IntegrationEnvironment


# ── Mock code for Claude execution ────────────────────────────────────
# This Python code is executed by mock_claude.py and produces streaming
# events that simulate a successful Claude execution.

_MOCK_CLAUDE_CODE = """\
events = [
    generate_system_event(session_id),
    generate_assistant_event("Scheduled task completed successfully."),
    generate_result_event(session_id, "Done"),
]
"""


# ── Helpers ───────────────────────────────────────────────────────────


def _create_schedule_env(
    tmp_path: Path,
    schedules: dict,
) -> IntegrationEnvironment:
    """Create an integration environment with periodic schedules configured."""
    from airut.gateway.config import (
        EmailAccountConfig,
        EmailAuthConfig,
        EmailChannelConfig,
        GlobalConfig,
        ImapConfig,
        RepoServerConfig,
        ServerConfig,
        SmtpConfig,
        get_storage_dir,
    )

    from .email_server import TestEmailServer
    from .environment import create_test_repo

    egress_network = f"airut-egress-{uuid.uuid4().hex[:8]}"

    master_repo = create_test_repo(tmp_path / "master_repo")
    storage_dir = get_storage_dir("test")
    storage_dir.mkdir(parents=True, exist_ok=True)
    mitmproxy_confdir = tmp_path / "mitmproxy-confdir"

    docker_dir = tmp_path / "docker"
    docker_dir.mkdir(exist_ok=True)
    (docker_dir / "airut-entrypoint.sh").write_text(
        '#!/usr/bin/env bash\nexec claude "$@"\n'
    )

    proxy_dir = tmp_path / "proxy"
    proxy_dir.mkdir(exist_ok=True)
    (proxy_dir / "proxy.dockerfile").write_text("FROM scratch\n")

    email_server = TestEmailServer(username="test", password="test")
    smtp_port, imap_port = email_server.start()

    global_config = GlobalConfig(
        max_concurrent_executions=2,
        shutdown_timeout_seconds=5,
        dashboard_enabled=False,
        dashboard_host="127.0.0.1",
        dashboard_port=0,
        container_command=MOCK_CONTAINER_COMMAND,
    )
    repo_config = RepoServerConfig(
        repo_id="test",
        git_repo_url=str(master_repo),
        channels={
            "email": EmailChannelConfig(
                account=EmailAccountConfig(
                    username="test",
                    password="test",
                    from_address="Claude Test <claude@test.local>",
                ),
                imap=ImapConfig(
                    server="127.0.0.1",
                    port=imap_port,
                    use_idle=False,
                    poll_interval=0.1,
                ),
                smtp=SmtpConfig(
                    server="127.0.0.1",
                    port=smtp_port,
                    require_auth=False,
                ),
                auth=EmailAuthConfig(
                    authorized_senders=["user@test.local"],
                    trusted_authserv_id="test.local",
                ),
            )
        },
        schedules=schedules,
    )
    config = ServerConfig(
        global_config=global_config,
        repos={"test": repo_config},
    )

    return IntegrationEnvironment(
        master_repo=master_repo,
        storage_dir=storage_dir,
        email_server=email_server,
        smtp_port=smtp_port,
        imap_port=imap_port,
        config=config,
        mitmproxy_confdir=mitmproxy_confdir,
        repo_root=tmp_path,
        egress_network=egress_network,
    )


def _make_schedule_config(
    cron: str = "0 0 1 1 *",
    prompt: str | None = _MOCK_CLAUDE_CODE,
    trigger_command: str | None = None,
    trigger_timeout: int | None = None,
    to: str = "user@test.local",
    name: str = "daily",
) -> dict:
    """Build a schedule dict with ScheduleConfig objects.

    Uses a far-future cron by default so the background scheduler
    thread never fires automatically; tests force dispatch via
    _tick() after setting next_fire to the past.
    """
    from airut.gateway.config import (
        ScheduleConfig,
        ScheduleDelivery,
    )

    return {
        name: ScheduleConfig(
            cron=cron,
            deliver=ScheduleDelivery(channel="email", to=to),
            prompt=prompt,
            trigger_command=trigger_command,
            trigger_timeout=trigger_timeout,
        )
    }


def _force_tick(service) -> None:
    """Set all schedule next_fire to the past and call _tick().

    This deterministically triggers all due schedules without relying
    on the background thread or real time passage.
    """
    scheduler = service._scheduler
    assert scheduler is not None
    with scheduler._lock:
        for repo_scheds in scheduler._schedules.values():
            for sched in repo_scheds.values():
                sched.next_fire = datetime.now(tz=UTC) - timedelta(minutes=5)
    scheduler._tick()


class _ServiceRunner:
    """Context manager that starts/stops a service in a background thread."""

    def __init__(self, env: IntegrationEnvironment):
        self.env = env
        self.service = env.create_service()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(
            target=lambda: self.service.start(), daemon=True
        )
        self._thread.start()
        wait_for_boot(self.service, timeout=15.0)
        return self.service

    def __exit__(self, *exc):
        self.service.stop()
        if self._thread:
            self._thread.join(timeout=10.0)
        return False


# ── Prompt Mode ───────────────────────────────────────────────────────


class TestSchedulerPromptMode:
    """End-to-end tests for prompt mode scheduled tasks."""

    def test_prompt_mode_delivers_email(self, tmp_path: Path) -> None:
        """Prompt mode: scheduler fires → Claude runs → email delivered.

        Full end-to-end happy path. Verifies the email arrives at
        the test SMTP server with the correct subject format.
        """
        schedules = _make_schedule_config(prompt=_MOCK_CLAUDE_CODE)
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                _force_tick(service)

                task = wait_for_task(
                    service.tracker,
                    lambda t: (
                        t.display_title == "scheduled: daily"
                        and t.status.value == "completed"
                    ),
                    timeout=30.0,
                )
                assert task is not None, "Scheduled task did not complete"
                assert task.sender == "scheduler"

                result_email = env.email_server.wait_for_sent(
                    lambda m: "[ID:" in (m.get("Subject", "")),
                    timeout=10.0,
                )
                assert result_email is not None, "No delivery email received"
                subject = result_email["Subject"]
                assert "daily" in subject
                assert "[ID:" in subject
                assert result_email["To"] == "user@test.local"

                body = get_message_text(result_email)
                assert len(body) > 0, "Email body is empty"
        finally:
            env.cleanup()

    def test_conversation_id_in_message_id_for_reply_routing(
        self, tmp_path: Path
    ) -> None:
        """The delivery email's Message-ID embeds the conversation ID.

        This enables reply-back: when the recipient replies, the IMAP
        listener extracts the conversation ID from In-Reply-To and
        resumes the conversation.
        """
        schedules = _make_schedule_config(prompt=_MOCK_CLAUDE_CODE)
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                _force_tick(service)

                task = wait_for_task(
                    service.tracker,
                    lambda t: (
                        t.display_title == "scheduled: daily"
                        and t.status.value == "completed"
                    ),
                    timeout=30.0,
                )
                assert task is not None

                result_email = env.email_server.wait_for_sent(
                    lambda m: "[ID:" in (m.get("Subject", "")),
                    timeout=10.0,
                )
                assert result_email is not None

                subject = result_email["Subject"]
                match = re.search(r"\[ID:([a-f0-9]+)\]", subject)
                assert match is not None, (
                    f"No conversation ID in subject: {subject}"
                )
                conv_id = match.group(1)

                message_id = result_email["Message-ID"]
                assert conv_id in message_id, (
                    f"Conv ID {conv_id} not in Message-ID: {message_id}"
                )
                assert message_id.startswith("<airut."), (
                    f"Message-ID should start with <airut.: {message_id}"
                )
        finally:
            env.cleanup()


# ── Script Mode ───────────────────────────────────────────────────────


class TestSchedulerScriptMode:
    """Tests for script mode scheduled tasks.

    Script mode runs a CommandTask first, then conditionally runs Claude
    based on exit code and stdout. Since mock_podman can't execute
    arbitrary commands, we mock _run_command_task to return controlled
    CommandResult values and let the rest of the pipeline run end-to-end.
    """

    def test_script_exit_0_with_output_runs_claude(
        self, tmp_path: Path
    ) -> None:
        """Script exits 0 with stdout → stdout becomes Claude's prompt.

        The script output is used as the prompt body, Claude runs,
        and the result is delivered via email.
        """
        from airut.sandbox.types import CommandResult

        schedules = _make_schedule_config(
            prompt=None,
            trigger_command="check-status",
        )
        env = _create_schedule_env(tmp_path, schedules)

        # Mock _run_command_task to return exit 0 with mock code output.
        # The output becomes Claude's prompt, so it must be valid mock code.
        mock_result = CommandResult(
            exit_code=0,
            stdout=_MOCK_CLAUDE_CODE,
            stderr="",
            duration_ms=50,
            timed_out=False,
        )

        try:
            with _ServiceRunner(env) as service:
                # Keep patch active during entire execution
                with patch(
                    "airut.gateway.scheduler.execution._run_command_task",
                    return_value=mock_result,
                ):
                    _force_tick(service)

                    task = wait_for_task(
                        service.tracker,
                        lambda t: (
                            t.display_title == "scheduled: daily"
                            and t.status.value == "completed"
                        ),
                        timeout=30.0,
                    )
                    assert task is not None, "Script mode task did not complete"

                result_email = env.email_server.wait_for_sent(
                    lambda m: "[ID:" in (m.get("Subject", "")),
                    timeout=10.0,
                )
                assert result_email is not None, (
                    "No delivery email after script mode"
                )
        finally:
            env.cleanup()

    def test_script_exit_0_empty_output_skips_claude(
        self, tmp_path: Path
    ) -> None:
        """Script exits 0 with empty stdout → no Claude, no email.

        This is the "all clear" case: the script checked something,
        found nothing wrong, and the system should be silent.
        """
        from airut.sandbox.types import CommandResult

        schedules = _make_schedule_config(
            prompt=None,
            trigger_command="check-status",
        )
        env = _create_schedule_env(tmp_path, schedules)

        mock_result = CommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            duration_ms=50,
            timed_out=False,
        )

        try:
            with _ServiceRunner(env) as service:
                # Keep patch active during entire execution
                with patch(
                    "airut.gateway.scheduler.execution._run_command_task",
                    return_value=mock_result,
                ):
                    _force_tick(service)

                    task = wait_for_task(
                        service.tracker,
                        lambda t: (
                            t.display_title == "scheduled: daily"
                            and t.status.value == "completed"
                        ),
                        timeout=10.0,
                    )
                    assert task is not None, (
                        "Task should complete even when skipping Claude"
                    )

                # No email should be sent
                result_email = env.email_server.wait_for_sent(
                    lambda m: "[ID:" in (m.get("Subject", "")),
                    timeout=2.0,
                )
                assert result_email is None, (
                    "Should not send email when script produces no output"
                )
        finally:
            env.cleanup()

    def test_script_nonzero_exit_generates_error_prompt(
        self, tmp_path: Path
    ) -> None:
        """Script exits non-zero → system generates error prompt for Claude.

        When the script fails, Claude gets an error prompt with the
        command, exit code, and output. The mock code is embedded in
        the stdout so mock_claude can parse and execute it.
        """
        from airut.sandbox.types import CommandResult

        schedules = _make_schedule_config(
            prompt=None,
            trigger_command="check-status",
        )
        env = _create_schedule_env(tmp_path, schedules)

        # The error prompt embeds the script output. Include mock code
        # so that when _build_script_error_prompt produces the combined
        # prompt, mock_claude finds valid events code to execute.
        mock_result = CommandResult(
            exit_code=1,
            stdout=f"Something failed\n{_MOCK_CLAUDE_CODE}",
            stderr="",
            duration_ms=50,
            timed_out=False,
        )

        try:
            with _ServiceRunner(env) as service:
                # Keep patch active during entire execution
                with patch(
                    "airut.gateway.scheduler.execution._run_command_task",
                    return_value=mock_result,
                ):
                    _force_tick(service)

                    task = wait_for_task(
                        service.tracker,
                        lambda t: (
                            t.display_title == "scheduled: daily"
                            and t.status.value == "completed"
                        ),
                        timeout=30.0,
                    )
                    assert task is not None, (
                        "Script error task should still complete"
                    )

                result_email = env.email_server.wait_for_sent(
                    lambda m: "[ID:" in (m.get("Subject", "")),
                    timeout=10.0,
                )
                assert result_email is not None, (
                    "Should deliver email after script failure"
                )
        finally:
            env.cleanup()


# ── Scheduler Tick Logic ──────────────────────────────────────────────


class TestSchedulerTickDirect:
    """Tests that exercise _tick() directly for deterministic timing.

    These tests bypass the background thread and call _tick() at
    controlled times to verify scheduling logic.
    """

    def test_schedule_not_due_is_not_dispatched(self, tmp_path: Path) -> None:
        """Schedules whose next_fire is in the future are not dispatched."""
        schedules = _make_schedule_config(
            cron="0 0 1 1 *",
            prompt=_MOCK_CLAUDE_CODE,
        )
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                # Tick without manipulating next_fire — schedule is far future
                service._scheduler._tick()

                all_tasks = service.tracker.get_all_tasks()
                scheduled_tasks = [
                    t
                    for t in all_tasks
                    if t.display_title.startswith("scheduled:")
                ]
                assert len(scheduled_tasks) == 0, (
                    "Far-future schedule should not have fired"
                )
        finally:
            env.cleanup()

    def test_tick_dispatches_due_schedule(self, tmp_path: Path) -> None:
        """Calling _tick() with a past next_fire dispatches the task."""
        schedules = _make_schedule_config(
            cron="0 0 1 1 *",
            prompt=_MOCK_CLAUDE_CODE,
        )
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                _force_tick(service)

                task = wait_for_task(
                    service.tracker,
                    lambda t: t.display_title == "scheduled: daily",
                    timeout=10.0,
                )
                assert task is not None, "Tick should have dispatched the task"
        finally:
            env.cleanup()

    def test_tick_recomputes_next_fire_after_dispatch(
        self, tmp_path: Path
    ) -> None:
        """After dispatching, next_fire advances to the next occurrence."""
        schedules = _make_schedule_config(
            cron="0 0 1 1 *",
            prompt=_MOCK_CLAUDE_CODE,
        )
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                _force_tick(service)

                # next_fire should now be in the future (next Jan 1)
                scheduler = service._scheduler
                with scheduler._lock:
                    for repo_scheds in scheduler._schedules.values():
                        for sched in repo_scheds.values():
                            assert sched.next_fire > datetime.now(tz=UTC), (
                                "next_fire should be in the future after tick"
                            )
        finally:
            env.cleanup()


# ── Lifecycle ─────────────────────────────────────────────────────────


class TestSchedulerLifecycle:
    """Tests for scheduler start/stop and config reload integration."""

    def test_scheduler_starts_and_stops_cleanly(self, tmp_path: Path) -> None:
        """Scheduler starts during boot and stops cleanly on shutdown."""
        schedules = _make_schedule_config(prompt=_MOCK_CLAUDE_CODE)
        env = _create_schedule_env(tmp_path, schedules)

        try:
            runner = _ServiceRunner(env)
            service = runner.__enter__()
            try:
                assert service._scheduler is not None
                assert service._scheduler._thread is not None
                assert service._scheduler._thread.is_alive()

                with service._scheduler._lock:
                    total = sum(
                        len(v) for v in service._scheduler._schedules.values()
                    )
                assert total == 1, f"Expected 1 schedule, got {total}"
            finally:
                runner.__exit__(None, None, None)

            # After stop, thread should have exited
            assert not service._scheduler._thread.is_alive()
        finally:
            env.cleanup()

    def test_rebuild_repo_updates_schedules(self, tmp_path: Path) -> None:
        """rebuild_repo() replaces schedules with new config."""
        schedules = _make_schedule_config(prompt=_MOCK_CLAUDE_CODE)
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                scheduler = service._scheduler
                assert scheduler is not None

                with scheduler._lock:
                    assert "test" in scheduler._schedules
                    assert "daily" in scheduler._schedules["test"]

                # Update the handler's config with new schedules
                from airut.gateway.config import (
                    ScheduleConfig,
                    ScheduleDelivery,
                )

                handler = service.repo_handlers["test"]
                new_schedules = {
                    "weekly": ScheduleConfig(
                        cron="0 9 * * 1",
                        deliver=ScheduleDelivery(
                            channel="email", to="user@test.local"
                        ),
                        prompt="New weekly prompt",
                    ),
                }
                object.__setattr__(handler.config, "schedules", new_schedules)

                scheduler.rebuild_repo("test")

                with scheduler._lock:
                    assert "daily" not in scheduler._schedules.get("test", {})
                    assert "weekly" in scheduler._schedules.get("test", {})
                    new_config = scheduler._schedules["test"]["weekly"].config
                    assert new_config.prompt == "New weekly prompt"
        finally:
            env.cleanup()

    def test_remove_repo_clears_schedules(self, tmp_path: Path) -> None:
        """remove_repo() removes all schedules for a repo."""
        schedules = _make_schedule_config(prompt=_MOCK_CLAUDE_CODE)
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                scheduler = service._scheduler
                assert scheduler is not None

                with scheduler._lock:
                    assert "test" in scheduler._schedules

                scheduler.remove_repo("test")

                with scheduler._lock:
                    assert "test" not in scheduler._schedules
        finally:
            env.cleanup()


# ── Edge Cases ────────────────────────────────────────────────────────


class TestSchedulerEdgeCases:
    """Edge case and bug-hunting tests."""

    def test_no_schedules_service_still_boots(self, tmp_path: Path) -> None:
        """Service boots cleanly with no schedules configured."""
        env = _create_schedule_env(tmp_path, schedules={})

        try:
            with _ServiceRunner(env) as service:
                assert service._scheduler is not None
                with service._scheduler._lock:
                    total = sum(
                        len(v) for v in service._scheduler._schedules.values()
                    )
                assert total == 0
        finally:
            env.cleanup()

    def test_multiple_schedules_in_same_repo(self, tmp_path: Path) -> None:
        """Multiple schedules in one repo are all tracked."""
        from airut.gateway.config import ScheduleConfig, ScheduleDelivery

        schedules = {
            "morning": ScheduleConfig(
                cron="0 9 * * *",
                deliver=ScheduleDelivery(channel="email", to="user@test.local"),
                prompt=_MOCK_CLAUDE_CODE,
            ),
            "evening": ScheduleConfig(
                cron="0 17 * * *",
                deliver=ScheduleDelivery(channel="email", to="user@test.local"),
                prompt=_MOCK_CLAUDE_CODE,
            ),
        }
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                scheduler = service._scheduler
                assert scheduler is not None

                with scheduler._lock:
                    repo_scheds = scheduler._schedules.get("test", {})
                    assert "morning" in repo_scheds
                    assert "evening" in repo_scheds
                    assert len(repo_scheds) == 2
        finally:
            env.cleanup()

    def test_compute_sleep_respects_max(self, tmp_path: Path) -> None:
        """_compute_sleep() never returns more than _MAX_SLEEP_SECONDS."""
        from airut.gateway.scheduler.service import _MAX_SLEEP_SECONDS

        schedules = _make_schedule_config(
            cron="0 0 1 1 *",
            prompt=_MOCK_CLAUDE_CODE,
        )
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                scheduler = service._scheduler
                assert scheduler is not None

                sleep = scheduler._compute_sleep()
                assert sleep <= _MAX_SLEEP_SECONDS
                assert sleep >= 0.1
        finally:
            env.cleanup()

    def test_dispatch_with_missing_handler_logs_error(
        self, tmp_path: Path
    ) -> None:
        """Dispatching a schedule for a removed repo handler doesn't crash."""
        from zoneinfo import ZoneInfo

        from airut.gateway.config import ScheduleConfig, ScheduleDelivery
        from airut.gateway.scheduler.cron import CronExpression
        from airut.gateway.scheduler.service import _ResolvedSchedule

        schedules = _make_schedule_config(
            cron="0 0 1 1 *",
            prompt=_MOCK_CLAUDE_CODE,
        )
        env = _create_schedule_env(tmp_path, schedules)

        try:
            with _ServiceRunner(env) as service:
                scheduler = service._scheduler
                assert scheduler is not None

                orphan = _ResolvedSchedule(
                    repo_id="nonexistent",
                    name="orphan",
                    config=ScheduleConfig(
                        cron="* * * * *",
                        deliver=ScheduleDelivery(
                            channel="email", to="user@test.local"
                        ),
                        prompt=_MOCK_CLAUDE_CODE,
                    ),
                    cron=CronExpression("* * * * *"),
                    tz=ZoneInfo("UTC"),
                    next_fire=datetime.now(tz=UTC) - timedelta(minutes=1),
                )

                # Should handle missing handler gracefully (log, not crash)
                scheduler._dispatch(orphan)

                # _dispatch returns synchronously on missing handler
                all_tasks = service.tracker.get_all_tasks()
                orphan_tasks = [
                    t for t in all_tasks if "orphan" in t.display_title
                ]
                assert len(orphan_tasks) == 0, (
                    "Should not dispatch task for missing handler"
                )
        finally:
            env.cleanup()
