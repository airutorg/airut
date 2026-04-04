# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Scheduled task execution.

Orchestrates prompt and script mode flows, delegating sandbox execution
to ``run_in_sandbox()`` and result delivery to ``deliver_result()``.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from typing import TYPE_CHECKING

from airut.dashboard.tracker import CompletionReason
from airut.gateway.config import ScheduleConfig
from airut.gateway.scheduler.delivery import deliver_result
from airut.gateway.service.message_processing import (
    run_in_sandbox,
)


if TYPE_CHECKING:
    from airut.gateway.service.gateway import GatewayService
    from airut.gateway.service.repo_handler import RepoHandler
    from airut.sandbox import CommandResult

logger = logging.getLogger(__name__)


def execute_scheduled_task(
    service: GatewayService,
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    task_id: str,
) -> None:
    """Execute a scheduled task. Runs in the shared worker pool.

    For prompt mode: builds the prompt and calls ``run_in_sandbox()``.
    For script mode: runs the trigger command first, then conditionally
    calls ``run_in_sandbox()`` based on the script's output/exit code.

    Args:
        service: Parent service for shared resources.
        repo_handler: Repo handler that owns this schedule.
        schedule_name: Name of the schedule being executed.
        config: Schedule configuration.
        task_id: Task ID for dashboard tracking.
    """
    repo_id = repo_handler.config.repo_id
    reason = CompletionReason.INTERNAL_ERROR

    try:
        service.tracker.set_executing(task_id)

        if config.trigger_command is not None:
            reason = _execute_script_mode(
                service, repo_handler, schedule_name, config, task_id
            )
        else:
            reason = _execute_prompt_mode(
                service, repo_handler, schedule_name, config, task_id
            )
    except Exception:
        logger.exception(
            "Schedule '%s/%s': execution failed (task %s)",
            repo_id,
            schedule_name,
            task_id,
        )
        reason = CompletionReason.INTERNAL_ERROR
    finally:
        service.tracker.complete_task(task_id, reason)
        # Check deferred config reloads
        service._check_pending_repo_reload(repo_id)
        service._check_pending_server_reload()


def _execute_prompt_mode(
    service: GatewayService,
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    task_id: str,
) -> CompletionReason:
    """Execute prompt mode: run Claude with the configured prompt."""
    repo_id = repo_handler.config.repo_id
    assert config.prompt is not None

    prompt = _build_prompt(repo_handler, schedule_name, config, config.prompt)
    model = config.model or repo_handler.config.model
    effort = config.effort or repo_handler.config.effort

    logger.info(
        "Schedule '%s/%s': executing prompt mode (model=%s)",
        repo_id,
        schedule_name,
        model,
    )

    result = run_in_sandbox(
        service,
        repo_handler,
        prompt=prompt,
        task_id=task_id,
        model=model,
        effort=effort,
    )

    deliver_result(repo_handler, schedule_name, config, result)
    return CompletionReason.SUCCESS


def _execute_script_mode(
    service: GatewayService,
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    task_id: str,
) -> CompletionReason:
    """Execute script mode: run command, then conditionally run Claude."""
    repo_id = repo_handler.config.repo_id
    assert config.trigger_command is not None
    command = shlex.split(config.trigger_command)

    # Initialize conversation for the command task
    conv_mgr = repo_handler.conversation_manager
    logger.info(
        "Schedule '%s/%s': updating git mirror for script mode",
        repo_id,
        schedule_name,
    )
    conv_mgr.mirror.update_mirror()
    conversation_id, _ = conv_mgr.initialize_new()
    service.tracker.set_conversation_id(task_id, conversation_id)

    logger.info(
        "Schedule '%s/%s': running trigger command: %s",
        repo_id,
        schedule_name,
        config.trigger_command,
    )

    # Build command task and execute
    cmd_result = _run_command_task(
        service, repo_handler, conversation_id, command, config
    )

    # Evaluate result
    exit_code = cmd_result.exit_code
    stdout = cmd_result.stdout
    stderr = cmd_result.stderr

    if exit_code == 0 and not stdout.strip():
        # No output, no action needed
        logger.info(
            "Schedule '%s/%s': trigger produced no output, skipping Claude",
            repo_id,
            schedule_name,
        )
        conv_mgr.delete(conversation_id)
        return CompletionReason.SUCCESS

    # Build prompt from script output
    if exit_code == 0:
        # Script output becomes the prompt
        body = _truncate_output(stdout, config.output_limit)
    else:
        # Script failed — generate error prompt
        combined = (stdout + stderr) if stderr else stdout
        body = _build_script_error_prompt(
            command, exit_code, combined, config.output_limit
        )

    prompt = _build_prompt(repo_handler, schedule_name, config, body)
    model = config.model or repo_handler.config.model
    effort = config.effort or repo_handler.config.effort

    logger.info(
        "Schedule '%s/%s': running Claude after trigger (exit=%d, model=%s)",
        repo_id,
        schedule_name,
        exit_code,
        model,
    )

    result = run_in_sandbox(
        service,
        repo_handler,
        prompt=prompt,
        task_id=task_id,
        model=model,
        effort=effort,
        conversation_id=conversation_id,
    )

    deliver_result(repo_handler, schedule_name, config, result)
    return CompletionReason.SUCCESS


def _run_command_task(
    service: GatewayService,
    repo_handler: RepoHandler,
    conversation_id: str,
    command: list[str],
    config: ScheduleConfig,
) -> CommandResult:
    """Run a command in the sandbox for script mode.

    Builds the container environment and mounts, creates a
    ``CommandTask``, and executes the command.
    """
    from airut.allowlist import parse_allowlist_yaml
    from airut.conversation import (
        create_conversation_layout,
        prepare_conversation,
    )
    from airut.gateway.service.message_processing import (
        build_image,
        convert_replacement_map,
    )
    from airut.sandbox import (
        NETWORK_LOG_FILENAME,
        ContainerEnv,
        Mount,
        NetworkSandboxConfig,
    )
    from airut.sandbox.types import ResourceLimits

    repo_cfg = repo_handler.config
    conv_mgr = repo_handler.conversation_manager

    conversation_dir = conv_mgr.get_conversation_dir(conversation_id)
    layout = create_conversation_layout(conversation_dir)
    prepare_conversation(layout)

    task_env, replacement_map = repo_cfg.build_task_env()
    resource_limits = repo_cfg.resource_limits

    # Override timeout if trigger specifies one
    if config.trigger_timeout is not None:
        resource_limits = ResourceLimits(
            timeout=config.trigger_timeout,
            memory=resource_limits.memory,
            cpus=resource_limits.cpus,
            pids_limit=resource_limits.pids_limit,
        )

    image_tag = build_image(
        service,
        conv_mgr.mirror,
        repo_cfg.container_path,
        passthrough_entrypoint=True,
    )

    mounts = [
        Mount(layout.workspace, "/workspace"),
        Mount(layout.inbox, "/inbox"),
        Mount(layout.outbox, "/outbox"),
        Mount(layout.storage, "/storage"),
    ]

    env = ContainerEnv(variables=task_env)

    # Network sandbox
    network_sandbox: NetworkSandboxConfig | None = None
    if repo_cfg.network_sandbox_enabled:
        try:
            allowlist_data = conv_mgr.mirror.read_file(
                ".airut/network-allowlist.yaml"
            )
            allowlist = parse_allowlist_yaml(allowlist_data)
        except Exception as e:
            from airut.sandbox import ProxyError

            raise ProxyError(f"Failed to read/parse allowlist: {e}") from e

        replacements = convert_replacement_map(replacement_map)
        network_sandbox = NetworkSandboxConfig(
            allowlist=allowlist,
            replacements=replacements,
        )

    task = service.sandbox.create_command_task(
        execution_context_id=conversation_id,
        image_tag=image_tag,
        mounts=mounts,
        env=env,
        execution_context_dir=conversation_dir,
        network_log_path=(
            conversation_dir / NETWORK_LOG_FILENAME
            if network_sandbox is not None
            else None
        ),
        network_sandbox=network_sandbox,
        resource_limits=resource_limits,
    )

    result: CommandResult = asyncio.run(task.execute(command))
    return result


def _build_prompt(
    repo_handler: RepoHandler,
    schedule_name: str,
    config: ScheduleConfig,
    body: str,
) -> str:
    """Build the full prompt with channel context header.

    The header uses the delivery channel's standard system prompt
    plus a note identifying the scheduled task.
    """
    adapter = repo_handler.adapters.get(config.deliver.channel)
    if adapter is None:
        # Fallback: no channel context
        return body

    channel_context = adapter.channel_context()

    header = (
        f"{channel_context}\n\n"
        f'This is a scheduled task "{schedule_name}". '
        f"Your response will be delivered to {config.deliver.to} "
        f"via {config.deliver.channel}."
    )

    return f"{header}\n\n{body}"


def _truncate_output(output: str, limit: int) -> str:
    """Truncate output to byte limit, appending a note if truncated."""
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return output

    total_size = len(encoded)
    truncated = encoded[:limit].decode("utf-8", errors="replace")
    size_str = _format_size(total_size)
    limit_str = _format_size(limit)
    return (
        f"{truncated}\n\n"
        f"[...truncated at {limit_str}, total output was {size_str}]"
    )


def _format_size(size: int) -> str:
    """Format byte size as human-readable string."""
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f}MB"
    if size >= 1024:
        return f"{size / 1024:.0f}KB"
    return f"{size}B"


def _build_script_error_prompt(
    command: list[str],
    exit_code: int,
    output: str,
    output_limit: int,
) -> str:
    """Build prompt for a failed trigger script."""
    truncated = _truncate_output(output, output_limit)
    cmd_str = shlex.join(command)
    return (
        "The scheduled trigger script failed unexpectedly.\n\n"
        f"Command: {cmd_str}\n"
        f"Exit code: {exit_code}\n\n"
        "Output:\n"
        f"{truncated}\n\n"
        "Investigate the failure and report findings."
    )
