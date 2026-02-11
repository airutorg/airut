# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Claude Code execution wrapper for Airut email gateway.

This module manages Podman container execution of Claude Code, including
two-layer image building, container lifecycle, and output parsing.

The container image is built in two layers:
1. **Repo image**: Built from ``.airut/container/Dockerfile`` read from the git
   mirror. Contains the tools and dependencies the repository needs.
2. **Overlay image**: Built on top of the repo image, adding the Airut-specific
   entrypoint script from the server's ``docker/`` directory (entrypoint).

Images are cached by content hash (SHA-256 of Dockerfile / entrypoint) and
rebuilt when stale (default 24 hours) to pick up upstream tool updates.
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lib.container.network import get_network_args
from lib.git_mirror import GitMirrorCache


if TYPE_CHECKING:
    from lib.container.proxy import TaskProxy


logger = logging.getLogger(__name__)

# Path to the repo Dockerfile inside the git mirror
_REPO_DOCKERFILE_PATH = ".airut/container/Dockerfile"


class ExecutorError(Exception):
    """Base exception for executor-related errors."""


class ImageBuildError(ExecutorError):
    """Raised when container image build fails."""


class ContainerTimeoutError(ExecutorError):
    """Raised when container execution times out."""


class JSONParseError(ExecutorError):
    """Raised when Claude output cannot be parsed as JSON."""


@dataclass
class ExecutionResult:
    """Result of Claude Code execution.

    Attributes:
        success: True if execution succeeded (exit code 0).
        output: Parsed JSON output from Claude (if success=True).
        error_message: Human-readable error message (if success=False).
        stdout: Raw stdout from container.
        stderr: Raw stderr from container.
        exit_code: Container exit code.
    """

    success: bool
    output: dict[str, Any] | None
    error_message: str
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class _ImageInfo:
    """Tracks a built image and its build time."""

    tag: str
    built_at: datetime


class ClaudeExecutor:
    """Executes Claude Code in isolated Podman containers.

    Uses a two-layer image build: a repo-defined base image (read from the git
    mirror) and a server-defined overlay (with the Airut entrypoint). Images
    are cached by content hash and rebuilt when stale.

    Attributes:
        entrypoint_path: Path to airut-entrypoint.sh.

    Thread Safety:
        This class is thread-safe. Multiple threads may call execute()
        concurrently. Image builds are serialized via a lock.
    """

    def __init__(
        self,
        mirror: GitMirrorCache,
        entrypoint_path: Path,
        container_command: str = "podman",
        max_age_hours: int = 24,
    ) -> None:
        """Initialize executor.

        Args:
            mirror: Git mirror cache for reading repo Dockerfile.
            entrypoint_path: Path to docker/airut-entrypoint.sh.
            container_command: Container runtime command (podman or docker).
            max_age_hours: Maximum image age before rebuild (default: 24).

        Raises:
            ValueError: If entrypoint_path doesn't exist.
        """
        self._mirror = mirror
        self.entrypoint_path = entrypoint_path
        self._container_command = container_command
        self._max_age_hours = max_age_hours

        if not self.entrypoint_path.exists():
            raise ValueError(
                f"Entrypoint does not exist: {self.entrypoint_path}"
            )

        # Thread safety for builds
        self._build_lock = threading.Lock()

        # Track running processes for stop functionality
        # Maps conversation_id -> subprocess.Popen
        self._running_processes: dict[str, subprocess.Popen[str]] = {}
        self._processes_lock = threading.Lock()

        # Cache built images by content hash
        self._repo_images: dict[str, _ImageInfo] = {}
        self._overlay_images: dict[str, _ImageInfo] = {}
        self._image_cache_lock = threading.Lock()

    @property
    def container_command(self) -> str:
        """Get container runtime command."""
        return self._container_command

    def _content_hash(self, content: bytes | str) -> str:
        """Compute SHA-256 hex digest of content."""
        if isinstance(content, str):
            content = content.encode()
        return hashlib.sha256(content).hexdigest()

    def _is_image_fresh(self, info: _ImageInfo) -> bool:
        """Check if an image is younger than max_age_hours."""
        age = datetime.now() - info.built_at
        return age <= timedelta(hours=self._max_age_hours)

    def _image_exists(self, tag: str) -> bool:
        """Check if a container image exists locally."""
        try:
            subprocess.run(
                [self.container_command, "image", "inspect", tag],
                check=True,
                capture_output=True,
                text=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _build_repo_image(
        self,
        dockerfile_content: bytes,
        context_files: dict[str, bytes] | None = None,
    ) -> str:
        """Build the repo image from Dockerfile content.

        Args:
            dockerfile_content: Raw Dockerfile bytes from the mirror.
            context_files: Additional files to include in the build context.
                Maps filename to content bytes. These are files from the
                ``.airut/container/`` directory that the Dockerfile may
                reference via COPY instructions.

        Returns:
            Image tag (e.g., ``airut-repo:abcdef0123456789``).

        Raises:
            ImageBuildError: If build fails.
        """
        context_files = context_files or {}

        # Include context files in hash for cache key
        hash_input = dockerfile_content
        for filename in sorted(context_files.keys()):
            hash_input += filename.encode() + context_files[filename]
        content_hash = self._content_hash(hash_input)
        tag = f"airut-repo:{content_hash}"

        # Check cache
        with self._image_cache_lock:
            cached = self._repo_images.get(content_hash)
            if cached and self._is_image_fresh(cached):
                logger.debug("Repo image %s is fresh, reusing", tag)
                return tag

        # Build in temp directory
        logger.info("Building repo image: %s", tag)
        start_time = time.time()

        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = Path(tmpdir) / "Dockerfile"
            dockerfile_path.write_bytes(dockerfile_content)

            # Write additional context files
            for filename, content in context_files.items():
                file_path = Path(tmpdir) / filename
                file_path.write_bytes(content)
                logger.debug("Added context file: %s", filename)

            cmd = [
                self.container_command,
                "build",
                "-t",
                tag,
                "-f",
                str(dockerfile_path),
                tmpdir,
            ]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                logger.error("Failed to build repo image: %s", error_msg)
                raise ImageBuildError(f"Repo image build failed: {error_msg}")

        elapsed = time.time() - start_time
        logger.info("Repo image built in %.2fs: %s", elapsed, tag)

        with self._image_cache_lock:
            self._repo_images[content_hash] = _ImageInfo(
                tag=tag, built_at=datetime.now()
            )

        return tag

    def _build_overlay_image(
        self, repo_tag: str, entrypoint_content: bytes
    ) -> str:
        """Build the overlay image on top of the repo image.

        Args:
            repo_tag: Tag of the repo image to use as base.
            entrypoint_content: Raw entrypoint script bytes.

        Returns:
            Overlay image tag (e.g., ``airut:abcdef0123456789``).

        Raises:
            ImageBuildError: If build fails.
        """
        overlay_hash = self._content_hash(
            repo_tag.encode() + entrypoint_content
        )
        tag = f"airut:{overlay_hash}"

        # Check cache
        with self._image_cache_lock:
            cached = self._overlay_images.get(overlay_hash)
            if cached and self._is_image_fresh(cached):
                logger.debug("Overlay image %s is fresh, reusing", tag)
                return tag

        logger.info("Building overlay image: %s (base: %s)", tag, repo_tag)
        start_time = time.time()

        # Build overlay with entrypoint
        overlay_dockerfile = (
            f"FROM {repo_tag}\n"
            "COPY airut-entrypoint.sh /entrypoint.sh\n"
            "RUN chmod +x /entrypoint.sh\n"
            'ENTRYPOINT ["/entrypoint.sh"]\n'
        )

        # Use the entrypoint's parent directory as context so COPY works
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write overlay Dockerfile
            df_path = Path(tmpdir) / "Dockerfile"
            df_path.write_text(overlay_dockerfile)

            # Copy entrypoint into build context
            ep_path = Path(tmpdir) / "airut-entrypoint.sh"
            ep_path.write_bytes(entrypoint_content)

            cmd = [
                self.container_command,
                "build",
                "-t",
                tag,
                "-f",
                str(df_path),
                tmpdir,
            ]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else str(e)
                logger.error("Failed to build overlay image: %s", error_msg)
                raise ImageBuildError(
                    f"Overlay image build failed: {error_msg}"
                )

        elapsed = time.time() - start_time
        logger.info("Overlay image built in %.2fs: %s", elapsed, tag)

        with self._image_cache_lock:
            self._overlay_images[overlay_hash] = _ImageInfo(
                tag=tag, built_at=datetime.now()
            )

        return tag

    def ensure_image(self) -> str:
        """Build or reuse the two-layer container image.

        Reads all files from the ``.airut/container/`` directory in the git
        mirror, builds the repo image if needed, then builds the overlay image
        with the entrypoint.

        Returns:
            The overlay image tag to use for container execution.

        Raises:
            ImageBuildError: If either layer fails to build.
        """
        with self._build_lock:
            # Read all files from .airut/container/ directory
            container_dir = ".airut/container"
            try:
                filenames = self._mirror.list_directory(container_dir)
            except Exception as e:
                raise ImageBuildError(
                    f"Failed to list {container_dir} from mirror: {e}"
                )

            # Read each file from the container directory
            dockerfile_content: bytes | None = None
            context_files: dict[str, bytes] = {}

            for filename in filenames:
                file_path = f"{container_dir}/{filename}"
                try:
                    content = self._mirror.read_file(file_path)
                except Exception as e:
                    raise ImageBuildError(
                        f"Failed to read {file_path} from mirror: {e}"
                    )

                if filename == "Dockerfile":
                    dockerfile_content = content
                else:
                    context_files[filename] = content

            if dockerfile_content is None:
                raise ImageBuildError(f"No Dockerfile found in {container_dir}")

            # Read entrypoint from local filesystem
            entrypoint_content = self.entrypoint_path.read_bytes()

            # Build repo image (cached by content hash + staleness)
            repo_tag = self._build_repo_image(dockerfile_content, context_files)

            # Build overlay image (cached by combined hash + staleness)
            overlay_tag = self._build_overlay_image(
                repo_tag, entrypoint_content
            )

            return overlay_tag

    def stop_execution(self, conversation_id: str) -> bool:
        """Stop a running execution for a conversation.

        Args:
            conversation_id: Conversation ID to stop.

        Returns:
            True if execution was stopped, False if not found.
        """
        with self._processes_lock:
            process = self._running_processes.get(conversation_id)
            if process is None:
                logger.warning(
                    "No running process found for conversation %s",
                    conversation_id,
                )
                return False

            logger.info(
                "Stopping execution for conversation %s", conversation_id
            )
            try:
                # Send SIGTERM to gracefully terminate container
                process.send_signal(signal.SIGTERM)
                # Wait up to 5 seconds for graceful shutdown
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    logger.warning(
                        "Process did not terminate gracefully, sending SIGKILL"
                    )
                    process.kill()
                    process.wait()
                # Remove from tracking
                self._running_processes.pop(conversation_id, None)
                return True
            except Exception as e:
                logger.error("Failed to stop process: %s", e)
                return False

    def execute(
        self,
        session_git_repo: Path,
        prompt: str,
        mounts: list[str],
        image_tag: str,
        session_id: str | None = None,
        model: str = "sonnet",
        on_event: Callable[[dict[str, Any]], None] | None = None,
        conversation_id: str | None = None,
        task_proxy: TaskProxy | None = None,
        container_env: dict[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> ExecutionResult:
        """Execute Claude Code in container with given prompt.

        Volume mounts are provided by the caller (typically built by
        ``conversation_layout.get_container_mounts()``). Environment variables
        come from repo config (per-task).

        Args:
            session_git_repo: Path to session git repository (workspace).
            prompt: User prompt to pass to Claude.
            mounts: Volume mount strings for podman ``-v`` flags.
            image_tag: Container image tag to use (from ``ensure_image()``).
            session_id: Optional session ID for --resume flag. When provided,
                Claude will resume the conversation context from that session.
            model: Claude model to use (e.g., "opus", "sonnet", "haiku").
                Passed via --model CLI parameter. Defaults to "sonnet".
            on_event: Optional callback to invoke for each streaming JSON event.
                Called with each parsed event dict as it arrives.
            conversation_id: Optional conversation ID for tracking running
                processes (enables stop functionality).
            task_proxy: Optional TaskProxy for network allowlisting.
            container_env: Environment variables to pass to the container.
            timeout_seconds: Maximum execution time in seconds.

        Returns:
            ExecutionResult with parsed output or error details.

        Raises:
            ExecutorError: If container execution fails unexpectedly.
        """
        return self._run_container(
            session_git_repo,
            prompt,
            mounts,
            image_tag,
            session_id,
            model,
            on_event,
            conversation_id,
            task_proxy,
            container_env=container_env or {},
            timeout_seconds=timeout_seconds,
        )

    def _run_container(
        self,
        session_git_repo: Path,
        prompt: str,
        mounts: list[str],
        image_tag: str,
        session_id: str | None,
        model: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        conversation_id: str | None = None,
        task_proxy: TaskProxy | None = None,
        container_env: dict[str, str] | None = None,
        timeout_seconds: int = 300,
    ) -> ExecutionResult:
        """Run the container with the given configuration."""
        logger.info(
            "Executing Claude Code (model=%s) for conversation in %s",
            model,
            session_git_repo,
        )

        # Build command
        # Add -i flag to keep stdin open for passing prompt
        # Disable Podman's journald logging since we capture
        # stdout/stderr ourselves
        cmd = [self.container_command, "run", "--rm", "-i", "--log-driver=none"]

        # Pass environment variables to container
        env = container_env or {}
        for env_var, value in env.items():
            cmd.extend(["-e", f"{env_var}={value}"])

        for mount in mounts:
            cmd.extend(["-v", mount])

        # Network allowlist: restrict container to internal network with proxy
        cmd.extend(get_network_args(task_proxy))

        cmd.append(image_tag)

        # Build claude command with optional --resume and --model
        claude_cmd = ["claude"]
        if session_id:
            claude_cmd.extend(["--resume", session_id])
            logger.info("Resuming session: %s", session_id)
        # Pass model via --model parameter
        claude_cmd.extend(["--model", model])
        claude_cmd.extend(
            [
                "-p",
                "-",  # Read prompt from stdin
                "--dangerously-skip-permissions",
                "--output-format",
                "stream-json",
                "--verbose",
            ]
        )
        cmd.extend(claude_cmd)

        logger.info(
            "Executing Claude Code with prompt (length=%d): %s",
            len(prompt),
            prompt,
        )
        # Redact secrets from logged command
        # Redact all environment variables passed to container
        redacted_cmd = []
        skip_next = False
        for i, arg in enumerate(cmd):
            if skip_next:
                skip_next = False
                continue
            if arg == "-e" and i + 1 < len(cmd):
                next_arg = cmd[i + 1]
                # Redact any env var that contains sensitive data
                if "=" in next_arg:
                    var_name = next_arg.split("=")[0]
                    redacted_cmd.extend(["-e", f"{var_name}=***"])
                    skip_next = True
                    continue
            redacted_cmd.append(arg)
        logger.debug("Full command: %s", " ".join(redacted_cmd))

        start_time = time.time()

        try:
            # Use Popen to stream output line-by-line
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Track process if conversation_id provided
            if conversation_id:
                with self._processes_lock:
                    self._running_processes[conversation_id] = process
                    logger.debug(
                        "Tracking process for conversation %s", conversation_id
                    )

            try:
                # Send prompt to stdin and close it
                if process.stdin:
                    process.stdin.write(prompt)
                    process.stdin.close()

                # Collect output and stream events
                stdout_lines: list[str] = []
                stderr_lines: list[str] = []

                # Read stdout line-by-line
                if process.stdout:
                    for line in process.stdout:
                        stdout_lines.append(line)
                        # Try to parse as JSON event and invoke callback
                        if on_event:
                            try:
                                event = json.loads(line.strip())
                                if isinstance(event, dict):
                                    on_event(event)
                            except json.JSONDecodeError:
                                # Skip non-JSON lines
                                pass

                # Wait for process to complete with timeout
                try:
                    process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    logger.error(
                        "Container execution timed out, killing process"
                    )
                    process.kill()
                    process.wait()
                    timeout_msg = (
                        f"Execution timed out after {timeout_seconds} seconds"
                    )
                    raise ContainerTimeoutError(timeout_msg)

                # Read stderr
                if process.stderr:
                    stderr_lines = process.stderr.readlines()

                stdout = "".join(stdout_lines)
                stderr = "".join(stderr_lines)
                exit_code = process.returncode

            finally:
                # Remove from tracking
                if conversation_id:
                    with self._processes_lock:
                        self._running_processes.pop(conversation_id, None)
                        logger.debug(
                            "Removed process tracking for conversation %s",
                            conversation_id,
                        )

            elapsed = time.time() - start_time
            logger.info(
                "Execution completed in %.2fs (exit_code=%d)",
                elapsed,
                exit_code,
            )
            logger.debug(
                "Full stdout (length=%d):\n%s",
                len(stdout),
                stdout,
            )
            if stderr:
                logger.debug(
                    "Full stderr (length=%d):\n%s",
                    len(stderr),
                    stderr,
                )

            # Parse output
            if exit_code == 0:
                parsed_output = self._parse_claude_output(stdout)
                if parsed_output is not None:
                    # Defensive check: ensure parsed_output is a dict
                    if not isinstance(parsed_output, dict):
                        logger.error(
                            "Parser returned non-dict type %s: %s",
                            type(parsed_output).__name__,
                            parsed_output,
                        )
                        error_msg = (
                            f"Parser error: got {type(parsed_output).__name__} "
                            "instead of dict"
                        )
                        return ExecutionResult(
                            success=False,
                            output=None,
                            error_message=error_msg,
                            stdout=stdout,
                            stderr=stderr,
                            exit_code=exit_code,
                        )

                    return ExecutionResult(
                        success=True,
                        output=parsed_output,
                        error_message="",
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=exit_code,
                    )
                else:
                    # Parse failure
                    error_msg = "Failed to parse Claude JSON output"
                    logger.error("%s. Full stdout:\n%s", error_msg, stdout)
                    logger.debug("Full stderr:\n%s", stderr)
                    return ExecutionResult(
                        success=False,
                        output=None,
                        error_message=error_msg,
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=exit_code,
                    )
            else:
                # Non-zero exit code
                stderr_tail_lines = stderr.strip().split("\n")
                stderr_tail = "\n".join(stderr_tail_lines[-20:])
                error_msg = (
                    f"Container execution failed "
                    f"(exit code {exit_code}). "
                    f"Last 20 lines of stderr:\n{stderr_tail}"
                )
                logger.error(
                    "Container execution failed (exit_code=%d): %s",
                    exit_code,
                    stderr[:200],
                )
                return ExecutionResult(
                    success=False,
                    output=None,
                    error_message=error_msg,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                )

        except ContainerTimeoutError:
            # Re-raise timeout errors
            raise

        except Exception as e:
            logger.error("Unexpected container execution error: %s", e)
            raise ExecutorError(f"Container execution failed: {e}")

    def _parse_claude_output(self, stdout: str) -> dict[str, Any] | None:
        """Parse Claude's streaming JSON output.

        Parses the streaming JSON format (--output-format stream-json --verbose)
        which outputs one JSON event per line. Events include:
        - system/init: Session initialization with tools and model
        - assistant: Claude's responses (tool_use or text blocks)
        - user: Tool execution results
        - result: Final execution summary with cost and usage

        Args:
            stdout: Raw stdout from container (newline-delimited JSON).

        Returns:
            Parsed dict with 'events' list and extracted result fields,
            or None if parsing fails completely.
        """
        events: list[dict[str, Any]] = []
        result_event: dict[str, Any] | None = None

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
                    if event.get("type") == "result":
                        result_event = event
            except json.JSONDecodeError:
                # Skip non-JSON lines (should be rare with stream-json)
                logger.debug("Skipping non-JSON line: %s", line[:100])
                continue

        if not events:
            logger.warning("No valid JSON events found in streaming output")
            return None

        logger.debug(
            "Parsed %d streaming JSON events (result=%s)",
            len(events),
            result_event is not None,
        )

        # Build result dict with events and extracted fields from result event
        parsed: dict[str, Any] = {
            "events": events,
        }

        if result_event:
            # Extract standard fields from result event for compatibility
            parsed["session_id"] = result_event.get("session_id", "")
            parsed["duration_ms"] = result_event.get("duration_ms", 0)
            parsed["total_cost_usd"] = result_event.get("total_cost_usd", 0.0)
            parsed["num_turns"] = result_event.get("num_turns", 0)
            parsed["is_error"] = result_event.get("is_error", False)
            parsed["usage"] = result_event.get("usage", {})
            parsed["result"] = result_event.get("result", "")
        else:
            # No result event - mark as error
            logger.warning("No result event found in streaming output")
            parsed["session_id"] = ""
            parsed["duration_ms"] = 0
            parsed["total_cost_usd"] = 0.0
            parsed["num_turns"] = 0
            parsed["is_error"] = True
            parsed["usage"] = {}
            parsed["result"] = ""

        return parsed


def extract_error_summary(stdout: str, max_lines: int = 10) -> str | None:
    """Extract a human-readable error summary from streaming JSON output.

    Parses the streaming JSON output to find error information, extracting
    text content from assistant messages to provide a more readable summary
    than raw JSON.

    Args:
        stdout: Raw stdout containing streaming JSON (newline-delimited).
        max_lines: Maximum number of lines to include in the summary.

    Returns:
        Formatted error summary string, or None if no useful info found.
    """
    if not stdout or not stdout.strip():
        return None

    text_blocks: list[str] = []
    result_text: str | None = None

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                continue

            event_type = event.get("type")

            # Extract text from assistant messages
            if event_type == "assistant":
                message = event.get("message", {})
                content = message.get("content", [])
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "").strip()
                        if text:
                            text_blocks.append(text)

            # Extract result text
            elif event_type == "result":
                result = event.get("result", "")
                if result:
                    result_text = result

        except json.JSONDecodeError:
            continue

    # Prefer result text if available
    if result_text:
        lines = result_text.strip().split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "\n".join(lines)

    # Fall back to concatenated text blocks
    if text_blocks:
        combined = "\n".join(text_blocks)
        lines = combined.strip().split("\n")
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "\n".join(lines)

    return None
