# Async Sandbox IO

Replaces the synchronous, blocking IO model in the sandbox library with
`asyncio`-based concurrent IO. This fixes the stderr deadlock risk, adds stderr
streaming callbacks, enables parallel network log tailing during execution, and
provides a foundation for interactive container sessions.

## Motivation

The current `run_container()` in `_run_container.py` uses `subprocess.Popen`
with blocking line-by-line IO:

```
process = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
process.stdin.write(data); process.stdin.close()
for line in process.stdout:   # blocks here
    on_stdout_line(line)
process.wait()
stderr = process.stderr.readlines()  # read stderr AFTER stdout is done
```

This has three problems:

1. **Stderr deadlock**: Stdout is read in a blocking loop. Stderr is only read
   after stdout finishes. If the container writes enough stderr to fill the OS
   pipe buffer (~64KB), the container blocks on the stderr write, which prevents
   it from writing more stdout, deadlocking the parent's stdout reader.

2. **No stderr streaming**: `AgentTask` collects stderr silently after
   execution. There is no `on_stderr_line` callback, making it impossible to
   observe container errors in real-time.

3. **No concurrent activities**: The execution path is single-threaded. There is
   no mechanism to tail the network log file in parallel, and no support for
   interactive (bidirectional) IO with the container.

## Design Goals

1. **Concurrent stdout/stderr**: Read both streams simultaneously with no
   deadlock risk, regardless of output volume on either stream.
2. **Streaming callbacks for both streams**: `on_stdout_line` and
   `on_stderr_line` callbacks, invoked in real-time as lines arrive.
3. **Network log tailing**: Optionally tail the proxy's network log file during
   execution, with an `on_network_line` callback.
4. **Interactive mode foundation**: The async architecture enables future
   interactive (bidirectional) IO. See [Interactive Mode](#interactive-mode).
5. **Clean async model**: Use `asyncio` as the single concurrency primitive. No
   manual threading for IO multiplexing.

## Scope

**In scope:**

- `airut/sandbox/_run_container.py` — async rewrite of `run_container()`
- `airut/sandbox/task.py` — async `execute()` on `AgentTask` and `CommandTask`
- `airut/sandbox/sandbox.py` — factory methods unchanged (not async)
- `airut/sandbox_cli.py` — `asyncio.run()` at entry point
- `airut/gateway/service/message_processing.py` — `asyncio.run()` wrapper
- All tests in `tests/sandbox/` — updated for async
- `spec/sandbox.md` — updated to reflect async execution model

**Out of scope:**

- Converting the gateway's threading model to async (future work)
- Async proxy lifecycle management (`_proxy.py`) — proxy start/stop remains
  synchronous (it's a `podman` CLI call, not a long-running IO stream)
- Async image builds — also synchronous podman calls
- `EventLog` and `NetworkLog` classes — file IO remains synchronous (append-only
  writes and offset-based reads are fast and non-blocking in practice)
- Interactive mode implementation (future work; see
  [Interactive Mode](#interactive-mode) for design direction)

## Container Execution

### Async Process Model

Replace `subprocess.Popen` with `asyncio.create_subprocess_exec`:

```python
# airut/sandbox/_run_container.py


async def run_container(
    container_command: str,
    image_tag: str,
    mounts: list[Mount],
    env: ContainerEnv,
    resource_limits: ResourceLimits,
    network_args: list[str],
    command: list[str],
    stdin_data: str | None,
    on_stdout_line: Callable[[str], None] | None,
    on_stderr_line: Callable[[str], None] | None,
    timeout: int | None,
    process_tracker: _ProcessTracker,
) -> _RawResult: ...
```

Key changes:

- Function becomes `async def`.
- `on_stderr_line` callback added (same signature as `on_stdout_line`).
- `stderr_passthrough` parameter removed — stderr is always captured as a pipe
  and delivered via callback. Callers that want passthrough behavior provide a
  callback that writes to `sys.stderr` (see
  [Behavioral Changes](#behavioral-changes)).

### Stream Reading

Both stdout and stderr are read concurrently as async tasks. Asyncio subprocess
streams are binary by default; lines are decoded as UTF-8 with `replace` error
handling to tolerate non-UTF-8 output:

```python
process = await asyncio.create_subprocess_exec(
    *cmd,
    stdin=asyncio.subprocess.PIPE,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)

# Write stdin and close
if process.stdin:  # guard for type checker (always true with stdin=PIPE)
    if stdin_data is not None:
        process.stdin.write(stdin_data.encode())
        await process.stdin.drain()
    process.stdin.close()
    await process.stdin.wait_closed()

# Mutable accumulators that survive cancellation
stdout_lines: list[str] = []
stderr_lines: list[str] = []


async def read_lines(stream, lines, callback):
    async for raw_line in stream:
        line = raw_line.decode("utf-8", errors="replace")
        lines.append(line)
        if callback is not None:
            callback(line)


await asyncio.gather(
    read_lines(process.stdout, stdout_lines, on_stdout_line),
    read_lines(process.stderr, stderr_lines, on_stderr_line),
)

await process.wait()
```

Key design decisions:

- **Binary streams + explicit decode**: `asyncio.create_subprocess_exec` uses
  binary streams. Lines are decoded with `errors="replace"` to prevent crashes
  on non-UTF-8 output (e.g., binary data in stderr from a crash dump).
- **Mutable accumulators**: `stdout_lines` and `stderr_lines` are mutable lists
  defined outside `read_lines`, so partial content is preserved even if the
  coroutine is cancelled by timeout (see [Timeout Handling](#timeout-handling)).
- **Synchronous callbacks**: `on_stdout_line` and `on_stderr_line` remain
  synchronous callables invoked from the event loop thread. All current
  callbacks do lightweight work (list append, event log write, sys.stderr
  write). If a future callback needs heavy processing, it should use
  `loop.run_in_executor()`.
- **Line-based reading**: `async for raw_line in stream` uses asyncio's
  `StreamReader.readline()` internally, which yields complete lines. This
  matches the current `for line in process.stdout` behavior. Note: programs that
  write partial lines without a trailing newline (e.g., progress bars) will have
  those lines buffered until a newline arrives or the stream closes. This is the
  same buffering behavior as the current synchronous code.

### Timeout Handling

Timeout wraps the combined read-and-wait sequence with `asyncio.wait_for()`.
Partial output is preserved via the external mutable accumulators:

```python
stdout_lines: list[str] = []
stderr_lines: list[str] = []


async def _run():
    await asyncio.gather(
        read_lines(process.stdout, stdout_lines, on_stdout_line),
        read_lines(process.stderr, stderr_lines, on_stderr_line),
    )
    await process.wait()


try:
    await asyncio.wait_for(_run(), timeout=timeout)
    timed_out = False
except TimeoutError:
    process.kill()
    await process.wait()
    timed_out = True

stdout = "".join(stdout_lines)
stderr = "".join(stderr_lines)
```

On timeout, the process is killed and `stdout`/`stderr` contain whatever was
read before the deadline. For `AgentTask`, the `on_stdout_line` callback has
already streamed all received events to the event log, so partial events are
preserved regardless of timeout.

Python 3.12+ guarantees that `asyncio.wait_for` cancels and awaits the inner
task before raising `TimeoutError`. Since the project requires Python 3.13+,
cancellation semantics are well-defined.

### Process Lifecycle

`_ProcessTracker` is updated to store the raw PID for cross-thread signal
delivery, avoiding thread-safety issues with `asyncio.subprocess.Process`
attributes:

```python
class _ProcessTracker:
    def __init__(self) -> None:
        self._pid: int | None = None
        self._lock = threading.Lock()

    def set(self, pid: int) -> None:
        with self._lock:
            self._pid = pid

    def clear(self) -> None:
        with self._lock:
            self._pid = None

    def stop(self) -> bool:
        with self._lock:
            pid = self._pid
        if pid is None:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        threading.Timer(5.0, self._force_kill).start()
        return True

    def _force_kill(self) -> None:
        with self._lock:
            pid = self._pid
        if pid is None:
            return  # clear() was called -- process already reaped
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # already exited
```

`set()` takes the raw PID (`int`) rather than an `asyncio.subprocess.Process`
reference, so `_ProcessTracker` has no asyncio dependency. The caller extracts
the PID: `process_tracker.set(process.pid)`.

`stop()` remains a synchronous method callable from any thread because:

- The gateway calls it from a different thread (via `_stop_execution` in
  `gateway.py`)
- Signal handlers call it synchronously
- `os.kill()` is thread-safe at the OS level

Using the raw PID with `os.kill()` instead of `process.send_signal()` avoids
accessing `asyncio.subprocess.Process` from outside the event loop thread.
`asyncio.subprocess.Process.returncode` is updated by the event loop's child
reaper, so checking it from another thread would be a race condition.

**PID reuse safety**: The `_force_kill` timer (5 second delay) re-reads
`self._pid` under the lock. If `clear()` has been called (meaning
`run_container()` finished and the process was reaped), the PID slot is `None`
and the kill is skipped. This prevents sending SIGKILL to an unrelated process
that reused the PID. The OS guarantees that a PID is not reused until the parent
has waited on it, and the async event loop's `process.wait()` in
`run_container()` always completes before `clear()` is called.

**Semantic change from current code**: The current `stop()` is blocking — it
waits for the process to exit before returning. The async version is
non-blocking — it sends SIGTERM and returns immediately, with a background timer
for SIGKILL. This is acceptable because:

- The gateway's `_stop_execution()` returns a boolean indicating whether a stop
  was initiated, not whether the process has exited.
- The sandbox CLI's signal handler benefits from returning quickly (the event
  loop's `process.wait()` handles the actual cleanup).
- The async `run_container()` observes the kill through stream readers hitting
  EOF and `process.wait()` completing.

`ProcessLookupError` is caught because the process may have already exited
between the PID read and the signal send.

## Task API Changes

### AgentTask

```python
class AgentTask:
    async def execute(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        model: str = "sonnet",
        effort: str | None = None,
        on_event: EventCallback | Callable[[StreamEvent], None] | None = None,
        on_stderr_line: Callable[[str], None] | None = None,
        on_network_line: Callable[[str], None] | None = None,
    ) -> ExecutionResult: ...
```

Changes:

- `execute()` becomes `async def`.
- New `on_stderr_line` callback for real-time stderr streaming. When `None`,
  stderr is silently captured into `ExecutionResult.stderr` (same as before).
- New `on_network_line` callback for network log tailing during execution (see
  [Network Log Tailing](#network-log-tailing)). When `None` or when
  `self._network_log` is `None` (no network sandbox configured), no tailing
  occurs.

The internal `on_stdout_line` closure (which parses stream-json and appends to
the event log) is unchanged in behavior.

### CommandTask

```python
class CommandTask:
    async def execute(
        self,
        command: list[str],
        *,
        on_output: Callable[[str], None] | None = None,
        on_stderr: Callable[[str], None] | None = None,
        on_network_line: Callable[[str], None] | None = None,
    ) -> CommandResult: ...
```

Changes:

- `execute()` becomes `async def`.
- New `on_stderr` callback replaces `stderr_passthrough` (see
  [Behavioral Changes](#behavioral-changes)).
- New `on_network_line` callback for network log tailing.

### Behavioral Changes

The async rewrite introduces these behavioral changes relative to the current
synchronous implementation:

1. **CommandTask no longer writes to `sys.stdout` implicitly.** The current
   `CommandTask.execute()` unconditionally writes every stdout line to
   `sys.stdout` in addition to invoking `on_output`. After the change, stdout is
   only delivered via the `on_output` callback. Callers that want terminal
   output must provide `on_output=lambda line: sys.stdout.write(line)`. The
   sandbox CLI does this explicitly.

2. **CommandTask stderr is captured instead of passed through.** The current
   code uses `stderr_passthrough=True`, which passes stderr to the parent
   process at the OS file descriptor level (character-by-character, real-time,
   no buffering). After the change, stderr is captured as a pipe and delivered
   line-by-line via callback. This introduces line buffering — partial lines
   (e.g., progress indicators) are held until a newline or stream close. The
   `CommandResult.stderr` field is now populated with actual content (previously
   always empty for CommandTask).

3. **`_RawResult` docstring updated.** The `stderr` field description changes
   from "empty when `stderr_passthrough` is True" to "raw stderr text."

### Network Log Tailing

When `on_network_line` is provided and `self._network_log` is not `None`, the
task starts an async tailing loop alongside the container execution:

```python
async def _tail_network_log(
    network_log: NetworkLog,
    callback: Callable[[str], None],
    stop_event: asyncio.Event,
    poll_interval: float = 0.5,
) -> None:
    offset = 0
    while not stop_event.is_set():
        lines, offset = network_log.tail(offset)
        for line in lines:
            callback(line)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=poll_interval)
        except TimeoutError:
            pass
    # Final drain after stop
    lines, _ = network_log.tail(offset)
    for line in lines:
        callback(line)
```

Inside `execute()`, the tailing task runs concurrently with the container:

```python
stop_tailing = asyncio.Event()
tail_task = asyncio.create_task(
    _tail_network_log(self._network_log, on_network_line, stop_tailing)
)
try:
    raw = await run_container(
        # ... container arguments ...
    )
finally:
    stop_tailing.set()
    try:
        await tail_task
    except BaseException:
        logger.warning("Network log tailing failed", exc_info=True)
```

Exceptions from `_tail_network_log` are caught with `except BaseException` and
logged in the `finally` block. `BaseException` (not `Exception`) is necessary
because `asyncio.CancelledError` is a `BaseException` in Python 3.9+, and the
tail task may be cancelled if the parent is cancelled by timeout at a higher
level. Without this, a propagating `CancelledError` would mask the container
execution result.

The `NetworkLog.tail()` method itself remains synchronous — it's a fast file
seek+read that doesn't benefit from async. The async wrapper handles the polling
interval.

When `on_network_line` is provided but `self._network_log is None` (network
sandbox not configured), tailing is silently skipped.

### Stop Semantics

`stop()` remains synchronous and thread-safe, as described in
[Process Lifecycle](#process-lifecycle). The async `execute()` observes the
process termination through the stream readers hitting EOF and `process.wait()`
completing.

The gateway's `_stop_execution()` in `gateway.py` (line 564) calls `task.stop()`
from the main thread while `execute()` runs in a worker thread's event loop.
This pattern is unchanged.

## Interactive Mode

Interactive mode (bidirectional IO for running terminal programs like Claude
Code in interactive mode) is **out of scope for this spec** but is a key
motivator for the async rewrite. The async architecture enables it as a future
addition.

### Design Direction

Interactive mode would add a `CommandTask.execute_interactive()` method that:

- Passes `-it` flags to podman for container-side TTY allocation.
- Uses a host-side PTY (`pty.openpty()`) connected to the podman process to
  relay terminal IO between the caller and the container's TTY.
- Accepts raw `bytes` callbacks (chunk-based, not line-based) since terminal
  output includes control sequences.
- Keeps stdin open for bidirectional communication.
- Supports terminal resize via `ioctl(TIOCSWINSZ)` on the PTY master.

This requires a separate spec to address:

- PTY plumbing between host, podman, and container (three layers of terminal
  allocation).
- `asyncio` integration with PTY file descriptors via `loop.connect_read_pipe()`
  / `loop.connect_write_pipe()` protocols.
- Interaction with the network log tailer and process tracker.
- Error handling and timeout semantics for long-running interactive sessions.
- Platform constraints (`pty` module is Unix-only; the project runs on Linux).

The async `run_container()` and the event loop architecture introduced by this
spec provide the necessary foundation. No pipe-mode code paths need to change
when interactive mode is added later.

## Caller Migration

**No backwards-compatibility layers.** All consumers switch to the async API
directly. There are no sync wrappers, re-exports, or deprecation shims.

### Gateway

The gateway runs message processing in a `ThreadPoolExecutor`, one thread per
conversation. Each thread currently calls `task.execute()` synchronously.

After migration, each thread calls `asyncio.run()`:

```python
# message_processing.py
result = asyncio.run(
    task.execute(
        prompt,
        session_id=session_id,
        model=model,
        effort=effort,
        on_event=todo_callback,
    )
)
```

This works because each worker thread has no existing event loop.
`asyncio.run()` creates a fresh loop, runs the coroutine, and tears it down.

**Child process watchers**: On Python 3.12+/Linux, asyncio uses
`PidfdChildWatcher` (kernel 5.3+) which is per-loop and thread-safe. Multiple
concurrent worker threads each running `asyncio.run()` with their own subprocess
will not interfere with each other. The project's deployment target (Ubuntu
22.04+, Debian 12+) satisfies the kernel requirement.

Both `task.execute()` call sites in `_process_message()` are wrapped (the
initial execution at line 543 and the recovery retry at line 601).

The `register_active_task` / `unregister_active_task` and `stop()` patterns
remain unchanged — `stop()` is still synchronous and thread-safe.

### Sandbox CLI

The CLI entry point wraps in `asyncio.run()`:

```python
# sandbox_cli.py
async def _execute_async(args, config) -> int:
    # ... setup sandbox, image, task ...
    result = await task.execute(
        args.command,
        on_output=lambda line: sys.stdout.write(line),
        on_stderr=lambda line: sys.stderr.write(line),
    )
    return _map_exit_code(result)


def _execute(args, config) -> int:
    return asyncio.run(_execute_async(args, config))
```

Signal handling continues to work — `signal.signal()` is set up before
`asyncio.run()`, and the handler calls `task.stop()` which is synchronous.

### Tests

All tests that call `execute()` must use `async` test functions. Add
`pytest-asyncio` as a dev dependency in `pyproject.toml`.

**Async test functions:**

```python
@pytest.mark.asyncio
async def test_agent_task_execute(mock_run_container):
    # ... create AgentTask with test parameters ...
    result = await task.execute("test prompt")
    assert result.outcome == Outcome.SUCCESS
```

**Async mock fixtures:**

The existing `create_mock_popen` pattern in `tests/sandbox/conftest.py` is
replaced with an async mock of `run_container`:

```python
@pytest.fixture
def mock_run_container(monkeypatch):
    async def fake_run_container(**kwargs):
        # Invoke callbacks to simulate streaming
        if kwargs.get("on_stdout_line"):
            for line in _MOCK_STDOUT.splitlines(keepends=True):
                kwargs["on_stdout_line"](line)
        if kwargs.get("on_stderr_line"):
            for line in _MOCK_STDERR.splitlines(keepends=True):
                kwargs["on_stderr_line"](line)
        return _RawResult(
            stdout=_MOCK_STDOUT,
            stderr=_MOCK_STDERR,
            exit_code=0,
            duration_ms=100,
            timed_out=False,
        )

    monkeypatch.setattr("airut.sandbox.task.run_container", fake_run_container)
```

**Testing specific behaviors:**

| Behavior                  | Test approach                                                                       |
| ------------------------- | ----------------------------------------------------------------------------------- |
| Timeout handling          | Mock `run_container` with `asyncio.sleep()` + assert `timed_out`                    |
| `_tail_network_log`       | Write to a temp file, call with short poll interval, assert callback receives lines |
| `_ProcessTracker.stop()`  | Start a real subprocess, call `stop()` from a thread, assert exit                   |
| `on_stderr_line` callback | Mock `run_container` that invokes callback, assert lines received                   |
| Network log + no sandbox  | Pass `on_network_line` when `network_log is None`, assert no crash                  |

Verify compatibility of `pytest-asyncio` with existing plugins (`pytest-socket`,
`pytest-xdist`) before finalizing the dependency addition.

## Migration Strategy

The migration is a single atomic change — all files updated in one PR. The
change is mechanical:

1. **`_run_container.py`**: Rewrite `run_container()` as async. Remove
   `stderr_passthrough`. Add `on_stderr_line`. Rewrite `_ProcessTracker` to use
   raw PID + `os.kill()`. Update `_RawResult` docstring.
2. **`task.py`**: Make `execute()` async on both task types. Add
   `on_stderr_line` / `on_stderr` and `on_network_line` callbacks. Remove
   implicit `sys.stdout.write` from `CommandTask`. Add `_tail_network_log()`.
3. **`sandbox_cli.py`**: Add `async` wrapper, explicit stdout/stderr callbacks.
4. **`message_processing.py`**: Wrap both `task.execute()` call sites with
   `asyncio.run()`.
5. **`tests/sandbox/`**: Convert all test functions to async, rewrite mock
   fixtures for async `run_container`.
6. **`pyproject.toml`**: Add `pytest-asyncio` dev dependency.
7. **`spec/sandbox.md`**: Update execution flow descriptions to reflect async
   model.

No intermediate compatibility state. The old sync API ceases to exist.
