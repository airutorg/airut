# Integration Tests

Integration tests for the Airut gateway, sandbox, and channel implementations.

## Architecture

### Test Servers

**Email** — In-process SMTP/IMAP server
(`tests/integration/gateway/email_server.py`) using `aiosmtpd` for SMTP and a
minimal custom IMAP implementation. Thread-safe message store shared between
protocols.

**Slack** — Mock Socket Mode server
(`tests/integration/gateway/slack_server.py`) simulating Slack's WebSocket and
Web API endpoints.

### Mock Container Tool

Tests substitute `CONTAINER_COMMAND` with a mock that simulates container
behavior (`mock_podman.py` → `mock_claude.py`). Response strategies: `echo`,
`file_ops`, `scripted`, `error`, `slow`.

## CI Integration

Tests run as part of the CI workflow (`.github/workflows/ci.yml`) via
`scripts/ci.py`. No environment variables needed - `conftest.py` configures
`CONTAINER_COMMAND` at module load.

```bash
# Run via local CI runner
uv run scripts/ci.py --workflow integration

# Run directly
uv run pytest tests/integration/ -v --allow-hosts=127.0.0.1,localhost,claude.ai,storage.googleapis.com
```

## Test Coverage

### Gateway (`tests/integration/gateway/`)

Gateway tests cover:

- **Conversation flow**: Creation, threading headers, dashboard tracking
- **Resumption**: Session persistence, --resume flag passing
- **Attachments**: Single, multiple, binary content preservation
- **Authorization**: Sender whitelist, DMARC/SPF verification
- **Errors**: Crash handling, invalid JSON, timeout
- **Concurrency**: Parallel execution, duplicate rejection
- **Git mirror updates**: Mirror creation, updates at service start and before
  each new conversation, ensuring conversations get latest code
- **Outbox**: Reply file attachments from outbox/ directory
- **Streaming and stop**: Streaming output handling and task cancellation

### Sandbox (`tests/integration/sandbox/`)

- **Install script compatibility**: Validates that the upstream
  `claude.ai/install.sh` structure matches `ClaudeBinaryCache` assumptions (GCS
  bucket URL, manifest format, platform strings, binary URL pattern). Requires
  external network access to `claude.ai` and `storage.googleapis.com`.
