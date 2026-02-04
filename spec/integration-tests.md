# Integration Tests

End-to-end integration tests for the Airut Email Gateway Service. Exercises the
complete email-to-response flow with minimal mocking.

## Architecture

### Test Email Server

In-process SMTP/IMAP server (`tests/integration/gateway/email_server.py`) using
`aiosmtpd` for SMTP and a minimal custom IMAP implementation. Thread-safe
message store shared between protocols.

### Mock Container Tool

Tests substitute `CONTAINER_COMMAND` with a mock that simulates container
behavior (`mock_podman.py` → `mock_claude.py`). Response strategies: `echo`,
`file_ops`, `scripted`, `error`, `slow`.

## CI Integration

Tests run as part of E2E workflow (`.github/workflows/e2e.yml`). No environment
variables needed - `conftest.py` configures `CONTAINER_COMMAND` at module load.

```bash
# Run via local CI runner
uv run scripts/ci.py --workflow e2e

# Run directly
uv run pytest tests/integration/ -v --allow-hosts=127.0.0.1,localhost
```

## Test Coverage

Tests live in `tests/integration/gateway/` and cover:

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
