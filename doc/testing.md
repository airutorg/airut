# Testing

Airut enforces **100% unit test coverage** in CI — every line in `airut/` and
`scripts/` must be exercised by tests, with no exceptions or skips. Integration
tests verify end-to-end workflows on top. Config migrations are independently
tested for correctness and safety.

## Unit Tests

94 test files under `tests/` cover all library and script code. CI enforces 100%
line coverage via `pytest-cov --cov-fail-under=100` — any uncovered line fails
the build.

Key properties:

- **No skips** — `pytest.skip()` is prohibited; external dependencies are mocked
- **No environment dependence** — tests behave identically locally and in CI
- **Network isolation** — `pytest-socket` blocks all network calls by default;
  tests that need sockets must opt in explicitly
- **Parallel execution** — `pytest-xdist` runs tests across all available cores
- **Warnings as errors** — all Python warnings are treated as test failures

## Integration Tests

38 test files under `tests/integration/` exercise full end-to-end workflows.
These run separately from unit tests via
`uv run scripts/ci.py --workflow integration`.

The integration suite uses purpose-built test servers that simulate external
dependencies without requiring real infrastructure:

- **Email server** — fake IMAP/SMTP server for email channel flows
- **Slack server** — fake Slack Web API and Socket Mode for Slack channel flows
- **Container runtime** — mock Podman for container lifecycle
- **Claude API** — mock Claude responses for agent execution

Tests cover conversation lifecycle, config reload, message queuing, session
recovery, multi-repo handling, dashboard APIs, and resource limits.

## Config Migrations

The server config carries a `config_version` integer. When the schema evolves,
numbered migration functions transform configs forward automatically. Each
migration is:

- **Idempotent** — applying twice produces the same result
- **Tag-preserving** — `!env` and `!var` references survive round-trip
- **Atomic** — file writes use temp-then-rename to prevent corruption
- **Security-aware** — security-affecting changes raise errors instead of
  silently auto-transforming

92 unit tests and 12 integration tests cover the migration chain, including edge
cases (missing keys, malformed sections, variable name collisions) and
double-migration idempotency.

## CI Pipeline

All checks run via `scripts/ci.py`, which is the single source of truth:

| Check              | Tool         | Requirement             |
| ------------------ | ------------ | ----------------------- |
| Formatting         | ruff         | Auto-fixed with `--fix` |
| Linting            | ruff         | No warnings             |
| Type checking      | ty           | No errors               |
| Unit test coverage | pytest-cov   | 100% line coverage      |
| License compliance | pip-licenses | Approved licenses only  |
| Markdown           | mdformat     | Consistent formatting   |

Integration tests run as a separate workflow. Both must pass before merge.
