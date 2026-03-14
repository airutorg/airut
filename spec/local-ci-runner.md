# CI Runner

`scripts/ci.py` is the single source of truth for all CI checks. It is called
directly by `.github/workflows/ci.yml` and can also be run locally for fast
feedback before pushing changes.

## Motivation

The current workflow requires running 10+ commands manually before creating a
PR. CLAUDE.md documents these steps but:

1. Running them one-by-one is slow and context-heavy for agents
2. Reproducing the exact CI environment is unnecessary for local validation
3. Verbose output clutters the context when checks pass

The CI runner provides a single command that validates changes, showing minimal
output on success and focused diagnostics on failure.

## Design

### Interface

```bash
# Run all checks
uv run scripts/ci.py

# Run specific step group
uv run scripts/ci.py --workflow code

# Show output even on success (for debugging)
uv run scripts/ci.py --verbose

# Fix auto-fixable issues before checking
uv run scripts/ci.py --fix
```

### Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed
- `2` - Script error (invalid arguments, missing dependencies)

### Output Behavior

**On success**: Single summary line per step (e.g., `✓ Lint`)

**On failure**: Last N lines (default 50) of failing step's output, plus summary
of what failed

Example failure output:

```
✓ Lint
✓ Format check
✗ Type check

Type check failed:
Command: uv run ty check .
────────────────────────────────────────────────────────
airut/foo.py:42:1 - error: Argument of type "str" cannot be assigned
airut/bar.py:17:5 - error: Cannot access member "xyz" for type "None"
────────────────────────────────────────────────────────
2 errors found

Summary: 1 of 5 checks failed
```

The full command is shown on failure so agents can easily re-run or iterate on
that specific step.

### Step Groups

Steps are organized into groups for selective runs via `--workflow <group>`. All
steps run in a single GitHub Actions job; the grouping exists only for local
convenience.

#### `code` group

| Step            | Command                                          |
| --------------- | ------------------------------------------------ |
| Lint            | `uv run ruff check .`                            |
| Format check    | `uv run ruff format --check .`                   |
| Type check      | `uv run ty check .`                              |
| Markdown format | `uv run python scripts/check_markdown.py`        |
| Test coverage   | `uv run pytest --cov=airut --cov-fail-under=100` |
| Worktree clean  | `git status --porcelain`                         |

#### `security` group

| Step                               | Command                                             |
| ---------------------------------- | --------------------------------------------------- |
| License check                      | `uv run python scripts/check_licenses.py`           |
| Vulnerability scan                 | `uv run uv-secure uv.lock`                          |
| Proxy vulnerability scan           | `uv run uv-secure airut/_bundled/proxy/uv.lock ...` |
| Proxy requirements.txt drift check | `uv export ... \| diff - ...`                       |

The license check resolves the transitive closure of runtime dependencies (via
`uv tree --no-dev`) and passes only those packages to `pip-licenses`. This
ensures the license audit covers exactly what ships in a production install,
without being affected by dev tooling licenses.

#### `integration` group

| Step              | Command                                                   |
| ----------------- | --------------------------------------------------------- |
| Integration tests | `pytest tests/integration/ -v --allow-hosts=127.0.0.1...` |

Integration tests run with a mock container tool (configured automatically by
test fixtures) and require only localhost network access for the test servers.

### `--fix` Mode

When `--fix` is passed, auto-fixable steps run their fix command instead of
check command:

| Check                 | Fix                  |
| --------------------- | -------------------- |
| `ruff check .`        | `ruff check . --fix` |
| `ruff format --check` | `ruff format .`      |
| `mdformat --check .`  | `mdformat .`         |

After fixes, the script continues to run remaining checks.

### GitHub Actions Integration

The consolidated workflow (`.github/workflows/ci.yml`) calls `ci.py` directly:

```yaml
- name: CI checks
  run: uv run scripts/ci.py --verbose --timeout 0
```

`--timeout 0` disables `ci.py`'s overall timeout since GitHub Actions provides
its own `timeout-minutes`. `--verbose` shows full output in CI logs.

This makes `ci.py` the single source of truth — local and GitHub CI run
identical checks. There are no separate workflow files to drift against.
