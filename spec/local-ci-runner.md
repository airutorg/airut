# Local CI Runner

A Python script that runs the same checks as GitHub Actions CI locally,
providing fast feedback before pushing changes.

## Motivation

The current workflow requires running 10+ commands manually before creating a
PR. CLAUDE.md documents these steps but:

1. Running them one-by-one is slow and context-heavy for agents
2. Reproducing the exact CI environment is unnecessary for local validation
3. Verbose output clutters the context when checks pass

The local CI runner provides a single command that validates changes match CI
expectations, showing minimal output on success and focused diagnostics on
failure.

## Design

### Interface

```bash
# Run all checks
uv run scripts/ci.py

# Run specific workflow
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

### Workflow Mapping

The script derives steps from workflow files but filters for local relevance:

#### From `code.yml`

| Step            | Command                                          | Include |
| --------------- | ------------------------------------------------ | ------- |
| Lint            | `uv run ruff check .`                            | Yes     |
| Format check    | `uv run ruff format --check .`                   | Yes     |
| Type check      | `uv run ty check .`                              | Yes     |
| Markdown format | `uv run mdformat --check .`                      | Yes     |
| Test coverage   | `uv run pytest --cov=airut --cov-fail-under=100` | Yes     |
| Worktree clean  | `git status --porcelain`                         | Yes     |

#### From `security.yml`

| Step               | Command                                   | Include |
| ------------------ | ----------------------------------------- | ------- |
| License check      | `uv run python scripts/check_licenses.py` | Yes     |
| Vulnerability scan | `uv run uv-secure uv.lock`                | Yes     |

The license check resolves the transitive closure of runtime dependencies (via
`uv tree --no-dev`) and passes only those packages to `pip-licenses`. This
ensures the license audit covers exactly what ships in a production install,
without being affected by dev tooling licenses.

#### From `e2e.yml`

| Step                    | Command                                                   | Include |
| ----------------------- | --------------------------------------------------------- | ------- |
| E2E email gateway tests | `pytest tests/integration/ -v --allow-hosts=127.0.0.1...` | Yes     |

E2E email gateway tests run with a mock container tool (configured automatically
by test fixtures) and require only localhost network access for the test email
server.

### `--fix` Mode

When `--fix` is passed, auto-fixable steps run their fix command instead of
check command:

| Check                 | Fix                  |
| --------------------- | -------------------- |
| `ruff check .`        | `ruff check . --fix` |
| `ruff format --check` | `ruff format .`      |
| `mdformat --check .`  | `mdformat .`         |

After fixes, the script continues to run remaining checks.

### Drift Detection

Steps are hardcoded in `ci.py` rather than parsed from workflow YAML at runtime.
To ensure they stay in sync, the test suite includes drift detection tests that:

1. Parse the workflow YAML files to extract step names
2. Compare against the steps defined in `ci.py`
3. Fail if there are steps in workflows not accounted for in `ci.py`

This provides single-source-of-truth benefits without runtime YAML parsing
complexity. When workflows change, the test fails with a clear message about
what needs updating.
