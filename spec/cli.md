# CLI

The `airut` command-line interface for installation, configuration, service
management, and self-update. Installed as a console script entry point via
`uv tool install airut`.

## Overview

A single `airut` binary with subcommands covering the full operator lifecycle:
initial setup, readiness verification, service management, and updates. The CLI
is deliberately minimal — no argument parser library, no configuration files of
its own. Each subcommand is a function that receives `argv` and returns an exit
code.

**Key principle**: The CLI is the operator's interface. It handles
infrastructure concerns (systemd, uv, version checks) so the gateway can focus
on email processing.

## Entry Point

```
[project.scripts]
airut = "airut.cli:cli"
```

The `cli()` function in `airut/cli.py` dispatches to subcommand handlers. When
invoked with no arguments or `--help`, it prints version information and usage.
Unknown commands exit with code 2.

Per-subcommand help is available via `airut <command> --help`, which prints
usage and options without executing the command.

### Config File Selection

Every subcommand that uses the server config (`init`, `check`, `migrate`,
`update`, `run-gateway`) selects the file the same way, in order of precedence:

1. `--config PATH` (or `--config=PATH`)
2. `$AIRUT_CONFIG`
3. `~/.config/airut/airut.yaml` (`$XDG_CONFIG_HOME/airut/airut.yaml`)

A `--config` without a value, or any unrecognized argument, is a usage error
(exit code 2); `install-service` and `uninstall-service` take no arguments. The
`.env` file is read from the selected config file's directory. Declarative
setups (e.g. a Nix module) set `AIRUT_CONFIG` in the service environment and in
a wrapper for interactive use, so `airut check` in an admin shell checks the
same file the gateway runs with.

## Subcommands

### init

```
airut init [--config PATH]
```

Create a stub server config at the selected path (see
[Config File Selection](#config-file-selection)).

This step is **optional**. If no config file exists, `airut run-gateway` starts
with built-in defaults (dashboard enabled, no repos). Users can configure repos
later via the dashboard config editor.

**Behavior:**

- If the config already exists, prints its path and returns 0 (idempotent)
- Creates parent directories (e.g. `~/.config/airut/`) if needed
- Writes a commented YAML template with placeholder values
- Prints links to deployment and repo-onboarding guides on GitHub

**Stub template:** Contains commented-out `execution`, `dashboard`, and
`network` sections, plus a minimal `repos:` block with placeholder email, git,
and secrets values. The template header links to the
[documented example](https://github.com/airutorg/airut/blob/main/config/airut.example.yaml)
for all available options.

### check

```
airut check [--config PATH]
```

Verify configuration, system dependencies, and service status. Exit code 0 if
all critical checks pass, 1 otherwise.

**Sections:**

| Section       | What it checks                                           | Affects exit code |
| ------------- | -------------------------------------------------------- | ----------------- |
| Version       | Installed version, upstream update availability          | No                |
| Configuration | Config file parses without error (missing = defaults)    | Yes               |
| Config schema | Whether config_version matches current (migration hint)  | No                |
| Dependencies  | git (>= 2.25), podman (>= 4.0) installed and version met | Yes               |
| Service       | Unit file exists, service running, version mismatch      | No                |

**Version checking** uses `check_upstream_version()` from `airut/version.py`.
For PyPI installs, it queries the PyPI JSON API. For VCS (GitHub) installs, it
queries the GitHub API for the latest commit. Editable and local-dir installs
skip the check. See `airut/version.py` for the `InstallSource` detection via PEP
610 `direct_url.json`.

**Dependency checking** uses `shutil.which()` to locate binaries and runs their
version commands with a 10-second timeout. Version strings are parsed tolerantly
— pre-release suffixes like `-rc1` are stripped. Minimum versions are defined in
`_MIN_VERSIONS`:

- git: 2.25
- podman: 4.0 (netavark backend required for network sandbox)

**Config schema** status is informational only:

- Reads `config_version` from the YAML file without full validation
- Reports "up to date (vN)" when the file version matches
  `CURRENT_CONFIG_VERSION`
- Reports "migration pending (vN → vM)" when the file version is older, with a
  hint to run `airut migrate` or save from the dashboard
- Skipped when no config file exists or the file is unparseable

**Service status** is informational only:

- Checks if `~/.config/systemd/user/airut.service` exists
- Queries `systemctl --user is-active airut.service`
- When running and config is available, fetches `/api/version` from the local
  dashboard to detect version mismatch between running and installed binaries

### migrate

```
airut migrate [--config PATH]
```

Apply pending config schema migrations to the config file.

**Behavior:**

- If no config file exists, prints an error and suggests `airut init` (exit 1)
- Reads the YAML file, applies all pending migrations from `config_version` to
  `CURRENT_CONFIG_VERSION`, and writes back atomically
- Preserves `!env`, `!var` and `!file` tags during the round-trip; tag-free
  spellings (and a JSON file) are written back as tagged YAML
- If already up to date, prints "already up to date (vN)" and returns 0
- On success, prints "Migrated config schema: vN → vM" and returns 0
- On error (parse failure, invalid version), prints the error and returns 1
- A read-only config (a symlink, or a file or directory that is not writable;
  see [config-editor.md](config-editor.md#read-only-mode)) is left untouched and
  reported as an error: migrate it where it is managed (`check` says so instead
  of suggesting `airut migrate`)

**When to use:** Run `airut migrate` after updating airut to a version with a
new config schema. Alternatively, saving from the dashboard config editor also
applies pending migrations automatically.

**Implementation:** Delegates to `migrate_config_file()` in
`airut/config/migration.py`, which uses `YamlConfigSource` for atomic load/save
with tag preservation.

### update

```
airut update [--wait] [--force] [--config PATH]
```

Update airut to the latest version via `uv tool upgrade airut`.

**Workflow:**

1. **Pre-flight** — If the service is running (and neither `--force` nor
   `--wait` is set), query `/api/health` on the local dashboard for active task
   counts. Block if tasks are in flight.
2. **Upgrade** — Run `uv tool upgrade airut` (120-second timeout). If the output
   contains "Nothing to upgrade" (case-insensitive), print "Already up to date."
   and return 0 without touching the service.
3. **Stop service** — When the binary was actually updated and the service was
   previously installed, stop and uninstall the service immediately. This
   prevents a stale process from running old code while the readiness check and
   reinstall proceed. From this point on, the service is down regardless of
   whether subsequent steps succeed or fail.
4. **Readiness check** — Run `airut check --config <selected path>` via
   subprocess (30-second timeout) using the updated binary. If the check fails
   (non-zero exit), print the check output and instruct the user to fix the
   issues and run `airut install-service` to start the service. The service is
   already stopped at this point, so there is no stale process running old code.
5. **Reinstall service** — Only when the readiness check passes and the service
   was previously installed, reinstall using the new binary
   (`airut install-service` via subprocess, 30-second timeout).

**Options:**

| Flag            | Behavior                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------- |
| `--wait`        | Poll every 10 seconds until all tasks complete                                                                      |
| `--force`       | Skip the in-flight task check entirely                                                                              |
| `--config PATH` | Config used to find the dashboard and for the readiness check (see [Config File Selection](#config-file-selection)) |

**Task blocking** prevents data loss during updates. The health endpoint returns
task counts by status (e.g.,
`{"tasks": {"queued": 0, "authenticating": 0, "pending": 0, "executing": 1, "completed": 5}}`).
When `--wait` is specified and tasks are active, the command polls every 10
seconds until idle or the service becomes unreachable.

### install-service

```
airut install-service
```

Install and start the airut systemd user service.

**Preconditions:**

- loginctl linger must be enabled for the current user (checked via
  `/var/lib/systemd/linger/{username}` file existence). Without linger, user
  services stop when the user logs out.

The generated unit runs the gateway with the default config selection. For a
config file elsewhere, add a drop-in (`systemctl --user edit airut`) with
`Environment=AIRUT_CONFIG=/path/to/airut.yaml`; drop-ins survive the unit
reinstall that `airut update` performs. The shell running `airut update` needs
the same `AIRUT_CONFIG`, or its readiness check inspects the default file.

**Workflow:**

1. Check linger is enabled
2. Create `~/.config/systemd/user/` directory
3. Locate the `airut` binary (`shutil.which` with `~/.local/bin/airut` fallback)
4. Generate and write the unit file
5. `systemctl --user daemon-reload`
6. Enable and start the service

**Generated unit file** (`airut.service`):

```ini
[Unit]
Description=Airut Email Gateway
After=network.target

[Service]
ExecStart={airut_path} run-gateway --resilient
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec=300
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

The service runs `airut run-gateway --resilient`, which delegates to
`airut.gateway.service:main()`. `Restart=always` with 10-second backoff ensures
the gateway recovers from transient failures.

`KillMode=mixed` sends the stop signal to the gateway alone. With the default
(`control-group`), systemd also signals the `podman run` clients, which forward
it to the task containers and end running tasks before the gateway can drain
them (see
[Graceful shutdown](gateway-architecture.md#thread-pool-architecture)).
`TimeoutStopSec=300` leaves room for the drain (`execution.shutdown_timeout`,
default 60 s) plus listener and sandbox teardown; a shutdown timeout near or
above it lets systemd kill the gateway mid-drain, skipping the teardown.

**Implementation:** `airut/install_services.py` contains the service management
logic. The CLI command (`cmd_install_service`) sets up logging and delegates to
`install_services()`.

### uninstall-service

```
airut uninstall-service
```

Stop and remove the airut systemd user service.

**Workflow:**

1. Stop the service (errors ignored — may already be stopped)
2. Disable the service (errors ignored — may already be disabled)
3. Remove the unit file
4. `systemctl --user daemon-reload`

### run-gateway

```
airut run-gateway [--config PATH] [--read-only-config] [--resilient] [--debug]
```

Start the email gateway service. Normally invoked by systemd, not run directly.

**Options:**

| Flag                 | Behavior                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------- |
| `--config PATH`      | Config file (see [Config File Selection](#config-file-selection))                                   |
| `--read-only-config` | Dashboard config editor is a read-only viewer ([config-editor.md](config-editor.md#read-only-mode)) |
| `--resilient`        | Stay alive on boot failure, show error on dashboard                                                 |
| `--debug`            | Enable debug logging                                                                                |

Delegates immediately to `airut.gateway.service:main()` with the remaining
arguments. See [gateway-architecture.md](gateway-architecture.md) for the
gateway design.

## Architecture

### Module Structure

```
airut/
├── cli.py                # CLI entry point, subcommand dispatch, check/update
├── install_services.py   # Systemd user service management
└── version.py            # Version detection (embedded + git fallback)

scripts/
└── airut.py              # Wrapper for uv run (adds project root to sys.path)
```

### Dispatch

Subcommands are registered in two structures:

- `_SUBCOMMANDS`: frozenset of valid command names (for input validation)
- `_DISPATCH`: dict mapping command names to handler function names

The `cli()` function uses `getattr()` to look up handlers by name, which allows
tests to mock individual commands without patching the dispatch table.

### Terminal Output

The CLI uses ANSI color codes for readability, managed by the `_Style` class.
Color is enabled when:

- stdout is a TTY
- `NO_COLOR` environment variable is not set
- `TERM` is not `dumb`

### Exit Codes

| Code | Meaning                                                        |
| ---- | -------------------------------------------------------------- |
| 0    | Success (or `check` with all checks passing)                   |
| 1    | Error (check failure, update failure, service install failure) |
| 2    | Unknown command or invalid arguments                           |

## Configuration Paths

| Path                                    | Purpose                           |
| --------------------------------------- | --------------------------------- |
| `~/.config/airut/airut.yaml`            | Server config (created by `init`) |
| `~/.config/airut/.env`                  | Environment variables for secrets |
| `~/.config/systemd/user/`               | Systemd user unit files           |
| `~/.local/bin/airut`                    | Default binary location (uv tool) |
| `~/.local/state/airut/`                 | State directory (XDG state)       |
| `~/.local/state/airut/<repo_id>/`       | Per-repo runtime state            |
| `~/.local/state/airut/claude-binaries/` | Cached Claude Code binaries       |

The config file and its `.env` follow
[Config File Selection](#config-file-selection). The state directory is, in
order of precedence: `$AIRUT_STATE_DIR`; systemd's `$STATE_DIRECTORY` (set for
units with `StateDirectory=`, first entry if several); the XDG default above.
Path variables expand `~` and are made absolute. The network sandbox CA stays in
`~/.airut-mitmproxy/` regardless.

See [repo-config.md](repo-config.md) for the per-repo schema in server config.

## Design Decisions

### Why No Argument Parser Library?

The CLI has six subcommands with minimal options (`--wait`, `--force`,
`--resilient`, `--debug`). A library like argparse would add complexity without
proportional benefit. Manual `argv` parsing keeps the code simple and avoids
import overhead for commands like `run-gateway` that delegate immediately.

### Why Self-Update via uv?

Airut is distributed on PyPI and installed via `uv tool install`. Using
`uv tool upgrade` for updates leverages the existing package manager, avoids
reimplementing version resolution, and ensures the binary and its dependencies
stay consistent.

### Why Uninstall-Then-Reinstall for Service Updates?

The systemd unit file contains the absolute path to the `airut` binary
(`ExecStart={airut_path} run-gateway --resilient`). After `uv tool upgrade`, the
binary path is unchanged but its contents are new. The service must be stopped
and restarted to pick up the new binary. The uninstall-reinstall cycle ensures a
clean state: the unit file is regenerated (in case the template changed),
systemd reloads, and the service starts fresh.

### Why Skip Service Restart When Already Up to Date?

`uv tool upgrade` outputs "Nothing to upgrade" when the installed version
matches the latest. Detecting this avoids an unnecessary service stop/start
cycle, which would briefly interrupt email processing for no benefit.

### Why Block on In-Flight Tasks?

Stopping the gateway gives running tasks only `execution.shutdown_timeout`
(default 60 s) to finish before their Claude Code containers are killed,
potentially losing work in progress. The pre-flight check queries the dashboard
health endpoint for task counts and blocks unless the operator explicitly opts
in with `--force` or `--wait`.
