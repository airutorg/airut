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
airut = "lib.airut:cli"
```

The `cli()` function in `lib/airut.py` dispatches to subcommand handlers. When
invoked with no arguments or `--help`, it prints version information and usage.
Unknown commands exit with code 2.

Per-subcommand help is available via `airut <command> --help`, which prints
usage and options without executing the command.

## Subcommands

### init

```
airut init
```

Create a stub server config at `~/.config/airut/airut.yaml`.

**Behavior:**

- If the config already exists, prints its path and returns 0 (idempotent)
- Creates parent directories (`~/.config/airut/`) if needed
- Writes a commented YAML template with placeholder values
- Prints links to deployment and repo-onboarding guides on GitHub

**Config path:** Determined by `get_config_path()` in `lib/gateway/config.py`,
which returns `~/.config/airut/airut.yaml`.

**Stub template:** Contains commented-out `execution`, `dashboard`, and
`container_command` sections, plus a minimal `repos:` block with placeholder
email, git, and secrets values. The template header links to the
[documented example](https://github.com/airutorg/airut/blob/main/config/airut.example.yaml)
for all available options.

### check

```
airut check
```

Verify configuration, system dependencies, and service status. Exit code 0 if
all critical checks pass, 1 otherwise.

**Sections:**

| Section       | What it checks                                           | Affects exit code |
| ------------- | -------------------------------------------------------- | ----------------- |
| Version       | Installed version, upstream update availability          | No                |
| Configuration | Config file exists, parses without error, repo count     | Yes               |
| Dependencies  | git (>= 2.25), podman (>= 4.0) installed and version met | Yes               |
| Service       | Unit file exists, service running, version mismatch      | No                |

**Version checking** uses `check_upstream_version()` from `lib/git_version.py`.
For PyPI installs, it queries the PyPI JSON API. For VCS (GitHub) installs, it
queries the GitHub API for the latest commit. Editable and local-dir installs
skip the check. See `lib/git_version.py` for the `InstallSource` detection via
PEP 610 `direct_url.json`.

**Dependency checking** uses `shutil.which()` to locate binaries and runs their
version commands with a 10-second timeout. Version strings are parsed tolerantly
— pre-release suffixes like `-rc1` are stripped. Minimum versions are defined in
`_MIN_VERSIONS`:

- git: 2.25
- podman: 4.0 (netavark backend required for network sandbox)

**Service status** is informational only:

- Checks if `~/.config/systemd/user/airut.service` exists
- Queries `systemctl --user is-active airut.service`
- When running and config is available, fetches `/version` from the local
  dashboard to detect version mismatch between running and installed binaries

### update

```
airut update [--wait] [--force]
```

Update airut to the latest version via `uv tool upgrade airut`.

**Workflow:**

1. **Pre-flight** — If the service is running (and neither `--force` nor
   `--wait` is set), query `/health` on the local dashboard for active task
   counts. Block if tasks are in flight.
2. **Upgrade** — Run `uv tool upgrade airut` (120-second timeout). If the output
   contains "Nothing to upgrade" (case-insensitive), print "Already up to date."
   and return 0 without touching the service.
3. **Service restart** — Only when the binary was actually updated and the
   service was previously installed:
   - Uninstall the service (stop, disable, remove unit, daemon-reload)
   - Reinstall using the new binary (`airut install-service` via subprocess,
     30-second timeout)

**Options:**

| Flag      | Behavior                                       |
| --------- | ---------------------------------------------- |
| `--wait`  | Poll every 10 seconds until all tasks complete |
| `--force` | Skip the in-flight task check entirely         |

**Task blocking** prevents data loss during updates. The health endpoint returns
`{"tasks": {"in_progress": N, "queued": N}}`. When `--wait` is specified and
tasks are active, the command polls every 10 seconds until idle or the service
becomes unreachable.

### install-service

```
airut install-service
```

Install and start the airut systemd user service.

**Preconditions:**

- loginctl linger must be enabled for the current user (checked via
  `/var/lib/systemd/linger/{username}` file existence). Without linger, user
  services stop when the user logs out.

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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

The service runs `airut run-gateway --resilient`, which delegates to
`lib.gateway.service:main()`. `Restart=always` with 10-second backoff ensures
the gateway recovers from transient failures.

**Implementation:** `lib/install_services.py` contains the service management
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
airut run-gateway [--resilient] [--debug]
```

Start the email gateway service. Normally invoked by systemd, not run directly.

Delegates immediately to `lib.gateway.service:main()` with the remaining
arguments. See [gateway-architecture.md](gateway-architecture.md) for the
gateway design.

## Architecture

### Module Structure

```
lib/
├── airut.py              # CLI entry point, subcommand dispatch, check/update
├── install_services.py   # Systemd user service management
└── git_version.py        # Version detection (embedded + git fallback)

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
| 2    | Unknown command                                                |

## Configuration Paths

| Path                              | Purpose                            |
| --------------------------------- | ---------------------------------- |
| `~/.config/airut/airut.yaml`      | Server config (created by `init`)  |
| `~/.config/airut/.env`            | Environment variables for secrets  |
| `~/.config/systemd/user/`         | Systemd user unit files            |
| `~/.local/bin/airut`              | Default binary location (uv tool)  |
| `~/.local/state/airut/<repo_id>/` | Per-repo runtime state (XDG state) |

See [repo-config.md](repo-config.md) for the server/repo config split and YAML
schema.

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

Stopping the gateway while tasks are running would kill active Claude Code
containers, potentially losing work in progress. The pre-flight check queries
the dashboard health endpoint for task counts and blocks unless the operator
explicitly opts in with `--force` or `--wait`.
