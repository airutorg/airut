# Execution Sandbox

The execution sandbox isolates Claude Code sessions from the host system and
from each other. Each conversation runs in a dedicated Podman container with
controlled mounts, environment variables, and network access.

The same sandbox technology is available as a standalone CLI (`airut-sandbox`)
for running arbitrary commands in CI pipelines and other environments. See
[ci-sandbox.md](ci-sandbox.md) for CI usage and
[spec/sandbox-cli.md](../spec/sandbox-cli.md) for the full CLI specification.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Threat Model](#threat-model)
- [Isolation Properties](#isolation-properties)
  - [Filesystem Isolation](#filesystem-isolation)
  - [Workspace Isolation](#workspace-isolation)
  - [Credential Isolation](#credential-isolation)
  - [Session Metadata](#session-metadata)
- [Network Isolation](#network-isolation)
- [Container Runtime](#container-runtime)
- [Resource Limits](#resource-limits)
  - [Two-Layer Configuration](#two-layer-configuration)
  - [cgroup v2 Requirement](#cgroup-v2-requirement)
  - [Other Limits](#other-limits)
- [Fail-Secure Behavior](#fail-secure-behavior)
- [Further Reading](#further-reading)

<!-- mdformat-toc end -->

## Threat Model

Claude Code executes arbitrary code on behalf of the agent. Without isolation:

- A compromised session could access host files or credentials
- Sessions could interfere with each other
- Malicious code could persist across conversations
- Credentials could be exfiltrated or misused

The execution sandbox contains these risks through container isolation, mount
restrictions, and credential scoping.

## Isolation Properties

### Filesystem Isolation

Each conversation gets a fresh container with controlled mounts:

| Mount Point     | Source                          | Access | Purpose                             |
| --------------- | ------------------------------- | ------ | ----------------------------------- |
| `/workspace`    | `conversations/{id}/workspace/` | rw     | Git checkout                        |
| `/root/.claude` | `conversations/{id}/claude/`    | rw     | Claude session state                |
| `/inbox`        | `conversations/{id}/inbox/`     | rw     | Email attachments                   |
| `/outbox`       | `conversations/{id}/outbox/`    | rw     | Files to attach to reply            |
| `/storage`      | `conversations/{id}/storage/`   | rw     | Conversation-scoped persistent data |

Everything outside these mount points is ephemeral — the container filesystem is
destroyed after each task execution. Only the mounted directories persist
between messages in a conversation.

**Why ephemeral?** The container image is rebuilt from the repository's default
branch at every task start. This means the agent can request new tools or
dependencies (by modifying `.airut/container/Dockerfile`), create a PR, and once
the user merges it, the next task automatically picks up the changes. The same
applies to the network allowlist and repo configuration. Ephemeral containers
make this self-service workflow possible.

**What's NOT mounted:**

- Host SSH keys or `~/.ssh`
- Host git configuration
- Host credential files
- Other conversation directories
- Server configuration or secrets

### Workspace Isolation

The workspace is a full git clone, not a shallow copy or shared reference. All
git objects are self-contained — the container cannot access paths outside its
mounts, and workspace corruption doesn't affect the mirror or other
conversations.

### Credential Isolation

Credentials are passed via environment variables, not files. All credential pool
entries (`secrets`, `masked_secrets`, `signing_credentials`,
`github_app_credentials`) in the server config auto-inject into the container as
environment variables by their key name.

- All resolved values are registered for log redaction
- No host credential files are mounted

For credentials that should only be usable with specific services (e.g., GitHub
tokens for GitHub APIs), use **masked secrets** in the server config. The
container receives a surrogate token; the proxy swaps it for the real value only
when the request matches scoped hosts. See
[network-sandbox.md](network-sandbox.md#masked-secrets-token-replacement) for
details.

Git authentication uses `gh auth git-credential` helper with `GH_TOKEN`,
avoiding SSH key exposure.

### Session Metadata

Session metadata (`conversation.json`) is stored outside the container mount.
This prevents the agent from tampering with session tracking or conversation
IDs.

## Network Isolation

Containers are placed on an internal Podman network with no direct internet
access. All HTTP(S) traffic routes through a proxy container that enforces the
network allowlist. See [network-sandbox.md](network-sandbox.md) for details.

## Container Runtime

Containers run with rootless Podman:

- **User**: root inside container (with `IS_SANDBOX=1` for Claude Code)
- **Working directory**: `/workspace`
- **Resource limits**: Configurable per-repo (memory, CPUs, process count,
  timeout) — see [Resource Limits](#resource-limits)
- **Capabilities**: All Linux capabilities dropped (`--cap-drop=ALL`)
- **Privilege escalation**: Blocked (`--security-opt=no-new-privileges:true`)

These security options are defense-in-depth measures. Rootless Podman already
provides strong isolation, but explicitly dropping all capabilities and
preventing privilege escalation ensures that even if a container escape
vulnerability exists, the process cannot gain additional privileges.

The container image is built in two layers — a repo-defined base image and a
server overlay with the entrypoint. See [spec/image.md](../spec/image.md) for
build details.

## Resource Limits

Container resource limits are configured via the `resource_limits` block in the
server config per repo. All fields are optional — when omitted, the
corresponding podman flag is not passed and no limit is enforced.

```yaml
# ~/.config/airut/airut.yaml (server config, per repo)
repos:
  my-project:
    resource_limits:
      timeout: 6000       # Max execution time in seconds (>= 10)
      memory: "4g"        # Memory limit, e.g. "2g", "512m" (--memory)
      cpus: 2             # CPU limit, supports fractional (--cpus)
      pids_limit: 256     # Process limit, fork bomb protection (--pids-limit)
```

| Field        | Podman flag                  | Effect                       |
| ------------ | ---------------------------- | ---------------------------- |
| `timeout`    | `process.wait(timeout=N)`    | Container killed after N sec |
| `memory`     | `--memory=X --memory-swap=X` | Hard memory limit, no swap   |
| `cpus`       | `--cpus=N`                   | CPU core limit (float)       |
| `pids_limit` | `--pids-limit=N`             | Max number of processes      |

Setting `--memory-swap` equal to `--memory` disables swap, preventing slow OOM
thrashing.

### Two-Layer Configuration

The server config also supports a top-level `resource_limits` block that defines
default values for all repos:

```yaml
# ~/.config/airut/airut.yaml (server config, top level)
resource_limits:
  timeout: 7200       # Default timeout
  memory: "8g"        # Default memory limit
  cpus: 4             # Default CPU limit
  pids_limit: 1024    # Default process limit
```

Per-repo values override these defaults. For each field independently: the repo
value is used if set, otherwise the server default applies. If neither sets a
value, no limit is enforced for that dimension.

### cgroup v2 Requirement

Memory, CPU, and process limits require cgroup v2 with `cpu`, `memory`, and
`pids` controllers delegated to the user running Airut. Run `airut check` to
verify. This is the default on Ubuntu 22.04+, Fedora 34+, Debian 12+, and RHEL
9+.

### Other Limits

- **Conversation expiry**: 7 days without activity (configurable)

## Fail-Secure Behavior

- If image build fails: Task aborts with error message
- If proxy doesn't start: Task aborts (no unproxied execution)
- If workspace clone fails: Conversation marked failed, retry on next message
- If timeout exceeded: Container killed, partial results returned

## Further Reading

- [ci-sandbox.md](ci-sandbox.md) — Using the sandbox for CI pipelines
- [network-sandbox.md](network-sandbox.md) — Network allowlist enforcement
- [security.md](security.md) — Overall security model
- [spec/sandbox.md](../spec/sandbox.md) — Sandbox library specification
- [spec/sandbox-cli.md](../spec/sandbox-cli.md) — Standalone CLI specification
- [spec/image.md](../spec/image.md) — Container image build details
- [spec/gateway-architecture.md](../spec/gateway-architecture.md) — Full
  execution flow
