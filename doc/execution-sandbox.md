# Execution Sandbox

The execution sandbox isolates Claude Code sessions from the host system and
from each other. Each conversation runs in a dedicated Podman container with
controlled mounts, environment variables, and network access.

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

| Mount Point     | Source                     | Access | Purpose                  |
| --------------- | -------------------------- | ------ | ------------------------ |
| `/workspace`    | `sessions/{id}/workspace/` | rw     | Git checkout             |
| `/root/.claude` | `sessions/{id}/claude/`    | rw     | Claude session state     |
| `/inbox`        | `sessions/{id}/inbox/`     | rw     | Email attachments        |
| `/outbox`       | `sessions/{id}/outbox/`    | rw     | Files to attach to reply |

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

Credentials are passed via environment variables, not files:

```yaml
# In .airut/airut.yaml (repo config)
container_env:
  GH_TOKEN: !secret GH_TOKEN              # Required
  ANTHROPIC_API_KEY: !secret? ANTHROPIC_API_KEY  # Optional
```

- `!secret NAME` resolves from server's secrets pool (error if missing)
- `!secret? NAME` silently skips if missing
- All resolved values are registered for log redaction
- Values loaded from git mirror's default branch (not workspace)

Git authentication uses `gh auth git-credential` helper with `GH_TOKEN`,
avoiding SSH key exposure.

### Session Metadata

Session metadata (`session.json`) is stored outside the container mount. This
prevents the agent from tampering with session tracking or conversation IDs.

## Network Isolation

Containers are placed on an internal Podman network with no direct internet
access. All HTTP(S) traffic routes through a proxy container that enforces the
network allowlist. See [network-sandbox.md](network-sandbox.md) for details.

## Container Runtime

Containers run with rootless Podman:

- **User**: root inside container (with `IS_SANDBOX=1` for Claude Code)
- **Working directory**: `/workspace`
- **Timeout**: Configurable per-repo (default 300s)

The container image is built in two layers — a repo-defined base image and a
server overlay with the entrypoint. See [spec/image.md](../spec/image.md) for
build details.

## Resource Limits

- **Timeout**: Configurable per-repo; container killed if exceeded
- **Conversation limit**: 100 active conversations (oldest garbage-collected)
- **Conversation expiry**: 7 days without activity (configurable)

## Fail-Secure Behavior

- If image build fails: Task aborts with error message
- If proxy doesn't start: Task aborts (no unproxied execution)
- If workspace clone fails: Conversation marked failed, retry on next message
- If timeout exceeded: Container killed, partial results returned

## Further Reading

- [network-sandbox.md](network-sandbox.md) — Network allowlist enforcement
- [security.md](security.md) — Overall security model
- [spec/image.md](../spec/image.md) — Container image build details
- [spec/gateway-architecture.md](../spec/gateway-architecture.md) — Full
  execution flow
