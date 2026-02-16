# Airut

Headless Claude Code interaction via email. Named "Airut" (Finnish:
herald/messenger).

Send an email with instructions, receive Claude Code's response. Airut runs
Claude Code in isolated containers, maintains conversation state, and handles
the full email-to-PR workflow.

```
You → Email → Airut → Claude Code (container) → PR → Email reply → You
```

## Key Features

- **Defense-in-depth sandboxing** — container isolation, surrogate credentials,
  and network allowlist limit blast radius in case of agent misbehavior
- **Email-native authentication** — DMARC verification with sender allowlist, no
  API keys to manage
- **Model selection via subaddressing** — choose the model per email (e.g.,
  `airut+haiku@example.com` for fast/cheap, `airut+opus@example.com` for complex
  tasks)
- **Conversation threading** — reply to continue conversations across sessions
- **File attachments** — send files to the agent, receive files back
- **Web dashboard** — monitor running tasks and view network activity logs

## Quick Start

### Prerequisites

- Linux (dedicated VM recommended, Debian 13 tested)
- [uv](https://docs.astral.sh/uv/), Git, and Podman (rootless)
- Dedicated email account with IMAP/SMTP access

### Install

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Airut from PyPI
uv tool install airut
```

Or install the latest development version from main:

```bash
uv tool install airut --from git+https://github.com/airutorg/airut.git
```

### Configure

```bash
# Generate initial config at ~/.config/airut/airut.yaml
airut init

# Validate config and system dependencies
airut check
```

### Deploy

```bash
# Install and start the systemd service
airut install-service

# Verify it's running
airut check
```

### Update

```bash
airut update
```

## How It Works

Each email conversation runs in an isolated container with its own git
workspace, Claude Code session, and sandboxed network. The recommended workflow
has agents push PRs for your review — you review, leave comments, and reply to
the email to iterate.

```
You: "Add user authentication"
    ↓
Agent: works → pushes PR → replies with PR link
    ↓
You: review PR, leave comments
    ↓
You: reply to email "Address the review comments"
    ↓
Agent: reads comments → fixes → updates PR → replies
    ↓
You: approve and merge
```

## Sandbox Library

The `airut.sandbox` module is a standalone library for safe containerized
execution of headless Claude Code. It can be used independently of the email
gateway to run Claude Code in isolated containers from any Python application —
CI pipelines, automation scripts, custom integrations, or your own agent
orchestrator.

**Core capabilities:**

- **Container lifecycle** — two-layer image build, execution, and cleanup via
  Podman or Docker
- **Network isolation** — transparent DNS-spoofing proxy enforcing a domain
  allowlist, with no `HTTP_PROXY` env vars or `iptables` rules needed
- **Secret masking** — surrogate credential injection so real secrets never
  reach the container, with proxy-side replacement on egress
- **Event streaming** — append-only log of Claude's streaming JSON output, safe
  for concurrent reads during execution
- **Outcome classification** — typed `Outcome` enum (success, timeout,
  prompt-too-long, session-corrupted, container-failed) so callers match on
  outcomes instead of parsing strings

**Quick example:**

```python
from airut.sandbox import Sandbox, SandboxConfig, Mount, ContainerEnv, Outcome

sandbox = Sandbox(SandboxConfig())
sandbox.startup()

image = sandbox.ensure_image(dockerfile, context_files)
task = sandbox.create_task(
    execution_context_id="my-run-1",
    execution_context_dir=run_dir,
    image_tag=image,
    mounts=[Mount(host_path=repo, container_path="/workspace")],
    env=ContainerEnv(variables={"ANTHROPIC_API_KEY": key}),
    timeout_seconds=600,
)
result = task.execute("Fix the failing tests")

if result.outcome == Outcome.SUCCESS:
    print(result.response_text)

sandbox.shutdown()
```

See the
[sandbox spec](https://github.com/airutorg/airut/blob/main/spec/sandbox.md) for
full architecture details and API reference.

## Documentation

Full documentation is available on GitHub:

- [Deployment Guide](https://github.com/airutorg/airut/blob/main/doc/deployment.md)
  — installation, configuration, and service management
- [Architecture](https://github.com/airutorg/airut/blob/main/doc/architecture.md)
  — system architecture and data flow
- [Security Model](https://github.com/airutorg/airut/blob/main/doc/security.md)
  — email auth, container isolation, credential handling
- [Repo Onboarding](https://github.com/airutorg/airut/blob/main/doc/repo-onboarding.md)
  — how to onboard a new repository
- [Agentic Operation](https://github.com/airutorg/airut/blob/main/doc/agentic-operation.md)
  — email-to-PR workflow patterns

## Links

- [GitHub Repository](https://github.com/airutorg/airut)
- [Full README](https://github.com/airutorg/airut#readme)

## License

MIT License. See [LICENSE](https://github.com/airutorg/airut/blob/main/LICENSE)
for details.
