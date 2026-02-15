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

- Linux VM (tested on Debian 13)
- Rootless Podman (for container execution)
- Python 3.13+ (via uv)
- Git and GitHub CLI (`gh`)
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
