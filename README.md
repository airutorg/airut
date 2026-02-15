<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo.svg">
    <img src="assets/logo.svg" alt="Airut logo" width="400">
  </picture>
</p>

# Airut

Headless Claude Code interaction via email. Named "Airut" (Finnish:
herald/messenger). Created by Pyry Haulos.

## What It Does

Send an email with instructions, receive Claude Code's response. Airut runs
Claude Code in isolated containers, maintains conversation state, and handles
the full email-to-PR workflow.

```
You → Email → Airut → Claude Code (container) → PR → Email reply → You
```

**Key features:**

- **Defense-in-depth sandboxing**: Container isolation, surrogate credentials,
  and network allowlist significantly limit blast radius in case of agent
  misbehavior. Agents run in permissive mode to complete tasks end-to-end, while
  security controls bound what they can access and where data can go.
- **Email-native authentication**: DMARC verification with sender allowlist — no
  API keys to manage
- **Model selection via subaddressing**: Control costs by choosing the model per
  email (e.g., `airut+haiku@example.com` for fast/cheap,
  `airut+opus@example.com` for complex tasks)
- **Conversation threading**: Reply to continue conversations; `[ID:xyz123]`
  tracks state across sessions
- **File attachments**: Send files to `/inbox`; receive files from `/outbox`
- **Web dashboard**: Monitor running tasks and view network activity logs

## Why Email?

### A Super-Optimized Communication Medium

Email clients have been refined over decades for managing multiple asynchronous
communications. For many of us, the inbox is already where our task list lives.
Agent interactions integrate naturally into this workflow — you get the benefits
of decades of compounded investment in email tooling: threading, search,
filters, mobile clients, and notification systems.

Using email also dramatically lowers the barrier to engage with an agent. Send a
message from any device, get results when ready. No terminal session to keep
open, no custom client to install.

### Parallel Agent Management

Running multiple Claude Code agents requires isolation — each needs its own
workspace, session state, and credentials. Airut provides this automatically:
each email conversation is fully isolated, and a configurable thread pool
manages concurrent execution.

### Code Review as Feedback

The recommended workflow has agents push PRs for review. You review the PR,
leave comments, then reply to the email. The agent reads review feedback and
iterates. This provides:

- Human oversight before code lands
- Natural checkpoint for feedback
- Audit trail via git history

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

**Proof of concept:** This project itself is developed exclusively via the email
workflow — from the first working version onward, all development has been done
by sending instructions to Airut and reviewing the resulting PRs.

**Example project:** The
[airut.org website](https://github.com/airutorg/website) is a minimal
Airut-managed repository that demonstrates the email-to-deploy workflow with
Cloudflare Pages. Its `.airut/` directory and `CLAUDE.md` serve as a good
starting point for onboarding your own projects.

## Documentation

### High-Level Documentation

- **[doc/architecture.md](doc/architecture.md)** — System architecture and data
  flow
- **[doc/security.md](doc/security.md)** — Security model (email auth,
  isolation, credentials)
- **[doc/execution-sandbox.md](doc/execution-sandbox.md)** — Container isolation
  and resource limits
- **[doc/network-sandbox.md](doc/network-sandbox.md)** — Network allowlist and
  proxy architecture
- **[doc/deployment.md](doc/deployment.md)** — Installation and configuration
  guide
- **[doc/repo-onboarding.md](doc/repo-onboarding.md)** — How to onboard a new
  repository
- **[doc/agentic-operation.md](doc/agentic-operation.md)** — Email-to-PR
  workflow patterns

### Implementation Specifications

- **[spec/](spec/README.md)** — Detailed specs for email protocol, config
  schema, dashboard, and tooling

### Agent Instructions

- **[CLAUDE.md](CLAUDE.md)** — Operating instructions for Claude Code agents

## Quick Start

### Prerequisites

- Linux (dedicated VM recommended, Debian 13 tested)
- [uv](https://docs.astral.sh/uv/), Git, and Podman (rootless)
- Dedicated email account with IMAP/SMTP access (one per repository)

### Install and Configure

```bash
uv tool install airut          # Install from PyPI
airut init                     # Generate config at ~/.config/airut/airut.yaml
```

Edit `~/.config/airut/airut.yaml` with your email, repo, and secrets. See
[deployment.md](doc/deployment.md) for the full guide including email providers,
secrets management, and git credentials.

[Onboard your repository](doc/repo-onboarding.md) by creating the `.airut/`
directory with container Dockerfile, network allowlist, and `CLAUDE.md`.

### Deploy

```bash
airut check                    # Validate config and system dependencies
airut install-service          # Install and start systemd service
airut check                    # Verify everything is running
```

### Send Your First Email

```
To: airut@example.com
Subject: Fix the typo in README

Please fix the typo in the README file.
```

### Update

```bash
airut update                   # Stop service, upgrade, restart
```

## Project Structure

```
airut/
├── CLAUDE.md              # Agent operating instructions
├── doc/                   # High-level documentation
├── spec/                  # Implementation specifications
├── .airut/                # Repo-specific Airut configuration
├── config/                # Server configuration templates
├── lib/                   # Library code
│   ├── _bundled/          # Static resources bundled into wheel
│   │   ├── assets/        # Logo SVG
│   │   └── proxy/         # Network sandbox (proxy filter, DNS, AWS signing)
│   ├── sandbox/           # Sandboxed execution (container, proxy, session, image)
│   ├── conversation/      # Conversation directory layout and preparation
│   ├── dashboard/         # Web dashboard server
│   ├── gateway/           # Email gateway service
│   └── gh/                # GitHub API wrappers
├── scripts/               # CLI tools
│   ├── gateway/           # Email gateway CLI
│   ├── ci.py              # Local CI runner
│   └── pr.py              # PR workflow tool
└── tests/                 # Unit and integration tests
```

## Development

This project is developed with Claude Code. See [CLAUDE.md](CLAUDE.md) for
conventions and workflow tools.

```bash
# Run local CI (auto-fix + all checks)
uv run scripts/ci.py --fix

# Monitor PR status
uv run scripts/pr.py ci --wait -v
uv run scripts/pr.py review -v
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
