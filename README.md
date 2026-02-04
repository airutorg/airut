<p align="center">
  <img src="assets/logo.svg" alt="Airut logo" width="400">
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

- **Comprehensive sandboxing**: Container isolation plus network allowlist
  prevents data exfiltration even if the agent is compromised
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

1. **Deploy Airut** on a Linux VM (see [deployment.md](doc/deployment.md))

2. **Onboard a repository** by creating `.airut/` configuration (see
   [repo-onboarding.md](doc/repo-onboarding.md))

3. **Send an email** to your configured address:

   ```
   To: airut@example.com
   Subject: Fix the typo in README

   Please fix the typo in the README file.
   ```

4. **Receive the response** with results and PR link

## Project Structure

```
airut/
├── CLAUDE.md              # Agent operating instructions
├── doc/                   # High-level documentation
├── spec/                  # Implementation specifications
├── .airut/                # Repo-specific Airut configuration
├── config/                # Server configuration templates
├── docker/                # Container images (proxy, entrypoint)
├── lib/                   # Library code
│   ├── container/         # Container execution (executor, proxy, session)
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
