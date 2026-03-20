# Airut Documentation

Airut is a self-hosted gateway that runs sandboxed
[Claude Code](https://docs.anthropic.com/en/docs/claude-code) over email and
Slack. Send a message with instructions, get results back in the same thread.

```
You → Email/Slack → Airut → Claude Code (container) → PR → Reply → You
```

Each conversation runs in an isolated container with network sandboxing and
credential masking. Self-hosted: your code and conversations never leave your
infrastructure.

Named "Airut" (Finnish: herald/messenger).

## Getting Started

1. **[Deployment](deployment.md)** — Install Airut, configure the server, set up
   git credentials and secrets
2. **[GitHub App setup](github-app-setup.md)** (recommended) — Create a GitHub
   App for the agent's GitHub identity
3. **Set up a channel:**
   - [Email setup](email-setup.md) — IMAP/SMTP provider, DMARC, sender
     authorization
   - [Slack setup](slack-setup.md) — App creation, Socket Mode, authorization
     rules
4. **[Repo onboarding](repo-onboarding.md)** — Add `.airut/` configuration,
   container Dockerfile, and network allowlist to your repository
5. **Send a message** — email or Slack — and Airut handles workspace creation,
   container isolation, and cleanup

## Architecture and Security

- [Architecture](architecture.md) — System architecture, data flow, and
  component overview
- [Security](security.md) — Security model: channel authentication, container
  isolation, credential handling
- [Execution sandbox](execution-sandbox.md) — Container isolation and resource
  limits
- [Network sandbox](network-sandbox.md) — Network allowlist enforcement via
  proxy
- [CI sandbox](ci-sandbox.md) — Sandboxing GitHub Actions and CI pipelines with
  `airut-sandbox`

## Channels

- [Email setup](email-setup.md) — Email provider selection, DMARC verification,
  and sender authorization
- [Slack setup](slack-setup.md) — Slack app creation, tokens, and authorization
  rules
- [M365 OAuth2](m365-oauth2.md) — Microsoft 365 OAuth2 configuration for
  IMAP/SMTP

## Operations

- [Deployment](deployment.md) — Installation, configuration, and service
  management
- [Repo onboarding](repo-onboarding.md) — Onboarding new repositories
- [Gerrit onboarding](gerrit-onboarding.md) — Gerrit-specific onboarding
- [Agentic operation](agentic-operation.md) — Message-to-PR workflow patterns
  and best practices

## Implementation Specifications

Detailed specs covering contracts, data formats, and component behavior live in
[spec/](../spec/README.md).
