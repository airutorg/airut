# Documentation

High-level documentation for Airut. These documents describe concepts, security
properties, and operational procedures.

For implementation-level specifications, see [spec/](../spec/).

**Getting started?** Read [deployment.md](deployment.md) first, then
[repo-onboarding.md](repo-onboarding.md) to configure your first repository.

## Architecture

- [architecture.md](architecture.md) — System architecture and data flow
- [security.md](security.md) — Security model (channel auth, isolation,
  credentials)
- [execution-sandbox.md](execution-sandbox.md) — Container isolation and
  resource limits
- [network-sandbox.md](network-sandbox.md) — Network allowlist and proxy
  architecture
- [agentic-operation.md](agentic-operation.md) — Message-to-PR workflow patterns

## Operations

- [deployment.md](deployment.md) — Installation and server configuration
- [repo-onboarding.md](repo-onboarding.md) — Onboarding new repositories
- [gerrit-onboarding.md](gerrit-onboarding.md) — Gerrit-specific onboarding

## Channel Setup

- [email-setup.md](email-setup.md) — Email provider selection, DMARC, and
  authorization
- [slack-setup.md](slack-setup.md) — Slack app creation, tokens, and
  authorization rules
- [m365-oauth2.md](m365-oauth2.md) — Microsoft 365 OAuth2 for email (IMAP/SMTP)
