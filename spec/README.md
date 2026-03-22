# Specifications

Implementation-level specifications for Airut components. These documents
describe contracts, data formats, and detailed behavior.

For high-level documentation, see [doc/](../doc/).

## Gateway

- [gateway-architecture.md](gateway-architecture.md) — Core gateway design,
  channel abstraction, data flow, container execution
- [authentication.md](authentication.md) — Per-channel authentication and
  authorization (DMARC for email, workspace/group/user rules for Slack)
- [repo-config.md](repo-config.md) — Per-repo schema in server config
- [declarative-config.md](declarative-config.md) — Declarative config layer
  (schema metadata, migration, diffing, round-trip, config variables)
- [multi-repo.md](multi-repo.md) — Multi-repository support design
- [slack-channel.md](slack-channel.md) — Slack channel implementation (Socket
  Mode, Agents & AI Apps)
- [integration-tests.md](integration-tests.md) — End-to-end test specification

## Sandbox

- [sandbox.md](sandbox.md) — Sandbox library for safe containerized Claude Code
  execution
- [sandbox-cli.md](sandbox-cli.md) — Standalone CLI for running commands in the
  sandbox (CI integration)
- [sandbox-action.md](sandbox-action.md) — Reusable GitHub Action wrapping
  airut-sandbox (`airutorg/sandbox-action`)

## Container

- [image.md](image.md) — Two-layer container image build strategy

## Network

- [network-sandbox.md](network-sandbox.md) — Proxy lifecycle, resource scoping,
  log format, crash recovery
- [masked-secrets.md](masked-secrets.md) — Scope-restricted credentials with
  proxy-level token replacement
- [aws-sigv4-resigning.md](aws-sigv4-resigning.md) — AWS SigV4/SigV4A credential
  masking via proxy re-signing
- [github-app-credential.md](github-app-credential.md) — GitHub App credential
  support with proxy-managed token rotation

## Dashboard

- [dashboard.md](dashboard.md) — Web dashboard for task monitoring

## Infrastructure

- [cli.md](cli.md) — CLI subcommands, service management, self-update
- [pr-workflow-tool.md](pr-workflow-tool.md) — PR workflow automation (ci.py,
  pr.py)
- [local-ci-runner.md](local-ci-runner.md) — CI runner (single source of truth
  for all CI checks)
