# Specifications

Implementation-level specifications for Airut components. These documents
describe contracts, data formats, and detailed behavior.

For high-level documentation, see [doc/](../doc/).

## Gateway

- [gateway-architecture.md](gateway-architecture.md) — Core gateway design, data
  flow, email protocol, container execution
- [protocol-agnostic-gateway.md](protocol-agnostic-gateway.md) —
  Protocol-agnostic gateway refactoring (channel adapter abstraction)
- [authentication.md](authentication.md) — DMARC verification and sender
  authorization
- [repo-config.md](repo-config.md) — Repo config schema (`.airut/airut.yaml`)
  and server/repo split
- [multi-repo.md](multi-repo.md) — Multi-repository support design
- [integration-tests.md](integration-tests.md) — End-to-end test specification

## Sandbox

- [sandbox.md](sandbox.md) — Sandbox library for safe containerized Claude Code
  execution

## Container

- [image.md](image.md) — Two-layer container image build strategy

## Network

- [network-sandbox.md](network-sandbox.md) — Proxy lifecycle, resource scoping,
  log format, crash recovery
- [masked-secrets.md](masked-secrets.md) — Scope-restricted credentials with
  proxy-level token replacement
- [aws-sigv4-resigning.md](aws-sigv4-resigning.md) — AWS SigV4/SigV4A credential
  masking via proxy re-signing

## Dashboard

- [dashboard.md](dashboard.md) — Web dashboard for task monitoring
- [live-dashboard.md](live-dashboard.md) — Real-time dashboard updates via SSE

## Infrastructure

- [cli.md](cli.md) — CLI subcommands, service management, self-update
- [pr-workflow-tool.md](pr-workflow-tool.md) — PR workflow automation (ci.py,
  pr.py)
- [local-ci-runner.md](local-ci-runner.md) — Local CI runner for pre-push
  validation
