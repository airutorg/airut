# Specifications

Implementation-level specifications for Airut components. These documents
describe contracts, data formats, and detailed behavior.

For high-level documentation, see [doc/](../doc/).

## Email Gateway

- [gateway-architecture.md](gateway-architecture.md) — Core gateway design, data
  flow, email protocol, container execution
- [authentication.md](authentication.md) — DMARC verification and sender
  authorization
- [repo-config.md](repo-config.md) — Repo config schema (`.airut/airut.yaml`)
  and server/repo split
- [multi-repo.md](multi-repo.md) — Multi-repository support design
- [integration-tests.md](integration-tests.md) — End-to-end test specification

## Container

- [image.md](image.md) — Two-layer container image build strategy

## Network

- [masked-secrets.md](masked-secrets.md) — Scope-restricted credentials with
  proxy-level token replacement

## Dashboard

- [dashboard.md](dashboard.md) — Web dashboard for task monitoring

## Infrastructure

- [auto-updater.md](auto-updater.md) — Automatic service updates
- [pr-workflow-tool.md](pr-workflow-tool.md) — PR workflow automation (ci.py,
  pr.py)
- [local-ci-runner.md](local-ci-runner.md) — Local CI runner for pre-push
  validation
