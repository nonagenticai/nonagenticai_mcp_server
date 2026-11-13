# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-14

First public release: the health surface and the MCP handshake, ported from the reference
implementation and verified against its OpenAPI document.

### Added

- Health endpoints `GET /health`, `/health/live`, `/health/ready` and `/api/health`, matching
  the reference implementation's responses.
- An MCP endpoint at `/mcp` over the streamable HTTP transport. `initialize` negotiates the
  protocol version; `tools/list` returns an empty catalog. The wire shape is stateless and
  SSE-framed, and `capabilities.tools.listChanged` is serialised as an explicit `false`, as the
  reference does.
- PostgreSQL pool and embedded migrations, with `DATABASE_MIGRATE_URL` for running migrations
  around a transaction-pooling connection pooler.
- OpenAPI document generation (`--print-openapi`) that reads no configuration and touches no
  database, so parity tooling can diff it in a bare workspace.
- The parity contract (`parity.toml`) pins the reference implementation and names, phase by
  phase, every operation that is not yet ported.

### Not yet

- The tool catalog, credential broker and execution worker. See the README's table.
