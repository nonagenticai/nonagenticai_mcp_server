# Executable catalog — MCP server (Rust)

An MCP server for a multi-tenant executable catalog: it stores immutable tool and toolkit
versions and serves binding-scoped tool discovery and invocation over the [Model Context
Protocol](https://modelcontextprotocol.io), with a PostgreSQL-backed catalog and a separate
execution worker.

**This repository is early.** It implements the health surface and the MCP handshake. The
catalog, credential broker and execution pipeline are being ported in phases against a recorded
parity contract (see [Parity](#parity)). The Python implementation this replaces is archived at
[`nonagenticai/nonagenticai_mcp_server-python-archive`](https://github.com/nonagenticai/nonagenticai_mcp_server-python-archive)
and remains the reference for every behaviour not yet ported.

## What works today

| surface | state |
|---|---|
| `GET /health`, `/health/live`, `/health/ready`, `/api/health` | implemented, responses match the reference |
| `POST /mcp` — `initialize` | implemented; negotiates the protocol version |
| `POST /mcp` — `tools/list` | implemented; returns `[]` (empty catalog) |
| OpenAPI document (`--print-openapi`) | implemented; needs no configuration and no database |
| migrations + pool | implemented (`migrations/0001_baseline.sql`, sqlx) |
| tool catalog, bindings, credentials | **not yet** (phases 2–3) |
| tool invocation and execution worker | **not yet** (phases 5–6) |

The `/mcp` endpoint is stateless and SSE-framed, and serialises `capabilities.tools.listChanged`
as an explicit `false` — both wire details the reference implementation has, and both are
asserted in `tests/http.rs` against an envelope captured from it.

## Stack

Rust 1.99.0 (pinned in `rust-toolchain.toml`), edition 2024, axum 0.8, tokio, sqlx 0.9
(runtime queries only, Postgres, embedded migrations), `rmcp` for the MCP transport, utoipa for
OpenAPI, tracing for JSON logs.

## Layout

| path | what |
|---|---|
| `src/lib.rs` | router, OpenAPI document, app state |
| `src/mcp.rs` | the `/mcp` transport and handler |
| `src/routes/health.rs` | health endpoints |
| `src/tenant.rs` | `TenantId` extractor for the trusted `X-Tenant-Id` header |
| `src/config.rs` | env config: `DATABASE_URL`, `BIND_ADDR` (required), optional `DATABASE_MIGRATE_URL`, `MCP_ALLOWED_HOSTS` |
| `src/db.rs` | pool + migrator |
| `migrations/` | `0001_baseline.sql`, the reference schema |
| `parity.toml`, `parity/` | the parity contract and its runners |

## Build, test, run

```bash
cargo build --locked
cargo test --locked              # DB test: TEST_DATABASE_URL / DATABASE_URL, else an
                                 # ephemeral docker postgres:18, else it fails (never skips)
./target/debug/mcp-server-rs --print-openapi   # OpenAPI JSON; no env, no database

DATABASE_URL=postgres://... BIND_ADDR=0.0.0.0:8080 ./target/debug/mcp-server-rs
```

Migrations run at startup. If `DATABASE_URL` goes through a transaction-pooling pooler, set
`DATABASE_MIGRATE_URL` to a direct Postgres URL: sqlx's migrator holds a session-level advisory
lock that pooled connections cannot guarantee.

## Parity

`parity.toml` pins the reference implementation and lists, per phase, every operation that is
not yet ported. The diff is `equal` only when those exclusions apply **and** nothing else
differs, so the contract can only get stricter: each phase deletes its own group.

```bash
# reference document (public archive; no env, no database)
git clone https://github.com/nonagenticai/nonagenticai_mcp_server-python-archive
(cd nonagenticai_mcp_server-python-archive && uv run --frozen python -c \
   'import json; from src.asgi import create_app; print(json.dumps(create_app().openapi()))') \
  > source.openapi.json

./target/debug/mcp-server-rs --print-openapi > target.openapi.json
```

`parity/README.md` records the evidence for each gate and the commands that produced it.

## CI

`.github/workflows/ci-public.yml` is self-contained and runs on GitHub-hosted runners: a secret
scan, a private-reference scan, `cargo fmt` / `clippy -D warnings` / `nextest` + doctests /
`cargo audit` against a disposable Postgres 18, and a Docker image build (pushed to
`ghcr.io` from `main` only when the repository variable `PUBLISH_IMAGE` is `true`).

It does **not** call the private estate archetype, because a public repository cannot read a
reusable workflow in a private repository — the run dies at startup with zero jobs. The same
reason rules out self-hosted runners: a fork PR can edit `runs-on`.

## Licensing

The code in this repository is Apache-2.0 and needs no licence key to build, test or run.
It contains no licence-enforcement code today: the executable-catalog port is early and has
not carried over the licence introspection of the Python implementation it replaces (archived
at [`nonagenticai/nonagenticai_mcp_server-python-archive`](https://github.com/nonagenticai/nonagenticai_mcp_server-python-archive)).
Nothing in this repository requires a licence server.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
