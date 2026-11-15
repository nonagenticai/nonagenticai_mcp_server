# Executable catalog — MCP server (Rust)

[![CI](https://github.com/nonagenticai/nonagenticai_mcp_server/actions/workflows/ci-public.yml/badge.svg)](https://github.com/nonagenticai/nonagenticai_mcp_server/actions/workflows/ci-public.yml)
[![Release](https://img.shields.io/github/v/release/nonagenticai/nonagenticai_mcp_server)](https://github.com/nonagenticai/nonagenticai_mcp_server/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An MCP server for a multi-tenant executable catalog. It stores immutable tool and toolkit
versions, serves binding-scoped tool discovery and invocation over the [Model Context
Protocol](https://modelcontextprotocol.io), introspects tenant licences, queues runs in
PostgreSQL, and executes them in isolated Kata pods through a separate worker binary. It is a
Rust port of the Python implementation archived at
[`nonagenticai/nonagenticai_mcp_server-python-archive`](https://github.com/nonagenticai/nonagenticai_mcp_server-python-archive).

| | |
|---|---|
| **Runtime** | Rust 1.99.0 (pinned in `rust-toolchain.toml`), edition 2024 |
| **Depends on** | PostgreSQL 18; a Kubernetes cluster with a Kata runtime class only when execution is enabled; a licence introspection endpoint only when licence authentication is configured |
| **Runs on** | Three binaries from one image: `mcp-server-rs` (API), `mcp-worker` (Kata executor) and `mcp-external-driver` (n8n and fr runtimes) |

## Features

- **MCP over stateless Streamable HTTP** at `/mcp` and `/mcp/`: `initialize`, `tools/list`,
  `tools/call`, and — when `MCP_TASKS_ENABLED` is set — `tasks/get`, `tasks/update` and
  `tasks/cancel`.
- **Catalog-backed `tools/list`.** The caller's live binding is resolved through the same
  catalog resolver the REST surface uses, paged by `CATALOG_PAGE_SIZE`, with an HMAC-signed,
  fingerprint-bound cursor. The binding revision is re-read before every page; a stale or
  forged cursor is refused with `catalog_unavailable_or_invalid_cursor`.
- **Schema-validated `tools/call`.** Inputs are validated against the tool's declared schema,
  the resolved tool is re-checked immediately before durable acceptance, and the run is queued
  in PostgreSQL. Refusals are returned as `isError: true` tool results, never as JSON-RPC
  errors.
- **Immutable catalog and toolkit versions** with draft/publish/disable/retire lifecycle,
  bounded Draft 2020-12 JSON Schema validation, UUIDv7 identities, expected-revision
  conflicts, and management REST routes under `/mcp/tools`, `/mcp/toolkits`, `/mcp/bindings`,
  `/mcp/available-tools` and `/mcp/runs`.
- **Licence and binding authentication** on every `/mcp` request: a tenant licence introspected
  at `LICENSE_INTROSPECT_URL` plus a binding token (`X-MCP-Binding`), or an operator key
  (`X-MCP-Admin-Key`) for management routes. Authentication fails closed.
- **Platform authoring** behind the platform operator key: the tool-source registry
  (`/mcp/sources`, with write-only tokens sealed through AES-256-GCM and a destination
  allow-list), service and operation contract drafts (`/mcp/services`, `/mcp/operations`,
  including the bounded OpenAPI 3.1 import), and tenant credential profiles
  (`/mcp/credential-profiles`). These read and write through a second pool
  (`MCP_PLATFORM_DATABASE_URL`, the same database under the elevated `mcp_platform` role) and
  answer `503 platform_authoring_unavailable` when it is unset, as the reference does.
- **Durable execution.** A PostgreSQL queue with fenced leases, global and per-tenant capacity,
  idempotency, cancellation, run journal, and recovery/quarantine. The `mcp-worker` binary
  claims runs, starts one hardened Kata runner pod per run (non-root, read-only root
  filesystem, all capabilities dropped), brokers every upstream call through a scoped
  credential broker, and records the outcome.
- **External runtimes.** Runs whose tool target is an n8n workflow, an fr project or one fixed fr
  channel command are driven by the `mcp-external-driver` binary, which is their only writer: it
  dispatches at most once (the dispatch event is committed before the upstream call), keeps each
  run's lease alive while an upstream answer is in flight, polls the upstream each interval,
  relays a human's approval answer back to fr, and records the outcome. Channels are signed — an
  HMAC envelope to fr, a two-minute HS256 JWT to n8n — and both bounds (a 4 MiB poll body, a
  64 KiB result) are the reference's.
- **Health and OpenAPI.** `/health`, `/health/live`, `/health/ready` and `/api/health` report
  whether execution is enabled; `--print-openapi` emits the OpenAPI document with no
  configuration and no database.

## Stack

Rust 1.99.0, edition 2024, axum 0.8, tokio, sqlx 0.9 (runtime queries only, PostgreSQL,
embedded migrations), `rmcp` 3.9 for the MCP transport, utoipa for OpenAPI, tracing for JSON
logs, and `kube` for the worker's pod transport.

## Layout

| path | what |
|---|---|
| `src/main.rs` | the API binary |
| `src/bin/mcp-worker.rs` | the executor binary |
| `src/bin/mcp-external-driver.rs` | the external-run driver binary |
| `src/external/` | the driver loop, its storage half, and the n8n and fr adapters |
| `src/lib.rs` | router, OpenAPI document, application state |
| `src/mcp.rs` | the `/mcp` transport and handlers (`initialize`, `tools/list`, `tools/call`, tasks) |
| `src/catalog/` | catalog domain: models, validation, publication, resolver |
| `src/auth/` | licence introspection, binding authentication, principals, management auth |
| `src/execution/` | run domain and execution service |
| `src/worker/` | scheduler, controller, Kata backend, credential broker, egress policy, recovery |
| `src/routes/` | health and management REST handlers |
| `src/sources/` | tool sources: the destination guard, the sealed token, the contracts and their repository |
| `src/storage/` | PostgreSQL repositories |
| `src/config.rs` | environment configuration |
| `src/db.rs` | pool and embedded migrator |
| `migrations/` | `0001_baseline.sql` and `0002_catalog_state.sql` |
| `parity.toml`, `parity/` | the parity contract, fixtures and runners |

## Quick start

```bash
git clone https://github.com/nonagenticai/nonagenticai_mcp_server.git
cd nonagenticai_mcp_server
cargo build --locked

export DATABASE_URL=postgres://user:password@127.0.0.1:5432/mcp
export BIND_ADDR=127.0.0.1:9000
./target/debug/mcp-server-rs
```

Migrations run at startup. If `DATABASE_URL` goes through a transaction-pooling pooler, set
`DATABASE_MIGRATE_URL` to a direct Postgres URL: sqlx's migrator holds a session-level advisory
lock that pooled connections cannot guarantee.

The image contains all three binaries. Run the worker and the external driver as separate
processes (or Deployments) with the same `DATABASE_URL`; execution stays disabled until
`EXECUTION_ENABLED=true` and the runner images are approved.

## Usage

Health is unauthenticated:

```bash
curl -sS http://127.0.0.1:9000/health
# {"execution":"unavailable","status":"alive"}
```

`/mcp` requires a tenant licence and a binding token. A `tools/list` request:

```bash
curl -sS http://127.0.0.1:9000/mcp \
  -H 'content-type: application/json' \
  -H 'X-Tenant-Id: Bearer <tenant licence>' \
  -H 'X-MCP-Binding: <binding token>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

The response is the binding's catalog page; pass the cursor from one page to fetch the next.
Off-cluster, the same licence may be sent as `Authorization: Bearer` instead of
`X-Tenant-Id`.

The OpenAPI document needs no configuration and no database:

```bash
./target/debug/mcp-server-rs --print-openapi
```

## Configuration

Nothing has a default port, and the server refuses to start without `DATABASE_URL` and
`BIND_ADDR`. The full set is documented in `src/config.rs`; worker-only settings use the
`MCP_WORKER_*`, `MCP_QUEUE_*`, `MCP_RUN_*` and `MCP_EXECUTION_*` prefixes.

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | required | Runtime connection pool (usually through PgBouncer). |
| `BIND_ADDR` | required | API listen address, for example `127.0.0.1:9000`. |
| `DATABASE_MIGRATE_URL` | unset | Direct Postgres URL for migrations; unset means migrate over `DATABASE_URL`. |
| `EXECUTION_ENABLED` | `false` | Whether this build may run tools. `MCP_EXECUTION_ENABLED` is accepted as an alias; the unprefixed name wins. |
| `PLATFORM_TENANT_ID` | built-in reserved id | The platform tenant that owns platform toolkits. |
| `CATALOG_PAGE_SIZE` | `10` | Page bound for `tools/list` and the catalog projection (1–100). |
| `MCP_APPROVED_RUNNER_IMAGES` | empty | JSON list of approved runner image digests; any other digest is refused. |
| `MCP_TASKS_ENABLED` | `false` | Serve the `io.modelcontextprotocol/tasks` extension. |
| `LICENSE_INTROSPECT_URL` | unset | Licence authority introspection endpoint. Unset means every presented credential is rejected (fail closed, 503). |
| `MCP_LICENSE_APP_KEY` | unset | The application key an introspected licence must name. |
| `MCP_LICENSE_ALLOW_HTTP` | `false` | Permit an `http://` introspection URL (in-cluster only). |
| `MCP_LICENSE_TIMEOUT_SECONDS` | `3` | Bound on one introspection call. |
| `MCP_ADMIN_KEY_FILE` | unset | Mounted operator key file for management authentication. |
| `MCP_ADMIN_TENANT_IDS` | empty | Tenant ids whose licences may use management authentication. |
| `MCP_LICENCE_MINTER_ENABLED` | `false` | Mint per-tenant broker credentials from licences. |
| `MCP_QUEUE_GLOBAL_MAX` | `100` | Queued runs across all tenants. |
| `MCP_QUEUE_PER_TENANT_MAX` | `20` | Queued runs per tenant. |
| `MCP_EXECUTION_GLOBAL_SLOTS` | `1` | Runner slots across all tenants. |
| `MCP_EXECUTION_PER_TENANT_SLOTS` | `1` | Runner slots per tenant. |
| `MCP_RUN_NAMESPACE` | `mcp-runs` | Namespace the worker creates runner pods in. |

Secrets — the admin key, the credential bundle, the licence-minter client secret and the source
encryption key — are read from mounted files or dedicated variables, never from this table.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo nextest run --locked          # or: cargo test --locked
cargo test --doc --locked
cargo audit
```

There are 24 integration-test files under `tests/`. Database tests select a server from
`TEST_DATABASE_URL`, else `DATABASE_URL`, else an ephemeral `postgres:18` container started
with Docker, else they fail — never skip. Each test gets its own fresh database. Runtime
`DATABASE_URL` is not used by the test harness when `TEST_DATABASE_URL` is set.

## Parity

`parity.toml` pins the Python reference at a public archived commit and defines the contract
used by the schema and OpenAPI diff gates. The OpenAPI diff is `equal` only when the reviewed
exclusions in `parity.toml` apply **and** nothing else differs, so the contract can only get
stricter. The exclusion list is **empty**: every operation the pinned source serves is served by
this service (`equal true · matched 108 · missing 0 · extra 0 · changed 0 · ignored 0`), so the
contract now guards against regression rather than tracking what is left to port;
`parity/README.md` records the evidence and the commands that produced it.

## CI

`.github/workflows/ci-public.yml` is self-contained and runs on GitHub-hosted runners: a secret
scan, a private-reference scan, `cargo fmt` / `clippy -D warnings` / `nextest` + doctests /
`cargo audit` against a disposable PostgreSQL 18, and a Docker image build. From `main`, and
only when the repository variable `PUBLISH_IMAGE` is `true`, the image is pushed to
`ghcr.io/nonagenticai/mcp-server-rs`.

The workflow does not call a private reusable workflow or use self-hosted runners: a public
repository cannot read a private reusable workflow, and a fork PR can edit `runs-on`, so a
self-hosted runner would execute untrusted code inside the estate network.

## Licensing

The code in this repository is Apache-2.0 and needs no licence key to build, test or run:
`--print-openapi`, the health endpoints and the migrations all work with no licence
infrastructure. Licence **authentication** for `/mcp` is implemented, not enforced
unconditionally:

- `LICENSE_INTROSPECT_URL` (no default) and `MCP_LICENSE_APP_KEY` (no default) configure the
  authority call: `POST {"token": ..., "app": ...}` to the licences service. Unset means the
  built-in `UnconfiguredLicenceAuthority`, which rejects every credential with 503 — the process
  starts and health works, but protected `/mcp` work stays disabled.
- `MCP_LICENCE_MINTER_ENABLED` (default `false`) optionally mints per-tenant broker credentials
  from the same licence authority.

The platform's licence gate is optional and lives in two separate public repositories —
[`licenses`](https://github.com/nonagenticai/licenses) (entitlements, plans and tokens) and
[`license-authz`](https://github.com/nonagenticai/license-authz) (the Envoy `ext_authz`
enforcement point). Nothing in this repository requires either of them.

## Security

Report vulnerabilities privately through the repository's Security tab — see the
organisation-wide [`SECURITY.md`](https://github.com/nonagenticai/.github/blob/main/SECURITY.md).
Do not open a public issue for a security problem.

## Contributing

Issues and pull requests are welcome. See
[`CONTRIBUTING.md`](https://github.com/nonagenticai/.github/blob/main/CONTRIBUTING.md) for the
organisation-wide rules; this repository's own commands are in **Development** above.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
