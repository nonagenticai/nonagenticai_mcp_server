# Parity contract — evidence

`parity.toml` pins the source: `nonagenticai/nonagenticai_mcp_server-python-archive` @
`22ac1ce` (108 OpenAPI operations). The source is frozen for the life of the port — security
fixes only — so the pinned SHA stays the oracle.

_Repointed 2026-11-14:_ the contract originally pinned the private pre-scrub SHA `dd2cabf`.
The public archive's tip emits a byte-for-byte identical OpenAPI document (`cmp`-clean, both
77,612 bytes), so the oracle moved to the public repository: it can now be fetched and replayed
by anyone, and no private repository path appears in this tree.

The two network gates use **coding-testing's own implementation**
(`services/schema_parity.py`, `services/openapi_diff.py`, reachable as
`PYTHONPATH=<coding-testing>/src`), which is what the deployed `/api/parity/*` routes run.
`parity/tools/` holds the two runners; the verdict is computed, never judged.

## 1. schema-diff — PASS

Source = the live database (read-only, direct to the primary — never through pgbouncer), the
one the Python reference's migrations built and the Rust migrator adopted. Target = a fresh
`postgres:18` with this repo's migrations applied.

```sh
SRC_DSN=postgresql://... PYTHONPATH=<coding-testing>/src \
  python parity/tools/schema_diff.py \
    --target-dsn postgresql://postgres:...@127.0.0.1:<port>/target --ignore-kind grant
```

```
computed=true  equal=true  vacuous=false
missing 0 · extra 0 · changed 0 · column_order 0 · source_conflicts 0
```

`grant` is the one excluded kind, deliberately: `migrations/0001_baseline.sql` is
`pg_dump --schema-only --no-owner --no-privileges`, while the executor/platform grants are
provisioned by the deploy path and already exist on the live database. Nothing else is
excluded. The dump also round-trips through `sqlx`'s migrator in `tests/db.rs`.

## 2. openapi-diff — PASS

```sh
# source document (no env, no database: the app object generates it)
(cd nonagenticai_mcp_server-python-archive && uv run --frozen python -c \
   'import json; from src.asgi import create_app; print(json.dumps(create_app().openapi()))') \
  > source.openapi.json
# target document
<the built binary> --print-openapi > target.openapi.json
# diff, exclusions read from parity.toml
PYTHONPATH=<coding-testing>/src python parity/tools/openapi_diff.py \
  --source-spec source.openapi.json --target-spec target.openapi.json --parity-toml parity.toml
```

```
equal=true  vacuous=false  matched 108/108
missing 0 · extra 0 · changed 0 · cosmetic 0 · source_conflicts 0 · ignored 0
```

All 108 source operations are served, so the ignore list is empty (landed 2026-11-15: phase
5A, phase 5B, the builtin surface and the phase-6 fr channel). The contract now guards against
regression: a missing, extra or changed operation fails the diff with no exclusion to hide
behind.

_Inline `$defs` (2026-11-14)._ The runner inlines each operation's local `$defs` before the diff.
The reference embeds pydantic's `model_json_schema()` in a request body, where `$id` gives the
embedded schema its own resource root and `$defs` holds what its `#/$defs/...` references point
at; the normaliser resolves every `$ref` against the document root, so those references are
unresolvable — the source document does not diff against **itself** on `POST /mcp/tools`
(`#/$defs/ToolManifest`). Inlining produces the schema the normaliser would compute under correct
`$id` scoping, so the verdict stays semantic. Measured after the change: the source self-diff of
`POST /mcp/tools` and `POST /mcp/tools/{identity}/versions` is `equal`, and the committed baseline
above is unchanged.


## 3. MCP transport — PASS

`tests/http.rs::mcp_initialize_negotiates_a_protocol_version` asserts the **exact** `initialize`
envelope captured from the source's own fastmcp transport
(`http_app(path="/", stateless_http=True, json_response=False)`):

```json
{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},
 "serverInfo":{"name":"Executable catalog","version":"2.0.0"}}
```

Both that test and the `tools/list` tests assert the response is SSE-framed
(`text/event-stream`), not plain JSON.

`tools/list` is served from the catalog projection for a binding principal
(`tests/http.rs`, over the real router and a real Postgres binding) and from the builtin
provider for a licence caller with no binding (`tests/builtin_provider.rs`); the 34 first-party
tools' names, scopes, descriptions and input schemas are the reference's own `tools/list`
output, captured in `tests/fixtures/builtin/oracle.json`. A member's per-login care-bus licence
authenticates and gets an **empty** listing, every call denied — the reference's own rule.

_Phase 1 note:_ the middleware's 401 body is `{"error":"unauthorized"}`, not FastAPI's
`{"detail": …}` that the template's `AppError` renders.
