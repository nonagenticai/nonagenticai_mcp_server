"""Generate the phase-5A py-oracle golden fixtures from the pinned Python reference.

Run with the archive's own interpreter, archive root passed as argv[1], output path as
argv[2]: `uv run --frozen python parity/tools/gen_phase5a_fixtures.py <archive> <out>`.

Everything here is produced by the reference's own code: the guard helpers, the tenant-URL
rule and the source contracts are called directly, so a divergence in an accepted URL, a
refusal, a default or a canonical JSON body fails a Rust test instead of reaching an
upstream. Phase 5A is the platform authoring surface: sources, services, operations,
credential profiles and toolkit import.
"""

import json
import sys

ROOT = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, ROOT)

from pydantic import ValidationError  # noqa: E402

from src.sources.guard import (  # noqa: E402
    checked_base_url,
    enforce,
    host_allowed,
    is_ip_literal,
)
from src.sources.models import (  # noqa: E402
    FORBIDDEN_HEADERS,
    SECRETLESS_KINDS,
    RevisionOnly,
    SourceCreate,
    SourceUpdate,
    TokenUpdate,
    checked_tenant_url,
)

#: `checked_base_url` cases: the input and the `allow_internal_http` flag. Whether it is
#: accepted, and the refusal message, are the reference's own answers (never assumed here).
BASE_URL_CASES = [
    ("https://api.example.com", False),
    ("https://api.example.com/v1/coding", False),
    ("https://api.example.com/", False),
    ("http://api.example.com", False),
    ("http://api.example.com", True),  # allow_internal_http
    ("https://user:pw@api.example.com", False),
    ("https://api.example.com?q=1", False),
    ("https://api.example.com#frag", False),
    ("https://127.0.0.1", False),
    ("https://2130706433", False),
    ("https://0x7f.1", False),
    ("https://[::1]", False),
    ("https://api.example.com:65536", False),
    ("https://-bad.example.com", False),
    ("https://api.example.com/Coding", False),  # uppercase segment
    ("https://api.example.com/a/b", False),
    ("not a url", False),
    ("https://", False),
]

#: `host_allowed` cases: base_url and allow-list. The verdict is the reference's.
HOST_CASES = [
    ("https://api.example.com/v1", ["api.example.com"]),
    ("https://api.example.com/v1", ["API.EXAMPLE.COM"]),
    ("https://api.example.com/v1", ["*.example.com"]),
    ("https://api.example.com/v1", ["*.com"]),
    ("https://api.example.com/v1", ["example.com"]),
    ("https://api.example.com:8443/v1", ["api.example.com"]),
    ("https://api.example.com:8443/v1", ["api.example.com:8443"]),
    ("https://api.example.com:443/v1", ["api.example.com:443"]),
    ("https://api.example.com/v1", [""]),
    ("https://api.example.com/v1", []),
]

#: `is_ip_literal` cases.
IP_CASES = [
    ("127.0.0.1", True),
    ("[::1]", True),
    ("::1", True),
    ("2130706433", True),
    ("0x7f.1", True),
    ("api.example.com", False),
    ("example.1", True),  # numeric last label
    ("api.example.com2", False),
]

#: `checked_tenant_url` cases: value and the `allow_path` flag. The verdict is the reference's.
TENANT_URL_CASES = [
    ("https://api.example.com", True),
    ("https://api.example.com/a/b/", True),
    ("http://api.example.com", True),
    ("https://api.example.com", False),
    ("https://api.example.com/a", False),
    ("https://localhost", True),
    ("https://api.lan", True),
    ("https://api.svc", True),
    ("https://api.cluster.local", True),
    ("https://10.0.0.1", True),
    ("https://api", True),  # single label
    ("https://api..example.com", True),
    ("https://api.example.com/../x", True),
    ("https://api.example.com#f", True),
]

#: Source payloads: the canonical JSON of an accepted body, or the refusal message.
SOURCE_BODIES = [
    (
        "create_static_bearer",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {"kind": "static_bearer"},
            "token": "synthetic-token",
        },
    ),
    (
        "create_no_auth_no_token",
        SourceCreate,
        {"source_key": "public", "base_url": "https://api.example.com", "auth": {"kind": "none"}},
    ),
    (
        "create_licence_bearer",
        SourceCreate,
        {
            "source_key": "coding",
            "base_url": "https://api.example.com/v1",
            "auth": {"kind": "licence", "app_key": "coding"},
        },
    ),
    (
        "create_licence_header_bundle",
        SourceCreate,
        {
            "source_key": "coding",
            "base_url": "https://api.example.com/v1",
            "auth": {"kind": "licence", "app_key": "coding", "scheme": "x_tenant_id_bearer",
                     "bundle": "coding-bundle"},
        },
    ),
    (
        "create_static_header",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {"kind": "static_header", "header": "X-Api-Key"},
            "token": "synthetic-token",
        },
    ),
    (
        "create_static_header_reserved",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {"kind": "static_header", "header": "Content-Type"},
            "token": "synthetic-token",
        },
    ),
    (
        "create_query_param",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {"kind": "query_param", "param": "api_key"},
            "token": "synthetic-token",
        },
    ),
    (
        "create_basic",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {"kind": "basic", "username": "svc"},
            "token": "pa ss",
        },
    ),
    (
        "create_oauth2",
        SourceCreate,
        {
            "source_key": "billing",
            "base_url": "https://api.example.com",
            "auth": {
                "kind": "oauth2_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "scope": "read write",
                "client_auth": "post",
            },
            "token": "synthetic-token",
            "idempotency_header": "Idempotency-Key",
            "max_request_bytes": 1024,
            "max_response_bytes": 65536,
            "spec_path": "/openapi.json",
        },
    ),
    (
        "create_missing_secret",
        SourceCreate,
        {"source_key": "billing", "base_url": "https://api.example.com",
         "auth": {"kind": "static_bearer"}},
    ),
    (
        "create_secret_on_secretless",
        SourceCreate,
        {"source_key": "billing", "base_url": "https://api.example.com",
         "auth": {"kind": "none"}, "token": "x"},
    ),
    (
        "create_bad_key",
        SourceCreate,
        {"source_key": "Upper", "base_url": "https://api.example.com", "auth": {"kind": "none"}},
    ),
    (
        "create_internal_http_allowed",
        SourceCreate,
        {
            "source_key": "internal",
            "base_url": "http://api.cluster.local:8080",
            "allow_internal_http": True,
            "ca_file": "/etc/ssl/internal-ca.pem",
            "auth": {"kind": "none"},
        },
    ),
    (
        "create_bad_ca_file",
        SourceCreate,
        {
            "source_key": "internal",
            "base_url": "https://api.example.com",
            "ca_file": "relative/ca.pem",
            "auth": {"kind": "none"},
        },
    ),
    (
        "update_with_revision",
        SourceUpdate,
        {"base_url": "https://api.example.com", "auth": {"kind": "none"}, "expected_revision": 3},
    ),
    ("update_zero_revision", SourceUpdate,
     {"base_url": "https://api.example.com", "auth": {"kind": "none"}, "expected_revision": 0}),
    ("token_update", TokenUpdate, {"token": "a b c", "expected_revision": 2}),
    ("token_update_control_char", TokenUpdate, {"token": "a\tb", "expected_revision": 2}),
    ("revision_only", RevisionOnly, {"expected_revision": 1}),
    ("revision_only_missing", RevisionOnly, {}),
]

AUTH_KINDS = [
    "none",
    "licence",
    "static_bearer",
    "static_header",
    "query_param",
    "basic",
    "oauth2_client_credentials",
]


def outcome(model, body):
    """The canonical JSON of an accepted body, or the reference's first refusal message."""
    try:
        return {"ok": True, "dump": model.model_validate_json(json.dumps(body)).model_dump_json()}
    except ValidationError as error:
        return {"ok": False, "error": error.errors()[0]["msg"]}


def verdict(call):
    """Run `call` against the reference: {"ok": true} or {"ok": false, "message": ...}."""
    try:
        call()
        return {"ok": True, "message": None}
    except ValueError as error:
        return {"ok": False, "message": str(error)}


def main() -> None:
    fixtures = {
        "base_url_cases": [
            {
                "value": value,
                "allow_internal_http": allow,
                **verdict(lambda value=value, allow=allow: checked_base_url(value, allow)),
            }
            for value, allow in BASE_URL_CASES
        ],
        "host_cases": [
            {
                "base_url": url,
                "allowed": allowed,
                "ok": host_allowed(url, allowed),
            }
            for url, allowed in HOST_CASES
        ],
        "enforce_cases": [
            {
                "base_url": url,
                "allow_internal_http": False,
                "allowed": allowed,
                **verdict(lambda url=url, allowed=allowed: enforce(url, False, allowed)),
            }
            for url, allowed in HOST_CASES
        ],
        "ip_cases": [{"host": host, "ip": is_ip} for host, is_ip in IP_CASES],
        "tenant_url_cases": [
            {
                "value": value,
                "allow_path": allow_path,
                **verdict(
                    lambda value=value, allow_path=allow_path: checked_tenant_url(
                        value, allow_path=allow_path
                    )
                ),
            }
            for value, allow_path in TENANT_URL_CASES
        ],
        "auth_kinds": {
            kind: {"needs_secret": kind not in SECRETLESS_KINDS} for kind in AUTH_KINDS
        },
        "forbidden_headers": sorted(FORBIDDEN_HEADERS),
        "source_bodies": [
            {"name": name, "model": model.__name__, "body": body, **outcome(model, body)}
            for name, model, body in SOURCE_BODIES
        ],
    }
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(fixtures, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


if __name__ == "__main__":
    main()
