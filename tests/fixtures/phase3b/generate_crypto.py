#!/usr/bin/env python3
"""Generate ``crypto.json``: the golden AES-256-GCM fixture for one sealed source secret.

The oracle is the pinned Python service's ``src/sources/crypto.py`` (commit 22ac1ce4). The
ciphertext below is *produced by that module*, so a Rust test that decrypts it is reading the
Python implementation, not a paraphrase of it. The plaintext, the key and the source id are
recorded beside the ciphertext so a failure says which of the three disagrees.

Usage (the archive's project environment, not the standard library: ``crypto.py`` imports
``cryptography`` and ``pydantic``):

    ORACLE=/path/to/nonagenticai_mcp_server-python-archive \\
        /path/to/nonagenticai_mcp_server-python-archive/.venv/bin/python -I \\
        tests/fixtures/phase3b/generate_crypto.py

``-I`` isolates the interpreter from the caller's environment (an interpreter also loads
modules from its script directory, so isolation keeps a planted ``json.py`` out of the run);
the archive is put on ``sys.path`` explicitly. The committed ``crypto.json`` is the oracle read
by ``tests/worker_sources_creds.rs`` at test runtime — nothing here is imported then.

Two oracle behaviours the fixture pins down:

* The nonce is a 12-byte random prefix of the stored blob; the remainder is the AES-GCM sealing
  (ciphertext with its 16-byte tag). The fixture records ``nonce_bytes`` and the blob length so
  the Rust port's framing is checkable from the file alone.
* The associated data is the source id's 16 bytes: the same blob decrypts under the recorded id
  and *fails* under any other id. The fixture records the oracle's exception name for the
  swapped case, because that is the fail-closed rule the registry relies on.
"""

import base64
import json
import os
import sys
from uuid import UUID

DEFAULT_ORACLE = "/Users/georgedekker/Movies/nonagenticai/nonagenticai_mcp_server-python-archive"
ORACLE = os.environ.get("ORACLE", DEFAULT_ORACLE)
sys.path.insert(0, ORACLE)

from pydantic import SecretStr  # noqa: E402

from src.sources.crypto import decode_key, decrypt_token, encrypt_token  # noqa: E402

PIN = "22ac1ce4d1b8129a543832b8ed86fe0e1c0c7fe4"

#: A UUIDv7, the version `mcp_sources.source_id` is constrained to.
SOURCE_ID = "0190a0b0-0000-7000-8000-00000000c001"
#: A second UUIDv7 that never owns this ciphertext.
OTHER_SOURCE_ID = "0190a0b0-0000-7000-8000-00000000c002"
#: Printable ASCII without spaces, the stored-secret charset (`valid_secret`).
TOKEN = "python-oracle-token-0123456789"
#: A fixed 32-byte key, rendered unpadded base64url as `MCP_SOURCE_SECRET_KEY` accepts it.
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def main() -> None:
    key = SecretStr(KEY)
    source = UUID(SOURCE_ID)
    blob = encrypt_token(key, source, SecretStr(TOKEN))

    # The oracle's own reading of its own ciphertext, asserted before it is committed.
    assert decode_key(KEY) == decode_key(KEY + "=")
    assert decrypt_token(key, source, blob).get_secret_value() == TOKEN

    swapped = None
    try:
        decrypt_token(key, UUID(OTHER_SOURCE_ID), blob)
    except Exception as error:  # noqa: BLE001 - the exception type is the recorded outcome
        swapped = type(error).__name__
    assert swapped == "ExecutionDeniedError", swapped

    record = {
        "source": "nonagenticai_mcp_server-python-archive",
        "pin": PIN,
        "generated_from": "src/sources/crypto.py (encrypt_token, decrypt_token, decode_key)",
        "key": KEY,
        "key_padded": KEY + "=",
        "source_id": SOURCE_ID,
        "wrong_source_id": OTHER_SOURCE_ID,
        "token": TOKEN,
        "nonce_bytes": 12,
        "ciphertext": base64.b64encode(blob).decode("ascii"),
        "oracle": {
            "decrypt": TOKEN,
            "swapped_source_id": swapped,
        },
    }
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto.json")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"{target}: {len(blob)}-byte blob for {SOURCE_ID}")


if __name__ == "__main__":
    main()
