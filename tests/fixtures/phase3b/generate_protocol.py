#!/usr/bin/env python3
"""Generate ``protocol.json``: the golden fixtures for runner wire protocol v1.

The oracle is the pinned Python service's ``runner/protocol.py`` (commit 22ac1ce4). Every
case below is *executed* against that module and the outcome recorded verbatim, so a Rust
test replaying this file replays the Python implementation rather than a paraphrase of it.

Usage (Python standard library only; no project environment, no Cargo):

    ORACLE=/path/to/nonagenticai_mcp_server-python-archive \
        python3 -I tests/fixtures/phase3b/generate_protocol.py

``-I`` isolates the interpreter from the caller's environment (an interpreter also loads
modules from its script directory, so isolation keeps a planted ``json.py`` out of the
run); the archive is put on ``sys.path`` explicitly. The committed ``protocol.json`` is the
oracle read by ``tests/worker_protocol.rs`` at test runtime — nothing here is imported then.

Two oracle behaviours shape the fixture and are worth stating up front, because they are
easy to mistake for a Rust-side simplification:

* ``decode`` catches ``ProtocolError`` (a ``ValueError`` subclass) around both ``json.loads``
  and ``validate`` and re-raises it as ``ProtocolError("invalid frame")``. The specific
  messages that ``validate`` produces — ``duplicate field``, ``nonfinite JSON``,
  ``JSON complexity``, ``invalid sequence`` and so on — are therefore *unobservable through
  ``decode``*; a refused frame is ``invalid frame`` unless the size/boundary check failed
  first. ``encode`` calls ``validate`` outside any handler, so the specific messages are
  observable there. The fixture records exactly what each entry point emits.
* A frame's JSON object order is the sender's insertion order, and a Rust ``serde_json::Map``
  is a ``BTreeMap``. Byte equality is therefore asserted after *compact normalisation*
  (parse, then re-serialise compactly), which is key-order and number-spelling insensitive
  but value-exact.
"""

import json
import os
import sys

DEFAULT_ORACLE = "/Users/georgedekker/Movies/nonagenticai/nonagenticai_mcp_server-python-archive"
ORACLE = os.environ.get("ORACLE", DEFAULT_ORACLE)
sys.path.insert(0, ORACLE)

from runner import protocol as oracle  # noqa: E402

PIN = "22ac1ce4d1b8129a543832b8ed86fe0e1c0c7fe4"

# A UUIDv7 (the only operation identity the protocol accepts) and a UUIDv4 (never accepted).
V7 = "0190a0b0-0000-7000-8000-000000000000"
V4 = "550e8400-e29b-41d4-a716-446655440000"

CASES = []
DECODER_CASES = []


# --------------------------------------------------------------------------------------------
# Fixture helpers
# --------------------------------------------------------------------------------------------


def expected_frame(frame):
    """The frame as the Rust ``Frame`` represents it.

    ``idempotency_key`` is the one optional field, and Python distinguishes "absent" from
    "explicit null" while ``Option<String>`` does not: both decode to ``None`` and encode to
    "absent". Expected frames therefore drop the key when it is null. (The wire cases keep
    both spellings, because the receiver must accept both — the Python SDK always sends
    ``"idempotency_key": null``.)
    """
    copy = dict(frame)
    if copy.get("idempotency_key", 0) is None:
        del copy["idempotency_key"]
    return copy


def wire_fields(data):
    text = data[:-1] if data.endswith(b"\n") else data
    # Both branches carry the same convention: the frame text *without* its trailing
    # newline; `terminated` says whether the case supplies one.
    try:
        return {"wire_json": text.decode("utf-8"), "terminated": data.endswith(b"\n")}
    except UnicodeDecodeError:
        return {"wire_hex": text.hex(), "terminated": data.endswith(b"\n")}


def encode_case(name, frame, maximum=65536):
    try:
        data = oracle.encode(frame, maximum)
    except oracle.ProtocolError as exc:
        CASES.append(
            {
                "name": name,
                "direction": "encode",
                "frame": frame,
                "maximum": maximum,
                "ok": False,
                "error": str(exc),
            }
        )
        return
    assert data.endswith(b"\n") and b"\n" not in data[:-1], name
    assert len(data) <= maximum, name
    assert oracle.decode(data, maximum) is not None, name
    CASES.append(
        {
            "name": name,
            "direction": "encode",
            "frame": frame,
            "maximum": maximum,
            "ok": True,
            "wire_json": data[:-1].decode("utf-8"),
        }
    )


def encode_at_maximum_case(name, frame):
    """The exact-length encoding: ``len(wire) == maximum`` must still be accepted."""
    data = oracle.encode(frame, 65536)
    encode_case(name, frame, len(data))


def decode_case(name, data, maximum=65536):
    try:
        frame = oracle.decode(data, maximum)
    except oracle.ProtocolError as exc:
        CASES.append(
            {
                "name": name,
                "direction": "decode",
                "maximum": maximum,
                "ok": False,
                "error": str(exc),
                **wire_fields(data),
            }
        )
        return
    CASES.append(
        {
            "name": name,
            "direction": "decode",
            "frame": expected_frame(frame),
            "maximum": maximum,
            "ok": True,
            **wire_fields(data),
        }
    )


def decoder_case(name, frame_bytes, total_bytes, max_frames, chunks):
    decoder = oracle.Decoder(frame_bytes, total_bytes, max_frames)
    frames = []
    try:
        for chunk in chunks:
            frames.extend(decoder.feed(chunk))
    except oracle.ProtocolError as exc:
        DECODER_CASES.append(
            {
                "name": name,
                "decoder": {
                    "frame_bytes": frame_bytes,
                    "total_bytes": total_bytes,
                    "max_frames": max_frames,
                },
                "chunks_hex": [chunk.hex() for chunk in chunks],
                "ok": False,
                "error": str(exc),
                # Python's decoder raises with the stream state as it stood: an aggregate
                # bound fails before the chunk is buffered, a frame bound fails with the
                # frame still buffered.
                "buffer_empty": decoder.buffer == b"",
            }
        )
        return
    DECODER_CASES.append(
        {
            "name": name,
            "decoder": {
                "frame_bytes": frame_bytes,
                "total_bytes": total_bytes,
                "max_frames": max_frames,
            },
            "chunks_hex": [chunk.hex() for chunk in chunks],
            "ok": True,
            "frames": [expected_frame(frame) for frame in frames],
            "buffer_empty": decoder.buffer == b"",
        }
    )


def nest(levels, inner=0):
    value = inner
    for _ in range(levels):
        value = [value]
    return value


def node_count(value):
    """The oracle's ``json_value`` budget: every JSON value, root included, keys excluded."""
    if isinstance(value, dict):
        return 1 + sum(node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(node_count(item) for item in value)
    return 1


def frame_with_nodes(count, type_name="result"):
    """A ``result`` frame whose JSON tree has exactly ``count`` values (budget boundary cases)."""
    payload = count - 3  # the frame object, its "type" string and the "result" array
    assert payload > 0 and node_count({"type": type_name, "result": [0] * payload}) == count
    return {"type": type_name, "result": [0] * payload}


def wire(frame):
    """A frame the oracle *accepts*, serialised by the oracle's own encoder."""
    return oracle.encode(frame, 65536)


def raw(frame):
    """A frame the oracle must *refuse*: plain JSON text, never passed through ``encode``.

    ``encode`` validates, so it cannot be used to produce the malformed frames ``decode``
    is meant to reject — the bytes have to be written by hand. Key order is the dict's
    insertion order, which is irrelevant: the frame is refused either way.
    """
    return json.dumps(frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode() + b"\n"


# --------------------------------------------------------------------------------------------
# Frames used by more than one case
# --------------------------------------------------------------------------------------------


def init_frame():
    return {
        "type": "init",
        "protocol": 1,
        "files": [
            {"path": "tool/__init__.py", "content": ""},
            {
                "path": "tool/run.py",
                "content": "from runner.sdk import API\n\n\ndef run(context, api):\n    return {'ok': True}\n",
            },
        ],
        "digest": "0123456789abcdef" * 4,
        "entrypoint": "tool.run:run",
        "inputs": {
            "record": {
                "id": "r-1",
                "tags": ["a", "b"],
                "active": True,
                "score": 1.5,
                "note": None,
                "label": "café ☕ 🙂",
            }
        },
        "context": {"project_id": V7},
        "limits": {"frame_bytes": 65536, "init_bytes": 8388608},
    }


def api_call_frame(**overrides):
    frame = {
        "type": "api_call",
        "sequence": 1,
        "operation_id": V7,
        "arguments": {"record": "r-1", "limit": 5, "nested": {"deep": [1, 2, None, True]}},
    }
    frame.update(overrides)
    return frame


def api_result_frame(**overrides):
    frame = {
        "type": "api_result",
        "sequence": 3,
        "result": {"records": [{"id": "r-1", "token": "x"}]},
        "error": None,
    }
    frame.update(overrides)
    return frame


def result_frame(value):
    return {"type": "result", "result": value}


# --------------------------------------------------------------------------------------------
# Encode: every frame type, and every refusal reachable through a typed frame
# --------------------------------------------------------------------------------------------

encode_case("encode_init", init_frame())
encode_case("encode_ready", {"type": "ready", "protocol": 1})
encode_case("encode_api_call_with_idempotency", api_call_frame(idempotency_key="run-1:call.2"))
encode_case("encode_api_call_without_idempotency", api_call_frame())
encode_case("encode_api_result_ok", api_result_frame())
encode_case(
    "encode_api_result_denied",
    api_result_frame(result=None, error={"code": "api_call_denied"}),
)
encode_case(
    "encode_api_result_http_status_object_body",
    api_result_frame(result=None, error={"code": "http_status", "status": 429, "body": {"error": "rate"}}),
)
encode_case(
    "encode_api_result_http_status_array_body",
    api_result_frame(result=None, error={"code": "http_status", "status": 404, "body": [1, "two"]}),
)
encode_case(
    "encode_api_result_http_status_null_body",
    api_result_frame(result=None, error={"code": "http_status", "status": 400, "body": None}),
)
encode_case("encode_result_unicode", result_frame({"ok": True, "message": "café ☕ 🙂 / descartes"}))
encode_case("encode_error", {"type": "error", "code": "tool_failed"})
encode_case("encode_log_max_message", {"type": "log", "message": "é" * 4096})
encode_case("encode_cancel", {"type": "cancel"})
encode_case("encode_result_depth_32", result_frame(nest(31)))
encode_case("encode_result_nodes_ok", frame_with_nodes(10000))
encode_case("encode_result_nodes_refused", frame_with_nodes(10001))
encode_at_maximum_case("encode_at_maximum", {"type": "cancel"})

encode_case("encode_refused_protocol_2", {"type": "ready", "protocol": 2})
encode_case("encode_refused_init_protocol_0", dict(init_frame(), protocol=0))
encode_case("encode_refused_sequence_zero", api_call_frame(sequence=0))
encode_case("encode_refused_sequence_101", api_call_frame(sequence=101))
encode_case("encode_refused_operation_id_v4", api_call_frame(operation_id=V4))
encode_case("encode_refused_operation_id_text", api_call_frame(operation_id="bad"))
encode_case("encode_refused_idempotency_key_chars", api_call_frame(idempotency_key="bad key!"))
encode_case("encode_refused_idempotency_key_long", api_call_frame(idempotency_key="a" * 129))
encode_case("encode_refused_log_8193", {"type": "log", "message": "a" * 8193})
encode_case("encode_refused_error_code", {"type": "error", "code": "Raw Secret"})
encode_case(
    "encode_refused_api_error_secret",
    api_result_frame(result=None, error={"code": "secret"}),
)
encode_case(
    "encode_refused_api_error_status_500",
    api_result_frame(result=None, error={"code": "http_status", "status": 500, "body": {}}),
)
encode_case(
    "encode_refused_api_error_status_bool",
    api_result_frame(result=None, error={"code": "http_status", "status": True, "body": None}),
)
encode_case(
    "encode_refused_api_error_body_string",
    api_result_frame(result=None, error={"code": "http_status", "status": 400, "body": "x"}),
)
encode_case("encode_refused_frame_too_large", result_frame("x" * 100), maximum=10)
encode_case("encode_refused_json_complexity_depth", result_frame(nest(32)))

# --------------------------------------------------------------------------------------------
# Decode: accepted frames (every frame type, plus the spellings the runner really sends)
# --------------------------------------------------------------------------------------------

decode_case("decode_init", wire(init_frame()))
decode_case("decode_ready", b'{"type":"ready","protocol":1}\n')
decode_case("decode_api_call_without_key", wire(api_call_frame()))
decode_case(
    "decode_api_call_explicit_null_key",
    wire(api_call_frame(idempotency_key=None)),
)
decode_case("decode_api_call_braced_operation_id", wire(api_call_frame(operation_id="{%s}" % V7)))
decode_case("decode_api_call_simple_operation_id", wire(api_call_frame(operation_id=V7.replace("-", ""))))
decode_case("decode_api_call_urn_operation_id", wire(api_call_frame(operation_id="urn:uuid:%s" % V7)))
decode_case("decode_api_result_ok", wire(api_result_frame()))
decode_case(
    "decode_api_result_denied",
    wire(api_result_frame(result=None, error={"code": "api_call_denied"})),
)
decode_case("decode_result_unicode", wire(result_frame({"ok": True, "message": "café ☕ 🙂"})))
decode_case("decode_result_escaped", b'{"type":"result","result":"caf\\u00e9 \\ud83d\\ude42 \\n\\"quoted\\""}\n')
decode_case("decode_error", b'{"type":"error","code":"tool_failed"}\n')
decode_case("decode_log_max_message", wire({"type": "log", "message": "é" * 4096}))
decode_case("decode_cancel", b'{"type":"cancel"}\n')
decode_case("decode_whitespace_padded", b'  \t{"type":"cancel"}  \n')
decode_case("decode_crlf", b'{"type":"cancel"}\r\n')
decode_case("decode_result_depth_32", wire(result_frame(nest(31))))
decode_case("decode_result_nodes_ok", wire(frame_with_nodes(10000)))
decode_case(
    "decode_negative_zero_float",
    b'{"type":"result","result":{"z":-0.0,"f":1.0,"i":1}}\n',
)

# --------------------------------------------------------------------------------------------
# Decode: refusals. Everything that parses or validates after the boundary check is
# "invalid frame"; the boundary/size check is "invalid frame size or boundary".
# --------------------------------------------------------------------------------------------

decode_case("decode_refused_duplicate_key_top", b'{"type":"ready","protocol":1,"protocol":1}\n')
decode_case("decode_refused_duplicate_key_nested", b'{"type":"result","result":{"a":1,"a":2}}\n')
decode_case(
    "decode_refused_duplicate_key_deep",
    b'{"type":"result","result":{"a":[{"b":1,"b":2}]}}\n',
)
decode_case("decode_refused_nonfinite_nan", b'{"type":"result","result":NaN}\n')
decode_case("decode_refused_nonfinite_infinity", b'{"type":"result","result":Infinity}\n')
decode_case("decode_refused_nonfinite_negative", b'{"type":"result","result":-Infinity}\n')
decode_case("decode_refused_depth_33", raw(result_frame(nest(32))))
decode_case("decode_refused_nodes_10001", raw(frame_with_nodes(10001)))
decode_case("decode_refused_unknown_frame", b'{"type":"unknown"}\n')
decode_case("decode_refused_empty_object", b"{}\n")
decode_case("decode_refused_array_top_level", b"[]\n")
decode_case("decode_refused_null_top_level", b"null\n")
decode_case("decode_refused_missing_field", b'{"type":"ready"}\n')
decode_case("decode_refused_extra_field", b'{"type":"ready","protocol":1,"tenant_id":"forged"}\n')
decode_case(
    "decode_refused_init_wrong_type",
    b'{"type":"init","protocol":1,"files":{},"digest":"x","entrypoint":"x","inputs":{},"context":{},"limits":{}}\n',
)
decode_case(
    "decode_refused_init_missing_digest",
    b'{"type":"init","protocol":1,"files":[],"entrypoint":"x","inputs":{},"context":{},"limits":{}}\n',
)
decode_case("decode_refused_protocol_true", b'{"type":"ready","protocol":true}\n')
decode_case("decode_refused_protocol_float", b'{"type":"ready","protocol":1.0}\n')
decode_case("decode_refused_protocol_2", b'{"type":"ready","protocol":2}\n')
decode_case("decode_refused_sequence_zero", raw(api_call_frame(sequence=0)))
decode_case("decode_refused_sequence_101", raw(api_call_frame(sequence=101)))
decode_case("decode_refused_sequence_bool", b'{"type":"api_call","sequence":true,"operation_id":"%s","arguments":{}}\n' % V7.encode())
decode_case("decode_refused_sequence_float", b'{"type":"api_call","sequence":1.0,"operation_id":"%s","arguments":{}}\n' % V7.encode())
decode_case(
    "decode_refused_api_call_arguments_array",
    b'{"type":"api_call","sequence":1,"operation_id":"%s","arguments":[]}\n' % V7.encode(),
)
decode_case("decode_refused_operation_id_v4", raw(api_call_frame(operation_id=V4)))
decode_case("decode_refused_operation_id_text", raw(api_call_frame(operation_id="bad")))
decode_case(
    "decode_refused_operation_id_variant",
    raw(api_call_frame(operation_id="0190a0b0-0000-7000-0000-000000000000")),
)
decode_case(
    "decode_refused_operation_id_uppercase_urn",
    raw(api_call_frame(operation_id="URN:UUID:%s" % V7)),
)
decode_case("decode_refused_operation_id_v1", raw(api_call_frame(operation_id="0f8fad5b-d9cb-469f-a165-70867728950e")))
decode_case("decode_refused_idempotency_key_chars", raw(api_call_frame(idempotency_key="bad key!")))
decode_case("decode_refused_idempotency_key_long", raw(api_call_frame(idempotency_key="a" * 129)))
decode_case("decode_refused_idempotency_key_type", raw(api_call_frame(idempotency_key=1)))
decode_case("decode_refused_log_non_string", b'{"type":"log","message":1}\n')
decode_case("decode_refused_log_8193", raw({"type": "log", "message": "a" * 8193}))
decode_case(
    "decode_refused_api_result_error_secret",
    raw(api_result_frame(result=None, error={"code": "secret"})),
)
decode_case(
    "decode_refused_api_result_status_500",
    raw(api_result_frame(result=None, error={"code": "http_status", "status": 500, "body": {}})),
)
decode_case(
    "decode_refused_api_result_status_bool",
    raw(api_result_frame(result=None, error={"code": "http_status", "status": True, "body": {}})),
)
decode_case(
    "decode_refused_api_result_body_string",
    raw(api_result_frame(result=None, error={"code": "http_status", "status": 400, "body": "x"})),
)
decode_case(
    "decode_refused_api_result_extra_error_key",
    raw(
        api_result_frame(
            result=None, error={"code": "api_call_denied", "status": 400, "body": None}
        )
    ),
)
decode_case("decode_refused_error_code_uppercase", b'{"type":"error","code":"Raw Secret"}\n')
decode_case("decode_refused_error_code_long", raw({"type": "error", "code": "a" * 65}))
decode_case("decode_refused_invalid_json", b"not json\n")
decode_case("decode_refused_trailing_text", b'{"type":"cancel"} x\n')
decode_case("decode_refused_invalid_utf8", b"\xff\n")
decode_case("decode_refused_empty_line", b"\n")
decode_case("decode_refused_boundary_no_newline", b'{"type":"cancel"}')
decode_case("decode_refused_boundary_newline_inside", b'{"type":"cancel"}\n\n')
decode_case("decode_refused_boundary_two_frames", b'{}\n{}\n')
decode_case("decode_refused_oversized", b'{"type":"cancel"}\n', maximum=17)
decode_at_maximum = b'{"type":"cancel"}\n'
decode_case("decode_accepted_at_maximum", decode_at_maximum, maximum=len(decode_at_maximum))

# --------------------------------------------------------------------------------------------
# Decoder: chunked accumulation, the three stream bounds, and a whole frame in one feed
# --------------------------------------------------------------------------------------------

unicode_frame = wire(result_frame("café ☕"))
decoder_case(
    "decoder_byte_at_a_time",
    65536,
    65536,
    2,
    [bytes([byte]) for byte in unicode_frame],
)
decoder_case(
    "decoder_two_frames_one_chunk",
    65536,
    65536,
    2,
    [b'{"type":"cancel"}\n{"type":"ready","protocol":1}\n'],
)
decoder_case(
    "decoder_split_frame",
    65536,
    65536,
    2,
    [b'{"type":"can', b'cel"}\n{"type":"ready"', b',"protocol":1}\n'],
)
decoder_case(
    "decoder_frame_count",
    65536,
    65536,
    1,
    [b'{"type":"cancel"}\n{"type":"cancel"}\n'],
)
decoder_case("decoder_output_limit", 100, 2, 2, [b"xxx"])
decoder_case("decoder_output_limit_across_feeds", 100, 3, 2, [b"{}", b"{}"])
decoder_case("decoder_unterminated_frame", 10, 100, 2, [b"x" * 10])
decoder_case("decoder_frame_too_large", 5, 100, 5, [b'{"type":"cancel"}\n'])
decoder_case(
    "decoder_invalid_second_frame",
    65536,
    65536,
    5,
    [b'{"type":"cancel"}\nnot json\n'],
)
decoder_case(
    "decoder_total_exact",
    65536,
    18,
    1,
    [b'{"type":"cancel"}\n'],
)


# --------------------------------------------------------------------------------------------
# Emit
# --------------------------------------------------------------------------------------------


def main():
    payload = {
        "source": "nonagenticai_mcp_server-python-archive",
        "pin": PIN,
        "version": oracle.VERSION,
        "oracle": "runner/protocol.py",
    }
    rendered = "{\n"
    rendered += '  "source": %s,\n' % json.dumps(payload["source"])
    rendered += '  "pin": %s,\n' % json.dumps(payload["pin"])
    rendered += '  "version": %d,\n' % payload["version"]
    rendered += '  "oracle": %s,\n' % json.dumps(payload["oracle"])
    rendered += '  "cases": [\n'
    rendered += ",\n".join(
        "    " + json.dumps(case, ensure_ascii=False, separators=(",", ":")) for case in CASES
    )
    rendered += "\n  ],\n"
    rendered += '  "decoder_cases": [\n'
    rendered += ",\n".join(
        "    " + json.dumps(case, ensure_ascii=False, separators=(",", ":"))
        for case in DECODER_CASES
    )
    rendered += "\n  ]\n}\n"
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protocol.json")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    accepted = sum(1 for case in CASES if case["ok"])
    refused = len(CASES) - accepted
    print(
        "%s: %d cases (%d accepted, %d refused), %d decoder cases"
        % (target, len(CASES), accepted, refused, len(DECODER_CASES))
    )


if __name__ == "__main__":
    main()
