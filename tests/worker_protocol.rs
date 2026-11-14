//! Golden replay of runner protocol v1 against the pinned Python oracle.
//!
//! `tests/fixtures/phase3b/protocol.json` is produced by *executing* the archive's
//! `runner/protocol.py` (commit `22ac1ce4`) — `generate_protocol.py` beside it is the
//! generator. The JSON is committed, so this test never touches the archive: the fixture
//! **is** the oracle, and a change to it is a protocol change that must be justified
//! against the Python source.
//!
//! Three fixture conventions this file honours:
//!
//! * `wire_json` is the frame text without its trailing `\n` (which the test appends);
//!   `terminated: false` marks the case that deliberately omits the newline. `wire_hex`
//!   carries bytes that are not valid UTF-8.
//! * An accepted encode case is compared after *compact normalisation* — parse, then
//!   re-serialise compactly — which is value equality with key order and number spelling
//!   normalised. The two sides legitimately differ there: Python preserves dict insertion
//!   order and spells floats with `repr`, `serde_json` sorts keys (a `BTreeMap`) and spells
//!   floats with `ryu`. Everything else, including UTF-8 escaping, must agree.
//! * A refused case compares the exact `Display` string. The oracle's `decode` catches its
//!   own `ProtocolError` and re-raises `invalid frame`, so the specific rule below a
//!   refusal (`duplicate field`, `JSON complexity`, `invalid sequence`, …) is not visible
//!   through `decode`; only the size/newline pre-check keeps its own message. `encode`
//!   validates outside any handler and therefore does report the specific messages.

use mcp_server_rs::worker::protocol::{Decoder, Frame, VERSION, decode, encode};
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/phase3b/protocol.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the fixture parses")
}

/// Parse and re-serialise compactly: key-order and number-spelling insensitive, value-exact.
fn compact(bytes: &[u8]) -> String {
    serde_json::to_string(&serde_json::from_slice::<Value>(bytes).expect("a JSON value"))
        .expect("serialisable")
}

fn compact_value(value: &Value) -> String {
    serde_json::to_string(value).expect("serialisable")
}

fn maximum(case: &Value) -> usize {
    usize::try_from(case["maximum"].as_u64().expect("a maximum")).expect("fits in usize")
}

fn name(case: &Value) -> &str {
    case["name"].as_str().expect("a case name")
}

fn expected_frame(case: &Value) -> Frame {
    Frame::from_value(case["frame"].clone())
        .unwrap_or_else(|error| panic!("case {}: {error}", name(case)))
}

/// The exact bytes a decode case feeds to the wire, including its trailing newline decision.
fn case_wire(case: &Value) -> Vec<u8> {
    let mut bytes = match (case.get("wire_hex"), case.get("wire_json")) {
        (Some(encoded), _) => {
            hex::decode(encoded.as_str().expect("hex text")).expect("hex decodes")
        }
        (None, Some(text)) => text.as_str().expect("wire text").as_bytes().to_vec(),
        _ => panic!("case {} carries no wire", name(case)),
    };
    if case
        .get("terminated")
        .and_then(Value::as_bool)
        .unwrap_or(true)
    {
        bytes.push(b'\n');
    }
    bytes
}

fn cases(direction: &str) -> Vec<Value> {
    fixture()["cases"]
        .as_array()
        .expect("a case list")
        .iter()
        .filter(|case| case["direction"].as_str() == Some(direction))
        .cloned()
        .collect()
}

#[test]
fn the_fixture_is_protocol_v1() {
    assert_eq!(VERSION, 1);
    assert_eq!(fixture()["version"].as_u64(), Some(1));
    assert_eq!(
        fixture()["pin"].as_str(),
        Some("22ac1ce4d1b8129a543832b8ed86fe0e1c0c7fe4")
    );
}

#[test]
fn encode_cases_match_the_oracle() {
    let cases = cases("encode");
    assert!(!cases.is_empty(), "the fixture has encode cases");
    for case in &cases {
        let name = name(case);
        let frame = expected_frame(case);
        let maximum = maximum(case);
        match (
            case["ok"].as_bool().expect("an ok flag"),
            encode(&frame, maximum),
        ) {
            (true, Ok(bytes)) => {
                // One frame, one line: a single trailing newline and no other.
                assert!(bytes.ends_with(b"\n"), "{name}");
                assert_eq!(
                    bytes.iter().filter(|byte| **byte == b'\n').count(),
                    1,
                    "{name}"
                );
                let wire = case["wire_json"].as_str().expect("wire_json");
                assert_eq!(compact(&bytes), compact(wire.as_bytes()), "{name}");
                // The encoder's own output must decode back to the frame it was given.
                assert_eq!(
                    decode(&bytes, maximum).unwrap_or_else(|error| panic!("{name}: {error}")),
                    frame,
                    "{name}"
                );
            }
            (true, Err(error)) => {
                panic!("{name}: the oracle accepts it, this refuses with {error}")
            }
            (false, Ok(_)) => panic!("{name}: the oracle refuses it, this accepts it"),
            (false, Err(error)) => assert_eq!(
                error.to_string(),
                case["error"].as_str().expect("an error string"),
                "{name}"
            ),
        }
    }
}

#[test]
fn decode_cases_match_the_oracle() {
    let cases = cases("decode");
    assert!(!cases.is_empty(), "the fixture has decode cases");
    for case in &cases {
        let name = name(case);
        let wire = case_wire(case);
        let maximum = maximum(case);
        match (
            case["ok"].as_bool().expect("an ok flag"),
            decode(&wire, maximum),
        ) {
            (true, Ok(frame)) => {
                assert_eq!(frame, expected_frame(case), "{name}");
                // The decoded frame, re-rendered, is the fixture's expected frame.
                assert_eq!(
                    compact_value(&frame.to_value()),
                    compact_value(&case["frame"]),
                    "{name}"
                );
            }
            (true, Err(error)) => {
                panic!("{name}: the oracle accepts it, this refuses with {error}")
            }
            (false, Ok(_)) => panic!("{name}: the oracle refuses it, this accepts it"),
            (false, Err(error)) => assert_eq!(
                error.to_string(),
                case["error"].as_str().expect("an error string"),
                "{name}"
            ),
        }
    }
}

#[test]
fn decoder_cases_match_the_oracle() {
    // Bound to a local: `fixture()[...]` would borrow a temporary that dies at the
    // statement's end, while the slice is used for the whole loop.
    let document = fixture();
    let cases = document["decoder_cases"]
        .as_array()
        .expect("a decoder case list");
    assert!(!cases.is_empty(), "the fixture has decoder cases");
    for case in cases {
        let name = name(case);
        let settings = &case["decoder"];
        let mut decoder = Decoder::new(
            usize::try_from(settings["frame_bytes"].as_u64().expect("frame_bytes")).expect("fits"),
            usize::try_from(settings["total_bytes"].as_u64().expect("total_bytes")).expect("fits"),
            usize::try_from(settings["max_frames"].as_u64().expect("max_frames")).expect("fits"),
        );
        let chunks: Vec<Vec<u8>> = case["chunks_hex"]
            .as_array()
            .expect("chunk list")
            .iter()
            .map(|chunk| hex::decode(chunk.as_str().expect("hex text")).expect("hex decodes"))
            .collect();
        let mut frames = Vec::new();
        let mut failure = None;
        for chunk in &chunks {
            match decoder.feed(chunk) {
                Ok(produced) => frames.extend(produced),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        match (case["ok"].as_bool().expect("an ok flag"), failure) {
            (true, None) => {
                let expected: Vec<Frame> = case["frames"]
                    .as_array()
                    .expect("an expected frame list")
                    .iter()
                    .cloned()
                    .map(|frame| Frame::from_value(frame).expect("an expected frame"))
                    .collect();
                assert_eq!(frames, expected, "{name}");
            }
            (true, Some(error)) => {
                panic!("{name}: the oracle accepts it, this refuses with {error}")
            }
            (false, Some(error)) => assert_eq!(
                error.to_string(),
                case["error"].as_str().expect("an error string"),
                "{name}"
            ),
            (false, None) => panic!("{name}: the oracle refuses it, this accepts it"),
        }
        // The oracle's state after the call: a bound that fails before buffering leaves the
        // buffer empty, one that fails on buffered bytes leaves the frame behind.
        assert_eq!(
            decoder.buffer_is_empty(),
            case["buffer_empty"].as_bool().expect("a buffer state"),
            "{name}"
        );
    }
}
