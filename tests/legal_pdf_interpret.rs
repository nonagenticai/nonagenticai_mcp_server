//! The interpreter gate: from the fixture PDF's bytes, this port must produce the visitor
//! stream pypdf 6.21.4 hands the reference — record for record, text and matrices exactly —
//! and then the reference's text byte for byte.
//!
//! `tests/fixtures/legal_pdf/oracle.json` records, for every fixture document, the callbacks
//! `pdf_text.py` received and the text it produced. Comparing the callbacks first localises a
//! divergence to the parser (this gate) or to the layout (`tests/legal_pdf_layout.rs`).
//!
//! The oracle's `duw_act.pdf` entry is a real public document whose stream is deliberately
//! not stored, so it carries text only (and its page cap): the whole document goes through
//! the interpreter, and the resulting text must equal the reference's byte for byte. Its
//! fonts — composite Type 0 with `/Identity-H` and `/ToUnicode`, plus simple TrueType with
//! `/WinAnsiEncoding` and with a `/Differences` array — are what the synthetic set cannot
//! produce.

use std::fs;

use serde_json::Value;

use mcp_server_rs::pdf::interpret::Document;
use mcp_server_rs::pdf::{document_text, page_text};

/// Assert byte equality, and on failure name the first divergence in both directions so the
/// construct responsible can be found without re-reading two 10 kB strings.
fn assert_same_text(actual: &str, expected: &str, where_: &str) {
    if actual == expected {
        return;
    }
    let offset = actual
        .char_indices()
        .zip(expected.char_indices())
        .find(|((_, actual), (_, expected))| actual != expected)
        .map(|((offset, _), _)| offset)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    let context = |text: &str| {
        let start = text
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index < offset.saturating_sub(60))
            .last()
            .unwrap_or(0);
        let end = text
            .char_indices()
            .map(|(index, _)| index)
            .find(|index| *index > offset + 60)
            .unwrap_or(text.len());
        format!("{:?}", &text[start..end])
    };
    panic!(
        "{where_} (first divergence at byte {offset} of {} actual / {} expected)\n  actual:   {}\n  expected: {}",
        actual.len(),
        expected.len(),
        context(actual),
        context(expected),
    );
}

fn oracle() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/legal_pdf/oracle.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("fixture oracle")).expect("oracle json")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/legal_pdf/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::read(&path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

fn matrix(value: &Value) -> [f64; 6] {
    let numbers: Vec<f64> = value
        .as_array()
        .expect("a matrix")
        .iter()
        .map(|number| number.as_f64().expect("a number"))
        .collect();
    numbers.try_into().expect("six numbers")
}

#[test]
fn every_fixture_reproduces_the_reference_stream_and_text() {
    let oracle = oracle();
    let pdfs = oracle["pdfs"].as_object().expect("the fixture documents");
    assert!(!pdfs.is_empty(), "the fixture set is not empty");
    let mut compared = 0;

    for (name, entry) in pdfs {
        compared += 1;
        let document = Document::load(&fixture(name)).unwrap_or_else(|_| panic!("{name} loads"));
        let recorded = entry["visitors"].as_array();
        if let Some(visitors) = recorded {
            assert_eq!(document.page_count(), visitors.len(), "{name} (page count)");
        }

        let mut pages = Vec::new();
        for page_index in 0..document.page_count() {
            let expected_calls = recorded.and_then(|visitors| visitors.get(page_index));
            let calls = document
                .visitor_calls(page_index)
                .unwrap_or_else(|_| panic!("{name} page {page_index}"));
            if let Some(expected_calls) = expected_calls {
                let expected_calls = expected_calls.as_array().expect("a page's visitors");
                assert_eq!(
                    calls.len(),
                    expected_calls.len(),
                    "{name} page {page_index} (callback count)"
                );
                for (call_index, (actual, expected)) in
                    calls.iter().zip(expected_calls.iter()).enumerate()
                {
                    let where_ = format!("{name} page {page_index} callback {call_index}");
                    assert_eq!(
                        actual.text,
                        expected["text"].as_str().expect("text"),
                        "{where_} (text)"
                    );
                    assert_eq!(actual.cm, matrix(&expected["cm"]), "{where_} (cm)");
                    assert_eq!(actual.tm, matrix(&expected["tm"]), "{where_} (tm)");
                    assert_eq!(
                        actual.size,
                        expected["size"].as_f64().expect("size"),
                        "{where_} (size)"
                    );
                }
            }
            pages.push(page_text(&calls));
        }

        let rendered = document_text(&pages, pages.len());
        assert_same_text(
            &rendered,
            entry["text"].as_str().expect("the oracle text"),
            name,
        );
        if let Some(capped) = entry["text_max2"].as_str() {
            let read = document_text(&pages[..2], pages.len());
            assert_same_text(&read, capped, &format!("{name} (page cap)"));
        }
    }

    assert_eq!(compared, 7, "every fixture is compared");
}
