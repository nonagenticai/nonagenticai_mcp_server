//! The reference's PDF text layout, as pure functions over pypdf's visitor stream.
//!
//! `src/builtin/legal/pdf_text.py` at the pinned archive SHA builds one page's text from the
//! `(text, cm, tm, font_size)` callbacks pypdf hands to `extract_text(visitor_text=…)`, then
//! post-processes the pages. This module is that algorithm, byte for byte:
//!
//! * a **raised, smaller** run after an alphanumeric character is a superscript (`Art. 61^1`);
//!   it does not move the baseline;
//! * a vertical jump of more than one unit starts a new line;
//! * per line: whitespace collapses to one space, the line is stripped, page furniture is
//!   dropped; then `449[1]` becomes `449^1` and a word hyphenated across a line break is
//!   rejoined when the next line starts lowercase;
//! * reading fewer pages than the document has appends the reference's cut line.
//!
//! The PDF parsing that produces the stream lives beside this module; keeping the layout pure is
//! what lets the fixture gate compare the two halves separately (see
//! `tests/fixtures/legal_pdf/oracle.json`).

use std::sync::LazyLock;

use regex::Regex;

/// One callback from pypdf's text visitor: the decoded text of a flush, the graphics and text
/// matrices in force, and the raw `Tf` size.
#[derive(Debug, Clone, PartialEq)]
pub struct VisitorCall {
    pub text: String,
    /// The current transformation matrix (`cm`), six numbers as PDF stores it.
    pub cm: [f64; 6],
    /// The text matrix (`tm`), six numbers as PDF stores it.
    pub tm: [f64; 6],
    /// The font size operand of the last `Tf`.
    pub size: f64,
}

/// The page furniture the reference drops (`pdf_text.py:18-24`).
fn furniture() -> &'static [Regex] {
    static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"^©\s*Kancelaria Sejmu\b.*$",
            r"^Dziennik Ustaw\s+[–-]\s*\d+\s*[–-]\s*Poz\.\s*\d+$",
            r"^Monitor Polski\s+[–-]\s*\d+\s*[–-]\s*Poz\.\s*\d+$",
            r"^\d{4}-\d{2}-\d{2}$",
            r"^s\.\s*\d+/\d+$",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("the furniture pattern is valid"))
        .collect()
    });
    &PATTERNS
}

fn whitespace() -> &'static Regex {
    static RUN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[ \t\xa0]+").expect("the whitespace pattern is valid"));
    &RUN
}

fn bracketed_superscript() -> &'static Regex {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(\d)\^?\[(\d{1,2})\]").expect("the bracket pattern is valid")
    });
    &PATTERN
}

fn hyphenated_line() -> &'static Regex {
    // The reference uses a look-ahead (`(\w)-\n(?=[a-ząćęłńóśźż])`); the regex crate has none,
    // so the lowercase letter is consumed and put back: `$1$2`.
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(\w)-\n([a-ząćęłńóśźż])").expect("the hyphen pattern is valid")
    });
    &PATTERN
}

/// One page's raw text, the reference's `_page_text` (`pdf_text.py:30-60`).
///
/// The stream is the callbacks **in order**; the reference's state (`y`, `size`) is updated
/// exactly where it updates there, including the "a superscript does not move the baseline" rule.
pub fn page_text(calls: &[VisitorCall]) -> String {
    let mut out = String::new();
    let mut last_y: Option<f64> = None;
    let mut body: Option<f64> = None;

    for call in calls {
        if call.text.is_empty() {
            continue;
        }
        // `abs(font_size * tm[3] * cm[3]) or font_size`: the fallback is Python's falsy zero.
        let scaled = (call.size * call.tm[3] * call.cm[3]).abs();
        let size = if scaled == 0.0 { call.size } else { scaled };
        let y = call.tm[5] * call.cm[3] + call.cm[5];
        let raised = match (last_y, body) {
            (Some(last), Some(body)) => {
                let delta = y - last;
                delta > 0.5 && delta < 8.0 && size < body * 0.8 && !call.text.trim().is_empty()
            }
            _ => false,
        };
        if raised {
            if out.chars().next_back().is_some_and(char::is_alphanumeric) {
                out.push('^');
            }
            out.push_str(&call.text);
            continue;
        }
        if let Some(last) = last_y
            && (y - last).abs() > 1.0
            && !out.is_empty()
            && !out.ends_with('\n')
        {
            out.push('\n');
        }
        out.push_str(&call.text);
        last_y = Some(y);
        if !call.text.trim().is_empty() {
            body = Some(size);
        }
    }
    out
}

/// The whole document, the reference's `pdf_to_text` (`pdf_text.py:63-86`).
///
/// `pages` are the raw per-page texts **actually read**; `total_pages` is the document's page
/// count, which is what the cut line reports when fewer pages were read.
pub fn document_text(pages: &[String], total_pages: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    for page in pages {
        for raw in page.split('\n') {
            let line = whitespace().replace_all(raw, " ");
            let line = line.trim();
            if line.is_empty() || furniture().iter().any(|pattern| pattern.is_match(line)) {
                continue;
            }
            lines.push(line.to_owned());
        }
    }
    let joined = lines.join("\n");
    let joined = bracketed_superscript().replace_all(&joined, "$1^$2");
    let mut text = hyphenated_line().replace_all(&joined, "$1$2").into_owned();
    if pages.len() < total_pages {
        text.push_str(&format!(
            "\n[... text cut after page {} of {}]",
            pages.len(),
            total_pages
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(text: &str, size: f64, x: f64, y: f64) -> VisitorCall {
        VisitorCall {
            text: text.to_owned(),
            cm: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            tm: [1.0, 0.0, 0.0, 1.0, x, y],
            size,
        }
    }

    #[test]
    fn a_raised_smaller_run_is_a_superscript_and_does_not_move_the_baseline() {
        let calls = [
            call("Art. 61", 10.0, 72.0, 700.0),
            call("1", 6.0, 101.46, 703.0),
            call(".", 10.0, 104.8, 700.0),
        ];
        assert_eq!(page_text(&calls), "Art. 61^1.");
    }

    #[test]
    fn a_raised_run_at_the_same_size_or_too_far_starts_a_line() {
        let same = [
            call("same", 10.0, 72.0, 660.0),
            call("size", 10.0, 100.0, 663.0),
        ];
        assert_eq!(page_text(&same), "same\nsize");
        let far = [call("a", 10.0, 72.0, 640.0), call("b", 6.0, 72.0, 649.0)];
        assert_eq!(page_text(&far), "a\nb");
    }

    #[test]
    fn the_caret_needs_an_alphanumeric_before_it() {
        let calls = [
            call("453.", 10.0, 72.0, 600.0),
            call("2", 6.0, 91.46, 603.0),
        ];
        assert_eq!(page_text(&calls), "453.2");
    }

    #[test]
    fn document_text_drops_furniture_and_rejoins_a_hyphenated_word() {
        let page = "© Kancelaria Sejmu 2024\nArt. 449[1].\nwycho-\nwania\n2024-01-31";
        assert_eq!(
            document_text(&[page.to_owned()], 1),
            "Art. 449^1.\nwychowania"
        );
    }

    #[test]
    fn the_cut_line_reports_the_pages_read_and_the_total() {
        let pages = vec!["first page".to_owned(), "second page".to_owned()];
        assert_eq!(
            document_text(&pages, 3),
            "first page\nsecond page\n[... text cut after page 2 of 3]"
        );
    }
}
