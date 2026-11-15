//! pypdf 6.21.4's text visitor, transcribed: the `(text, cm, tm, font_size)` callbacks
//! `extract_text(visitor_text=…)` hands the reference, produced from the PDF's own content
//! streams.
//!
//! The reference's semantics are not a generic extractor's, and every one of them is
//! load-bearing for byte parity:
//!
//! * the visitor fires at *flushes* — `BT`, `ET`, `Tf`, `cm`, `Do`, a line break and the end
//!   of the stream — never per show operator;
//! * a flush reports the **memoised** matrices of the run's first character, not the current
//!   ones, except for the direction changes inside one show operator;
//! * `Tj`/`TJ`/`'`/`"` accumulate text; a `TJ` adjustment inserts a space only when it is at
//!   least 95% of half the font's space width, the run is non-empty and does not already end
//!   in a space;
//! * `Do` flushes, emits a newline of its own, and recurses into a Form XObject with fresh
//!   matrices and the form's own resources, guarded against cycles;
//! * a positioning operator that lands more than `0.8 × min(str_height, font_size)` away
//!   starts a new line, and enough horizontal movement inserts a space.
//!
//! Content streams are tokenised here rather than by `lopdf::content`, because pypdf's
//! visitor reports the matrices it parsed as doubles and `lopdf` stores reals as `f32`; a
//! single rounded operand would break the byte gate. `lopdf` still owns the object model,
//! stream decoding and the page tree.

use std::collections::HashMap;
use std::rc::Rc;

use lopdf::{Dictionary, Document as Pdf, Object, ObjectId, Stream};

use super::font::Font;
use super::layout::VisitorCall;

/// Why a document could not be read. The three legal tools turn this into the reference's
/// permanent error for an unreadable PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfError {
    /// The file is not a PDF this reader understands.
    Unreadable,
}

const IDENTITY: [f64; 6] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// pypdf's `get_configuration().xform_maximum_invocations_per_extraction` stand-in: the
/// recursion depth a Form XObject chain may reach before further content is skipped.
const MAX_FORM_INVOCATIONS: usize = 100;

/// A PDF document's pages, readable as the reference's visitor stream.
pub struct Document {
    inner: Pdf,
    pages: Vec<ObjectId>,
}

impl Document {
    /// Parse an in-memory PDF. The reference raises its permanent error class for a file
    /// pypdf cannot open; that is what `Unreadable` maps to.
    pub fn load(data: &[u8]) -> Result<Document, PdfError> {
        let inner = Pdf::load_mem(data).map_err(|_| PdfError::Unreadable)?;
        let pages = inner.get_pages().values().copied().collect();
        Ok(Document { inner, pages })
    }

    /// The document's page count, in page-tree order.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// The visitor callbacks `page.extract_text(visitor_text=…)` would deliver for one page,
    /// in order. The index is the page's position in the page tree.
    pub fn visitor_calls(&self, page_index: usize) -> Result<Vec<VisitorCall>, PdfError> {
        let page = *self.pages.get(page_index).ok_or(PdfError::Unreadable)?;
        let dictionary = self
            .inner
            .get_dictionary(page)
            .map_err(|_| PdfError::Unreadable)?;
        let Some(resources) = resources(&self.inner, dictionary) else {
            return Ok(Vec::new());
        };
        let content = self.inner.get_page_content(page);
        let mut extractor = Extractor::new(&self.inner, resources);
        let mut known = Vec::new();
        extractor.extract(&content, &mut known)?;
        Ok(extractor.calls)
    }
}

/// pypdf's `get_inherited("/Resources")`: a page's own resources, else its nearest ancestor's.
fn resources<'a>(document: &'a Pdf, page: &'a Dictionary) -> Option<&'a Dictionary> {
    let mut current = Some(page);
    let mut depth = 0;
    while let Some(dictionary) = current {
        if let Ok(Object::Dictionary(found)) = dictionary.get_deref(b"Resources", document) {
            return Some(found);
        }
        depth += 1;
        if depth > 64 {
            return None;
        }
        current = match dictionary.get_deref(b"Parent", document) {
            Ok(Object::Dictionary(parent)) => Some(parent),
            _ => None,
        };
    }
    None
}

/// The graphics state `q` saves and `Q` restores: pypdf's `cm_stack` entry.
struct SavedState {
    cm: [f64; 6],
    font: Rc<Font>,
    font_size: f64,
    leading: f64,
}

/// The state one content stream is read with — pypdf's `TextExtraction`, plus the visitor's
/// output list.
struct Extractor<'a> {
    document: &'a Pdf,
    resources: &'a Dictionary,
    calls: Vec<VisitorCall>,
    text: String,
    output: String,
    cm: [f64; 6],
    tm: [f64; 6],
    cm_prev: [f64; 6],
    tm_prev: [f64; 6],
    memo_cm: [f64; 6],
    memo_tm: [f64; 6],
    /// pypdf's `_space_width`: half the font's space width, before the font size applies.
    space_width: f64,
    /// `_actual_str_size["str_widths"]`, the pending run width in 1/1000 units.
    str_widths: f64,
    /// `_actual_str_size["str_height"]`, the pending run's font size.
    str_height: f64,
    leading: f64,
    font_size: f64,
    font: Rc<Font>,
    fonts: HashMap<Vec<u8>, Rc<Font>>,
    line_span: Option<(usize, f64, f64)>,
    rtl: bool,
    saved: Vec<SavedState>,
}

impl<'a> Extractor<'a> {
    fn new(document: &'a Pdf, resources: &'a Dictionary) -> Extractor<'a> {
        let mut fonts: HashMap<Vec<u8>, Rc<Font>> = HashMap::new();
        if let Ok(Object::Dictionary(entries)) = resources.get_deref(b"Font", document) {
            for (name, object) in entries.iter() {
                let (_, object) = dereference(document, object);
                if let Object::Dictionary(dictionary) = object {
                    let mut font = Font::from_dictionary(document, dictionary);
                    font.apply_page_space_default();
                    fonts.insert(name.clone(), Rc::new(font));
                }
            }
        }
        Extractor {
            document,
            resources,
            calls: Vec::new(),
            text: String::new(),
            output: String::new(),
            cm: IDENTITY,
            tm: IDENTITY,
            cm_prev: IDENTITY,
            tm_prev: IDENTITY,
            memo_cm: IDENTITY,
            memo_tm: IDENTITY,
            space_width: 500.0,
            str_widths: 0.0,
            str_height: 0.0,
            leading: 0.0,
            font_size: 12.0,
            font: Rc::new(Font::initial()),
            fonts,
            line_span: None,
            rtl: false,
            saved: Vec::new(),
        }
    }

    /// `PageObject._extract_text` over one content stream. `known` is the Form XObject cycle
    /// guard, shared with every recursive call the way pypdf shares `known_ids`.
    fn extract(&mut self, content: &[u8], known: &mut Vec<ObjectId>) -> Result<(), PdfError> {
        let operations = parse_operations(content)?;
        for operation in &operations {
            self.operate(operation, known);
        }
        self.output.push_str(&self.text);
        if !self.text.is_empty() {
            self.visit();
        }
        Ok(())
    }

    fn operate(&mut self, operation: &Operation, known: &mut Vec<ObjectId>) {
        match operation.operator.as_str() {
            "BT" => {
                self.tm = IDENTITY;
                self.flush_text();
            }
            "ET" => self.flush_text(),
            "q" => self.saved.push(SavedState {
                cm: self.cm,
                font: Rc::clone(&self.font),
                font_size: self.font_size,
                leading: self.leading,
            }),
            "Q" => match self.saved.pop() {
                Some(state) => {
                    self.cm = state.cm;
                    self.font = state.font;
                    self.font_size = state.font_size;
                    self.leading = state.leading;
                }
                // pypdf's handler resets only the current matrix when the stack is empty.
                None => self.cm = IDENTITY,
            },
            "cm" => self.handle_cm(&operation.operands),
            "Tf" => self.handle_tf(&operation.operands),
            "Td" => {
                let widths = self.handle_td(&operation.operands);
                self.post_process(widths);
            }
            "Tm" => {
                let widths = self.handle_tm(&operation.operands);
                self.post_process(widths);
            }
            "T*" => {
                let widths = self.handle_t_star();
                self.post_process(widths);
            }
            "Tj" => self.handle_tj_operation(&operation.operands),
            "'" => {
                let widths = self.handle_t_star();
                self.post_process(widths);
                self.handle_tj_operation(&operation.operands);
            }
            "\"" if operation.operands.len() >= 3 => {
                // `Tw` and `Tc` only change state text extraction never reads.
                let widths = self.handle_t_star();
                self.post_process(widths);
                self.handle_tj_operation(&operation.operands[2..]);
            }
            "TD" if operation.operands.len() >= 2 => {
                if let Operand::Number(ty) = operation.operands[1] {
                    self.leading = -ty;
                }
                let widths = self.handle_td(&operation.operands);
                self.post_process(widths);
            }
            "TJ" => self.handle_tj_array(&operation.operands),
            "Do" if !operation.operands.is_empty() => self.handle_do(&operation.operands, known),
            // `Tz`, `Tw`, `TL` and everything else the reference does not read.
            _ => {}
        }
    }

    /// `_flush_text`: the run is reported at the memoised matrices and the memo restarts.
    fn flush_text(&mut self) {
        self.output.push_str(&self.text);
        self.visit();
        self.text.clear();
        self.memo_cm = self.cm;
        self.memo_tm = self.tm;
    }

    /// `_handle_cm`: a flush that keeps the *new* matrix as the next run's start.
    fn handle_cm(&mut self, operands: &[Operand]) {
        self.output.push_str(&self.text);
        self.visit();
        self.text.clear();
        self.cm = match matrix(operands) {
            Some(matrix) => mult(&matrix, &self.cm),
            None => IDENTITY,
        };
        self.memo_cm = self.cm;
        self.memo_tm = self.tm;
    }

    /// `_handle_tf`: a non-empty run is flushed, then the font resource is swapped.
    fn handle_tf(&mut self, operands: &[Operand]) {
        if !self.text.is_empty() {
            self.output.push_str(&self.text);
            self.visit();
        }
        self.text.clear();
        self.memo_cm = self.cm;
        self.memo_tm = self.tm;
        let font = match operands.first() {
            Some(Operand::Name(name)) => self.fonts.get(name).cloned(),
            _ => None,
        };
        self.font = font.unwrap_or_else(|| Rc::new(Font::unknown()));
        self.space_width = self.font.space_width() / 2.0;
        if let Some(Operand::Number(size)) = operands.get(1) {
            self.font_size = *size;
        }
    }

    /// `_handle_td`.
    fn handle_td(&mut self, operands: &[Operand]) -> f64 {
        let tx = number(operands.first()).unwrap_or(0.0);
        let ty = number(operands.get(1)).unwrap_or(0.0);
        self.tm[4] += tx * self.tm[0] + ty * self.tm[2];
        self.tm[5] += tx * self.tm[1] + ty * self.tm[3];
        let widths = self.str_widths / 1000.0;
        self.str_widths = 0.0;
        widths
    }

    /// `_handle_tm`.
    fn handle_tm(&mut self, operands: &[Operand]) -> f64 {
        self.tm = matrix(operands).unwrap_or(IDENTITY);
        let widths = self.str_widths / 1000.0;
        self.str_widths = 0.0;
        widths
    }

    /// `_handle_t_star`.
    fn handle_t_star(&mut self) -> f64 {
        self.tm[4] -= self.leading * self.tm[2];
        self.tm[5] -= self.leading * self.tm[3];
        let widths = self.str_widths / 1000.0;
        self.str_widths = 0.0;
        widths
    }

    /// `process_operation(b"Tj", …)`: the show, then the positioning check.
    fn handle_tj_operation(&mut self, operands: &[Operand]) {
        let widths = self.handle_tj(operands);
        self.post_process(widths);
    }

    /// `_handle_tj`: a byte string is decoded through the font and reordered; a name operand
    /// is, to pypdf, a `str` and is appended verbatim.
    fn handle_tj(&mut self, operands: &[Operand]) -> f64 {
        match operands.first() {
            Some(Operand::Bytes(bytes)) => {
                let decoded = self.font.decode(bytes);
                self.display(&decoded.units);
                self.str_widths += decoded.widths * self.font_size;
                self.str_height = self.font_size;
            }
            Some(Operand::Name(name)) => {
                self.text.push('/');
                self.text.push_str(&String::from_utf8_lossy(name));
                self.str_height = self.font_size;
            }
            _ => return 0.0,
        }
        0.0
    }

    /// `_handle_tj_array`: pypdf's `TJ` loop. A string element is a `Tj`; a large enough
    /// adjustment is a `Tj` of one space. Both are post-processed like any `Tj`.
    fn handle_tj_array(&mut self, operands: &[Operand]) {
        let Some(Operand::Array(items)) = operands.first() else {
            return;
        };
        let threshold = self.space_width * 0.95;
        for item in items {
            match item {
                Operand::Bytes(_) => self.handle_tj_operation(std::slice::from_ref(item)),
                Operand::Number(value)
                    if value.abs() >= threshold
                        && !self.text.is_empty()
                        && !self.text.ends_with(' ') =>
                {
                    self.handle_tj_operation(&[Operand::Bytes(b" ".to_vec())]);
                }
                _ => {}
            }
        }
    }

    /// `get_display_str`: the characters are appended in reading order; a right-to-left run
    /// is accumulated backwards and flushes the left-to-right run that preceded it.
    fn display(&mut self, units: &[String]) {
        for unit in units {
            let mut characters = unit.chars();
            match (characters.next(), characters.next()) {
                (Some(character), None) if neutral(character) => {
                    if self.rtl {
                        self.text.insert(0, character);
                    } else {
                        self.text.push(character);
                    }
                }
                (Some(character), None) => {
                    if rtl(character) {
                        if !self.rtl {
                            self.rtl = true;
                            self.visit_at_current();
                            self.output.push_str(&self.text);
                            self.text.clear();
                        }
                        self.text.insert(0, character);
                    } else {
                        if self.rtl {
                            self.rtl = false;
                            self.visit_at_current();
                            self.output.push_str(&self.text);
                            self.text.clear();
                        }
                        self.text.push(character);
                    }
                }
                // A multi-character replacement is treated as neutral.
                _ => {
                    if self.rtl {
                        self.text.insert_str(0, unit);
                    } else {
                        self.text.push_str(unit);
                    }
                }
            }
        }
    }

    /// The visitor call pypdf makes for a direction change: the current matrices, not the
    /// memoised ones.
    fn visit_at_current(&mut self) {
        self.calls.push(VisitorCall {
            text: self.text.clone(),
            cm: self.cm,
            tm: self.tm,
            size: self.font_size,
        });
    }

    /// The visitor call every flush makes: the run's memoised matrices.
    fn visit(&mut self) {
        self.calls.push(VisitorCall {
            text: self.text.clone(),
            cm: self.memo_cm,
            tm: self.memo_tm,
            size: self.font_size,
        });
    }

    fn visit_text(&mut self, text: &str) {
        self.calls.push(VisitorCall {
            text: text.to_owned(),
            cm: self.memo_cm,
            tm: self.memo_tm,
            size: self.font_size,
        });
    }

    /// `_post_process_text_operation`.
    fn post_process(&mut self, str_widths: f64) {
        let was_empty = self.text.is_empty();
        self.crlf_space_check(str_widths);
        if was_empty || self.text.is_empty() {
            self.memo_cm = self.cm;
            self.memo_tm = self.tm;
        }
    }

    /// `crlf_space_check`: the one place a newline or a space is inserted between runs.
    fn crlf_space_check(&mut self, str_widths: f64) {
        let previous = mult(&self.tm_prev, &self.cm_prev);
        let current = mult(&self.tm, &self.cm);
        let orientation = orient(&current);
        let delta_x = current[4] - previous[4];
        let delta_y = current[5] - previous[5];
        let scale_previous_x = previous[0].hypot(previous[1]);
        let scale_previous_y = previous[2].hypot(previous[3]);
        let scale_y = current[2].hypot(current[3]);
        let (moved_height, moved_width) = if orientation == 0 || orientation == 180 {
            (delta_y, delta_x)
        } else {
            (delta_x, delta_y)
        };
        let axis_index = if orientation == 0 || orientation == 180 {
            5
        } else {
            4
        };
        let axis = current[axis_index];
        let distance = match self.line_span {
            Some((index, lower, upper)) if index == axis_index => {
                if lower <= axis && axis <= upper {
                    0.0
                } else {
                    (axis - lower).abs().min((axis - upper).abs())
                }
            }
            _ => moved_height.abs(),
        };
        let last = self
            .text
            .chars()
            .last()
            .or_else(|| self.output.chars().last());
        let space_width = self.font_size * self.space_width / 1000.0;
        if distance > 0.8 * (self.str_height * scale_previous_y).min(self.font_size * scale_y) {
            if last.is_some_and(|last| last != '\n') {
                let flushed = format!("{}\n", self.text);
                self.output.push_str(&self.text);
                self.output.push('\n');
                self.visit_text(&flushed);
                self.text.clear();
            }
            self.line_span = Some((axis_index, axis, axis));
        } else {
            if moved_width >= (space_width + str_widths) * scale_previous_x
                && last.is_some_and(|last| last != ' ')
            {
                self.text.push(' ');
            }
            self.line_span = match self.line_span {
                Some((index, lower, upper))
                    if index == axis_index && last.is_some_and(|last| last != '\n') =>
                {
                    Some((axis_index, lower.min(axis), upper.max(axis)))
                }
                _ => Some((axis_index, axis, axis)),
            };
        }
        self.tm_prev = self.tm;
        self.cm_prev = self.cm;
    }

    /// The `Do` branch of `_extract_text`: flush, emit the reference's newline, and recurse
    /// into the Form XObject with its own resources.
    fn handle_do(&mut self, operands: &[Operand], known: &mut Vec<ObjectId>) {
        self.output.push_str(&self.text);
        self.visit();
        if !self.output.is_empty() && !self.output.ends_with('\n') {
            self.output.push('\n');
            self.visit_text("\n");
        }
        if let Some(Operand::Name(name)) = operands.first()
            && let Ok(Object::Dictionary(xobjects)) =
                self.resources.get_deref(b"XObject", self.document)
            && let Some(xobject) = xobjects.get(name).ok().cloned()
        {
            let (id, xobject) = dereference(self.document, &xobject);
            if let Object::Stream(stream) = xobject
                && !id.is_some_and(|id| known.contains(&id))
                && known.len() < MAX_FORM_INVOCATIONS
                && form_matches(self.document, stream)
            {
                if let Some(id) = id {
                    known.push(id);
                }
                let content = stream.decompressed_content().unwrap_or_default();
                // A form without resources extracts nothing at all, visitor calls included.
                if let Some(form_resources) = resources(self.document, &stream.dict) {
                    let mut extractor = Extractor::new(self.document, form_resources);
                    extractor.extract(&content, known).ok();
                    self.calls.append(&mut extractor.calls);
                    // pypdf appends the form's text to the page's output; the next line-break
                    // decision reads the last character of that output.
                    self.output.push_str(&extractor.output);
                }
                if id.is_some() {
                    known.pop();
                }
            }
        }
        self.text.clear();
        self.memo_cm = self.cm;
        self.memo_tm = self.tm;
    }
}

/// `_extract_text__xform`: an Image XObject is not text; anything else is read as a stream.
fn form_matches(document: &Pdf, stream: &Stream) -> bool {
    match stream.dict.get_deref(b"Subtype", document) {
        Ok(Object::Name(name)) => name != b"Image",
        _ => true,
    }
}

fn dereference<'a>(document: &'a Pdf, object: &'a Object) -> (Option<ObjectId>, &'a Object) {
    document
        .dereference(object)
        .unwrap_or((None, &Object::Null))
}

/// pypdf's `mult`: matrices compose as `m × n`.
fn mult(m: &[f64; 6], n: &[f64; 6]) -> [f64; 6] {
    [
        m[0] * n[0] + m[1] * n[2],
        m[0] * n[1] + m[1] * n[3],
        m[2] * n[0] + m[3] * n[2],
        m[2] * n[1] + m[3] * n[3],
        m[4] * n[0] + m[5] * n[2] + n[4],
        m[4] * n[1] + m[5] * n[3] + n[5],
    ]
}

/// pypdf's `orient`.
fn orient(m: &[f64; 6]) -> u16 {
    if m[3] > 1e-6 {
        0
    } else if m[3] < -1e-6 {
        180
    } else if m[1] > 0.0 {
        90
    } else {
        270
    }
}

/// One content-stream operand, in the shapes the text operators read.
#[derive(Debug, Clone, PartialEq)]
enum Operand {
    Number(f64),
    Name(Vec<u8>),
    Bytes(Vec<u8>),
    Array(Vec<Operand>),
    /// Booleans, null and dictionaries: never read by the text path.
    Other,
}

#[derive(Debug, Clone, PartialEq)]
struct Operation {
    operator: String,
    operands: Vec<Operand>,
}

fn number(operand: Option<&Operand>) -> Option<f64> {
    match operand {
        Some(Operand::Number(value)) => Some(*value),
        _ => None,
    }
}

/// A `Tm`/`cm` operand list: exactly the six numbers pypdf's `float(operand)` loop accepts.
fn matrix(operands: &[Operand]) -> Option<[f64; 6]> {
    let mut matrix = [0.0; 6];
    for (index, operand) in operands.iter().take(6).enumerate() {
        match operand {
            Operand::Number(value) => matrix[index] = *value,
            _ => return None,
        }
    }
    if operands.len() < 6 {
        return None;
    }
    Some(matrix)
}

/// pypdf's `is_char_neutral`, with the reference's default (empty) custom range.
fn neutral(character: char) -> bool {
    matches!(character as u32,
        0x00..=0x2f | 0x3a..=0x40 | 0x660..=0x66d | 0x6f0..=0x6f9 | 0x2000..=0x206f | 0x20a0..=0x21ff)
}

/// pypdf's `is_char_rtl`, with the reference's default (empty) custom range.
fn rtl(character: char) -> bool {
    matches!(character as u32, 0x590..=0x8ff | 0xfb1d..=0xfdff | 0xfe70..=0xfeff)
}

// ── content-stream tokenizer ───────────────────────────────────────────────────────────────

/// Parse a content stream the way pypdf's `ContentStream` does for the operands text
/// extraction reads: numbers stay doubles, strings stay bytes, arrays nest.
fn parse_operations(data: &[u8]) -> Result<Vec<Operation>, PdfError> {
    let mut lexer = Lexer { data, index: 0 };
    let mut operations = Vec::new();
    let mut operands: Vec<Operand> = Vec::new();
    loop {
        lexer.whitespace();
        let Some(byte) = lexer.peek() else { break };
        match byte {
            b'(' => operands.push(Operand::Bytes(lexer.literal_string()?)),
            b'<' if lexer.peek_at(1) == Some(b'<') => {
                lexer.skip_dictionary();
                operands.push(Operand::Other);
            }
            b'<' => operands.push(Operand::Bytes(lexer.hex_string()?)),
            b'[' => {
                lexer.index += 1;
                operands.push(Operand::Array(lexer.array()?));
            }
            b']' | b'>' | b')' | b'{' | b'}' => lexer.index += 1,
            b'/' => operands.push(Operand::Name(lexer.name_value())),
            b'0'..=b'9' | b'+' | b'-' | b'.' => operands.push(lexer.number()),
            b'%' => lexer.comment(),
            _ => {
                let keyword = lexer.keyword();
                if keyword == "BI" {
                    lexer.skip_inline_image();
                    operations.push(Operation {
                        operator: "BI".to_owned(),
                        operands: std::mem::take(&mut operands),
                    });
                } else {
                    operations.push(Operation {
                        operator: keyword,
                        operands: std::mem::take(&mut operands),
                    });
                }
            }
        }
    }
    Ok(operations)
}

struct Lexer<'a> {
    data: &'a [u8],
    index: usize,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.index).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.data.get(self.index + offset).copied()
    }

    fn whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || byte == 0 {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn comment(&mut self) {
        while let Some(byte) = self.peek() {
            if byte == b'\n' || byte == b'\r' {
                break;
            }
            self.index += 1;
        }
    }

    /// A `/Name` operand with its leading slash removed.
    fn name_value(&mut self) -> Vec<u8> {
        self.index += 1;
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || delimiter(byte) {
                break;
            }
            self.index += 1;
        }
        self.data[start..self.index].to_vec()
    }

    fn number(&mut self) -> Operand {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || delimiter(byte) {
                break;
            }
            self.index += 1;
        }
        match std::str::from_utf8(&self.data[start..self.index])
            .ok()
            .and_then(|text| text.parse::<f64>().ok())
        {
            Some(value) => Operand::Number(value),
            None => Operand::Other,
        }
    }

    fn keyword(&mut self) -> String {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || delimiter(byte) {
                break;
            }
            self.index += 1;
        }
        String::from_utf8_lossy(&self.data[start..self.index]).into_owned()
    }

    fn literal_string(&mut self) -> Result<Vec<u8>, PdfError> {
        self.index += 1;
        let mut out = Vec::new();
        let mut depth = 1;
        while let Some(byte) = self.peek() {
            self.index += 1;
            match byte {
                b'(' => {
                    depth += 1;
                    out.push(byte);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(byte);
                }
                b'\\' => {
                    let Some(escaped) = self.peek() else { break };
                    self.index += 1;
                    match escaped {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'(' | b')' | b'\\' => out.push(escaped),
                        b'\n' => {}
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.index += 1;
                            }
                        }
                        b'0'..=b'7' => {
                            let mut value = u32::from(escaped - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(digit @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(digit - b'0');
                                        self.index += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(value as u8);
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        Err(PdfError::Unreadable)
    }

    fn hex_string(&mut self) -> Result<Vec<u8>, PdfError> {
        self.index += 1;
        let mut digits = Vec::new();
        while let Some(byte) = self.peek() {
            self.index += 1;
            if byte == b'>' {
                if digits.len() % 2 == 1 {
                    digits.push(b'0');
                }
                let mut out = Vec::with_capacity(digits.len() / 2);
                for pair in digits.chunks(2) {
                    let Ok(text) = std::str::from_utf8(pair) else {
                        return Err(PdfError::Unreadable);
                    };
                    let Ok(value) = u8::from_str_radix(text, 16) else {
                        return Err(PdfError::Unreadable);
                    };
                    out.push(value);
                }
                return Ok(out);
            }
            if byte.is_ascii_hexdigit() {
                digits.push(byte);
            }
        }
        Err(PdfError::Unreadable)
    }

    fn array(&mut self) -> Result<Vec<Operand>, PdfError> {
        let mut items = Vec::new();
        loop {
            self.whitespace();
            let Some(byte) = self.peek() else { break };
            match byte {
                b']' => {
                    self.index += 1;
                    break;
                }
                b'(' => items.push(Operand::Bytes(self.literal_string()?)),
                b'<' if self.peek_at(1) == Some(b'<') => {
                    self.skip_dictionary();
                    items.push(Operand::Other);
                }
                b'<' => items.push(Operand::Bytes(self.hex_string()?)),
                b'[' => {
                    self.index += 1;
                    items.push(Operand::Array(self.array()?));
                }
                b'/' => items.push(Operand::Name(self.name_value())),
                b'0'..=b'9' | b'+' | b'-' | b'.' => items.push(self.number()),
                b'%' => self.comment(),
                _ => {
                    let keyword = self.keyword();
                    items.push(Operand::Other);
                    if keyword.is_empty() {
                        self.index += 1;
                    }
                }
            }
        }
        Ok(items)
    }

    fn skip_dictionary(&mut self) {
        let mut depth = 0;
        while let Some(byte) = self.peek() {
            match byte {
                b'<' if self.peek_at(1) == Some(b'<') => {
                    depth += 1;
                    self.index += 2;
                }
                b'>' if self.peek_at(1) == Some(b'>') => {
                    depth -= 1;
                    self.index += 2;
                    if depth == 0 {
                        return;
                    }
                }
                b'(' => {
                    let _ = self.literal_string();
                }
                b'%' => self.comment(),
                _ => self.index += 1,
            }
        }
    }

    /// `BI … ID … EI`: pypdf parses the image dictionary and then reads to the `EI` marker;
    /// the bytes are not text operands, so they are skipped wholesale.
    fn skip_inline_image(&mut self) {
        while let Some(byte) = self.peek() {
            if byte == b'I' && self.peek_at(1) == Some(b'D') {
                self.index += 2;
                break;
            }
            self.index += 1;
        }
        while self.index + 1 < self.data.len() {
            if self.data[self.index].is_ascii_whitespace()
                && self.data[self.index + 1..].starts_with(b"EI")
            {
                self.index += 3;
                return;
            }
            self.index += 1;
        }
        self.index = self.data.len();
    }
}

fn delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}
