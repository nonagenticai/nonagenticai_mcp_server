//! PDF -> text, byte-for-byte with the reference's `src/builtin/legal/pdf_text.py`.
//!
//! The work is split in two, because the parity gate can then localise a divergence:
//!
//! * [`layout`] is the reference's own algorithm over pypdf's visitor stream — pure, no I/O,
//!   no PDF parsing. Its gate is the oracle's recorded stream (`tests/fixtures/legal_pdf`).
//! * [`interpret`] produces that stream from PDF bytes, reproducing pypdf's flush semantics:
//!   the visitor fires at `BT`/`ET`/`Tf`/`cm`/`Do`/line-break/final flushes with the run's
//!   memoised matrices, never per show operator. [`font`] is its font-decoding half.
//!
//! The three legal tools call one entry point that reads the document, applies the reference's
//! page cap and returns the text or its permanent error class.

pub mod article;
pub mod font;
mod font_data;
pub mod interpret;
pub mod layout;

pub use article::{AmbiguousArticle, cut_article};
pub use interpret::PdfError;
pub use layout::{VisitorCall, document_text, page_text};

/// The reference's `MAX_PDF_PAGES`: reading stops after this many pages and the cut line says so.
pub const MAX_PDF_PAGES: usize = 200;

/// PDF bytes -> plain text of the first [`MAX_PDF_PAGES`] pages — the reference's `pdf_to_text`
/// (`pdf_text.py:63-86`) over the interpreter's visitor stream.
pub fn text(data: &[u8]) -> Result<String, PdfError> {
    let document = interpret::Document::load(data)?;
    let total = document.page_count();
    let read = total.min(MAX_PDF_PAGES);
    let mut pages = Vec::with_capacity(read);
    for index in 0..read {
        pages.push(page_text(&document.visitor_calls(index)?));
    }
    Ok(document_text(&pages, total))
}

/// Every page's text, no page cap — the ELI consolidated-PDF path (`eli.py:232-243`), which
/// reads the whole act and then cuts one article out of it.
pub fn full_text(data: &[u8]) -> Result<String, PdfError> {
    let document = interpret::Document::load(data)?;
    let total = document.page_count();
    let mut pages = Vec::with_capacity(total);
    for index in 0..total {
        pages.push(page_text(&document.visitor_calls(index)?));
    }
    Ok(document_text(&pages, total))
}
