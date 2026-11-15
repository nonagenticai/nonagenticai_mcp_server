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

pub mod font;
mod font_data;
pub mod interpret;
pub mod layout;

pub use layout::{VisitorCall, document_text, page_text};

/// The reference's `MAX_PDF_PAGES`: reading stops after this many pages and the cut line says so.
pub const MAX_PDF_PAGES: usize = 200;
