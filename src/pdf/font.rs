//! pypdf 6.21.4's font decoding, transcribed for the visitor path.
//!
//! A show operator carries raw bytes; the reference turns them into text through the font:
//! the `/Encoding` (a named table, or a dict with `/BaseEncoding` and `/Differences`) maps a
//! code to a character, then `/ToUnicode` remaps that character. The same font's `/Widths`
//! — or, for the fourteen core fonts, the AFM metrics — decide where a `TJ` adjustment
//! becomes a space and how far a run has moved.
//!
//! This is `_cmap.py`'s `get_encoding`, `generic/_font.py`'s `Font.from_font_resource` and
//! `_text_extraction/__init__.py`'s `get_text_operands`, restricted to what text extraction
//! reads. Composite (Type 0/CID) fonts are decoded the reference's way: `/Identity-H` names
//! the UTF-16BE codec, so the raw bytes are decoded as UTF-16BE code units (`surrogatepass`
//! in the reference; an unpaired surrogate cannot be a Rust `char`, so it becomes U+FFFD,
//! which is the reference's own output on the error path), and `/W` supplies widths keyed by
//! the decoded character. Type 1 fonts whose encoding lives in an embedded font file are the
//! next slice; until then their bytes fall back to identity decoding.

use std::collections::HashMap;

use lopdf::{Dictionary, Document, Object};

use super::font_data;

/// pypdf's `MAPPING_DICTIONARY_SIZE_LIMIT`: a `/ToUnicode` map larger than this is refused.
const MAPPING_LIMIT: usize = 100_000;

/// pypdf's `Font.encoding`: a simple font's code table, or a composite font's codec name.
#[derive(Debug, Clone)]
enum Encoding {
    /// pypdf's `dict[int, str]`: a code decodes to its entry, or to `chr(code)` when absent.
    Table(Box<[String; 256]>),
    /// pypdf's `str`: the codec is applied to the whole byte string, so a code is as wide as
    /// the codec says — two bytes for the UTF-16BE family `/Identity-H` names.
    Utf16Be,
}

impl Encoding {
    /// The code -> character table a simple font reads, when this font has one.
    fn table(&self) -> Option<&[String; 256]> {
        match self {
            Encoding::Table(table) => Some(table),
            Encoding::Utf16Be => None,
        }
    }
}

/// One font's decoding state, the fields of pypdf's `Font` that the visitor path reads.
#[derive(Debug, Clone)]
pub struct Font {
    /// pypdf's `Font.encoding`: a simple font's code table, or a composite font's codec.
    encoding: Encoding,
    /// pypdf's `Font.character_map`: `/ToUnicode`, keyed by the encoding's own character.
    character_map: HashMap<char, String>,
    /// pypdf's `Font.character_widths`, keyed by the character a width is looked up for.
    character_widths: HashMap<char, f64>,
    /// The `"default"` entry of `character_widths`.
    default_width: f64,
    /// pypdf's `Font.space_char`: the character compared against for the space width.
    space_char: char,
    /// pypdf's `Font.space_width`, before `_extract_text`'s 200-unit fallback.
    space_width: f64,
}

/// The result of decoding one show operator's bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// The characters in display order: one entry per input character, each the
    /// `/ToUnicode` replacement when there is one.
    pub units: Vec<String>,
    /// pypdf's `get_text_operands` `widths`: the sum of the characters a width is looked up
    /// for — the raw bytes for a simple font, the decoded characters for a codec — in 1/1000
    /// text space units, before the font size multiplies it.
    pub widths: f64,
}

impl Font {
    /// `_handle_tf`'s fallback when the resource name is not a known font: every byte decodes
    /// to U+FFFD, every width is the generic default, and the space is a quarter em.
    pub fn unknown() -> Font {
        Font {
            encoding: Encoding::Table(Box::new(std::array::from_fn(|_| "\u{fffd}".to_owned()))),
            character_map: HashMap::new(),
            character_widths: HashMap::new(),
            default_width: 500.0,
            space_char: ' ',
            space_width: 250.0,
        }
    }

    /// `TextExtraction.__init__`'s font before any `Tf`: WinAnsi decoding, no `/ToUnicode`,
    /// the generic width table.
    pub fn initial() -> Font {
        Font {
            encoding: Encoding::Table(named_table(b"WinAnsiEncoding")),
            character_map: HashMap::new(),
            character_widths: HashMap::new(),
            default_width: 500.0,
            space_char: ' ',
            space_width: 250.0,
        }
    }

    /// `Font.from_font_resource`.
    pub fn from_dictionary(document: &Document, dictionary: &Dictionary) -> Font {
        let base_font = dictionary
            .get(b"BaseFont")
            .ok()
            .and_then(|object| name(document, object));
        let sub_type = dictionary
            .get(b"Subtype")
            .ok()
            .and_then(|object| name(document, object))
            .unwrap_or_else(|| "Unknown".to_owned());
        let name = base_font.clone().unwrap_or_else(|| "Unknown".to_owned());

        let to_unicode = parse_to_unicode(document, dictionary);
        let encoding = match parse_encoding(document, dictionary, &sub_type) {
            // PDF 1.7 §5.9.1: for a simple font, a `/ToUnicode` entry wins over the
            // encoding's own character for every source code it names.
            Encoding::Table(mut table) => {
                for &code in &to_unicode.codes {
                    if code <= 255 {
                        table[code as usize] = char::from(code as u8).to_string();
                    }
                }
                Encoding::Table(table)
            }
            // A composite font's encoding is a codec name; the rule above applies only when
            // the encoding is a dict, so no override is made.
            codec => codec,
        };

        let mut character_widths: HashMap<char, f64> = HashMap::new();
        let mut default_width = 0.0;
        let mut flags = 32;
        let simple = matches!(
            sub_type.as_str(),
            "Type1" | "MMType1" | "TrueType" | "Type3"
        );
        let interpretable = sub_type != "Type3"
            || dictionary.get(b"ToUnicode").is_ok()
            || char_procs_are_glyphs(document, dictionary);
        if simple {
            if interpretable {
                // `/Widths` is taken when it is declared, even if malformed; the core metrics
                // are the fallback only for a font that declares none.
                if dictionary.get(b"Widths").is_ok() {
                    collect_widths(document, dictionary, &mut character_widths);
                } else if let Some(metrics) = font_data::core_metrics(name.as_bytes()) {
                    for (character, width) in metrics.widths {
                        character_widths.insert(*character, f64::from(*width));
                    }
                    // pypdf takes the descriptor, and so the flags, from the core metrics entry.
                    flags = metrics.flags;
                }
                if let Ok(Object::Dictionary(descriptor)) =
                    dictionary.get_deref(b"FontDescriptor", document)
                {
                    if let Ok(missing) = descriptor.get_deref(b"MissingWidth", document) {
                        default_width = integer(document, missing).unwrap_or(0) as f64;
                    }
                    if let Ok(flags_object) = descriptor.get_deref(b"Flags", document) {
                        flags = integer(document, flags_object).unwrap_or(32);
                    }
                }
            }
        } else {
            collect_descendant_widths(
                document,
                dictionary,
                &mut character_widths,
                &mut default_width,
                &mut flags,
            );
        }

        let space_char = space_char(&to_unicode.map, &encoding);
        if default_width == 0.0 {
            default_width = add_default_width(&character_widths, flags, space_char);
        }
        let space_width = match character_widths.get(&space_char) {
            Some(width) if *width != 0.0 => *width,
            _ if flags & 1 == 1 => default_width,
            _ => (default_width / 2.0).floor(),
        };

        Font {
            encoding,
            character_map: to_unicode.map,
            character_widths,
            default_width,
            space_char,
            space_width,
        }
    }

    /// `_extract_text`'s per-page fallback: a font that declares no width for its space gets
    /// the reader's 200-unit default.
    pub fn apply_page_space_default(&mut self) {
        if self
            .character_widths
            .get(&self.space_char)
            .copied()
            .unwrap_or(0.0)
            == 0.0
        {
            self.space_width = 200.0;
        }
    }

    /// pypdf's `Font.space_width`, which `_handle_tf` halves into the `TJ` threshold.
    pub fn space_width(&self) -> f64 {
        self.space_width
    }

    /// `get_text_operands` over a byte string, then `get_display_str`'s `/ToUnicode` remap.
    pub fn decode(&self, bytes: &[u8]) -> Decoded {
        // A dict encoding maps each byte; a codec decodes the string, so its codes are as
        // wide as the codec says and the widths are looked up by the decoded character.
        let (text, raw) = match &self.encoding {
            Encoding::Table(table) => {
                let mut text = String::new();
                let mut raw = String::new();
                for &byte in bytes {
                    raw.push(char::from(byte));
                    text.push_str(&table[byte as usize]);
                }
                (text, Some(raw))
            }
            Encoding::Utf16Be => (decode_utf16_be(bytes), None),
        };
        let units = text
            .chars()
            .map(|character| match self.character_map.get(&character) {
                Some(mapped) => mapped.clone(),
                None => character.to_string(),
            })
            .collect();
        let mut widths = 0.0;
        for character in raw.as_deref().unwrap_or(&text).chars() {
            widths += if character == self.space_char {
                self.space_width
            } else {
                self.character_widths
                    .get(&character)
                    .copied()
                    .unwrap_or(self.default_width)
            };
        }
        Decoded { units, widths }
    }
}

/// `bytes.decode("utf-16-be", "surrogatepass")` and the reference's `"replace"` fallback.
///
/// `surrogatepass` keeps an unpaired surrogate in the Python string; a Rust `char` cannot
/// hold one, so it takes the replacement character the reference itself produces on the
/// fallback path, and for an odd trailing byte, which is what makes that fallback fire.
fn decode_utf16_be(bytes: &[u8]) -> String {
    let even = bytes.len() - bytes.len() % 2;
    let mut text = decode_utf16_units(&bytes[..even]);
    if even < bytes.len() {
        text.push('\u{fffd}');
    }
    text
}

/// The same decode over a whole number of code units, keeping surrogate pairs together.
fn decode_utf16_units(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    let mut index = 0;
    while index + 1 < bytes.len() {
        let unit = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        index += 2;
        if (0xd800..0xdc00).contains(&unit) {
            // A high surrogate pairs with the next unit only when that unit is a low one.
            let low = if index + 1 < bytes.len() {
                u16::from_be_bytes([bytes[index], bytes[index + 1]])
            } else {
                0
            };
            if (0xdc00..0xe000).contains(&low) {
                index += 2;
                let code =
                    0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                text.push(char::from_u32(code).unwrap_or('\u{fffd}'));
            } else {
                text.push('\u{fffd}');
            }
        } else {
            text.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'));
        }
    }
    text
}

/// `decode_utf16 = partial(bytes.decode, encoding="utf-16-be", errors="surrogatepass")` over a
/// range destination: the whole string, not just its first character. `None` when the
/// reference's decode would raise on a truncated string, which discards that CMap line.
fn decode_utf16_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(decode_utf16_units(bytes))
}

/// `Font._collect_tt_t1_character_widths`.
fn collect_widths(
    document: &Document,
    dictionary: &Dictionary,
    character_widths: &mut HashMap<char, f64>,
) {
    let Ok(Object::Array(widths)) = dictionary.get_deref(b"Widths", document) else {
        return;
    };
    let first = dictionary
        .get(b"FirstChar")
        .ok()
        .and_then(|object| integer(document, object))
        .unwrap_or(0);
    if first < 0 {
        return;
    }
    for (index, width) in widths.iter().enumerate() {
        let code = first as usize + index;
        if code > 255 {
            break;
        }
        character_widths.insert(
            char::from(code as u8),
            integer(document, width).unwrap_or(0) as f64,
        );
    }
}

/// pypdf's `_get_space_char`: the character `/ToUnicode` or the encoding maps a space to.
fn space_char(character_map: &HashMap<char, String>, encoding: &Encoding) -> char {
    if let Some(key) = character_map
        .iter()
        .find(|(_, value)| value.as_str() == " ")
        .map(|(key, _)| *key)
    {
        return key;
    }
    // A composite font's encoding is a codec name, so only `/ToUnicode` can name a space.
    encoding
        .table()
        .and_then(|table| table.iter().position(|value| value == " "))
        .map(|code| char::from(code as u8))
        .unwrap_or(' ')
}

/// `from_font_resource`'s composite branch: every `/DescendantFonts` entry contributes its
/// `/W` widths and `/DW` default, and its descriptor's flags (the last entry wins, as the
/// reference overwrites the same variables in its loop).
fn collect_descendant_widths(
    document: &Document,
    dictionary: &Dictionary,
    character_widths: &mut HashMap<char, f64>,
    default_width: &mut f64,
    flags: &mut i64,
) {
    let Ok(Object::Array(descendants)) = dictionary.get_deref(b"DescendantFonts", document) else {
        return;
    };
    for descendant in descendants {
        let (_, Object::Dictionary(d_font)) = dereference(document, descendant) else {
            continue;
        };
        collect_cid_widths(document, d_font, character_widths);
        if let Ok(dw) = d_font.get(b"DW")
            && let Some(default) = number(document, dw)
        {
            *default_width = default;
        }
        // `FontDescriptor(**…flags…)`, whose own default is 32.
        let mut descendant_flags = 32;
        if let Ok(Object::Dictionary(descriptor)) = d_font.get_deref(b"FontDescriptor", document)
            && let Ok(flags_object) = descriptor.get_deref(b"Flags", document)
        {
            descendant_flags = integer(document, flags_object).unwrap_or(32);
        }
        *flags = descendant_flags;
    }
}

/// pypdf's `Font._collect_cid_character_widths`: `/W`'s two interleaved forms — a start code
/// with a width list, and a start/stop code pair with one constant width.
///
/// pypdf raises `LimitReachedError` past its entry limits; a range that would exceed them is
/// skipped here instead of filling the map, so a hostile `/W` costs nothing.
fn collect_cid_widths(
    document: &Document,
    d_font: &Dictionary,
    character_widths: &mut HashMap<char, f64>,
) {
    /// pypdf's `MAX_CID_WIDTH_ENTRY_COUNT` (one range) and `MAX_WIDTH_ENTRY_COUNT` (all).
    const RANGE_LIMIT: i64 = 65_536;
    const TOTAL_LIMIT: usize = 100_000;
    let Ok(Object::Array(entries)) = d_font.get_deref(b"W", document) else {
        return;
    };
    let mut index = 0;
    while index < entries.len() && character_widths.len() < TOTAL_LIMIT {
        let Some(start) = integer(document, &entries[index]) else {
            // pypdf warns and moves on; only the entry's own tokens are skipped.
            index += 1;
            continue;
        };
        let next = entries
            .get(index + 1)
            .map(|object| dereference(document, object).1);
        if let Some(Object::Array(widths)) = next {
            // `start [w …]`: the codes run from `start`, one per list entry.
            if i64::try_from(widths.len()).unwrap_or(RANGE_LIMIT) <= RANGE_LIMIT {
                for (offset, width) in widths.iter().enumerate() {
                    if let Some(code) = code_point(start, offset)
                        && let Some(width) = number(document, width)
                    {
                        character_widths.insert(code, width);
                    }
                }
            }
            index += 2;
            continue;
        }
        // `start stop width`: one width for every code in the inclusive range.
        let stop = next.and_then(|object| integer(document, object));
        let constant = entries
            .get(index + 2)
            .and_then(|object| number(document, object));
        if let (Some(stop), Some(constant)) = (stop, constant) {
            if stop >= start && stop - start < RANGE_LIMIT {
                let mut code = start.max(0);
                while code <= stop {
                    if let Some(character) = u32::try_from(code).ok().and_then(char::from_u32) {
                        character_widths.insert(character, constant);
                    }
                    code += 1;
                }
            }
            index += 3;
            continue;
        }
        index += 1;
    }
}

/// `chr(start + offset)` as a code point; a negative or out-of-range code has no character.
fn code_point(start: i64, offset: usize) -> Option<char> {
    let code = start.checked_add(i64::try_from(offset).ok()?)?;
    u32::try_from(code).ok().and_then(char::from_u32)
}

/// pypdf's `_add_default_width`.
fn add_default_width(widths: &HashMap<char, f64>, flags: i64, space_char: char) -> f64 {
    if widths.is_empty() {
        return 500.0;
    }
    if let Some(space) = widths.get(&space_char).filter(|width| **width != 0.0) {
        if flags & 1 == 1 {
            return *space;
        }
        return (2.0 * space).trunc();
    }
    let valid: Vec<f64> = widths
        .values()
        .copied()
        .filter(|width| *width > 0.0)
        .collect();
    if valid.is_empty() {
        500.0
    } else {
        (valid.iter().sum::<f64>() / valid.len() as f64).floor()
    }
}

/// pypdf's `_parse_encoding`: the code -> character table, or a composite font's codec.
fn parse_encoding(document: &Document, dictionary: &Dictionary, sub_type: &str) -> Encoding {
    let standard = || Encoding::Table(named_table(b"StandardEncoding"));
    let Ok(encoding_object) = dictionary.get(b"Encoding") else {
        let base_font = dictionary
            .get(b"BaseFont")
            .ok()
            .and_then(|object| name(document, object));
        return match base_font.as_deref() {
            // pypdf matches the raw value, which still carries its `/`.
            Some("/Symbol") => Encoding::Table(named_table(b"Symbol")),
            Some("/ZapfDingbats") => Encoding::Table(named_table(b"ZapfDingbats")),
            _ => standard(),
        };
    };
    let (_, encoding_object) = dereference(document, encoding_object);
    match encoding_object {
        Object::Name(named) => match font_data::named_encoding(named) {
            Some(table) => Encoding::Table(from_table(table)),
            // pypdf's `_predefined_cmap` (and the `-UCS2-` CMaps) name a codec; an
            // unrecognised name on a composite font falls back to UTF-16BE.
            None => match codec_for(named) {
                Some(codec) => codec,
                None if sub_type == "Type0" => Encoding::Utf16Be,
                None => standard(),
            },
        },
        Object::Dictionary(encoding_dict) => {
            let base = encoding_dict
                .get(b"BaseEncoding")
                .ok()
                .and_then(|object| name(document, object))
                .and_then(|named| font_data::named_encoding(named.as_bytes()))
                .map(from_table)
                .unwrap_or_else(|| named_table(b"StandardEncoding"));
            Encoding::Table(apply_differences(document, encoding_dict, base))
        }
        _ => standard(),
    }
}

/// pypdf's `_predefined_cmap` for the UTF-16BE family, which is what composite fonts with
/// `/Identity-H` and the `Uni*` CMaps carry. The reference's CJK entries (`gbk`, `gb2312`,
/// `gb18030`, `cp950`, `cp932`) are not transcribed: a document using one would decode
/// differently here, and none is in this port's fixture set.
fn codec_for(named: &[u8]) -> Option<Encoding> {
    match named {
        b"Identity-H" | b"Identity-V" | b"UniCNS-UTF16-H" | b"UniCNS-UTF16-V"
        | b"UniGB-UTF16-H" | b"UniGB-UTF16-V" | b"UniJIS-UTF16-H" | b"UniJIS-UTF16-V" => {
            Some(Encoding::Utf16Be)
        }
        _ if named.windows(6).any(|window| window == b"-UCS2-") => Some(Encoding::Utf16Be),
        _ => None,
    }
}

/// One named `/Encoding`, pypdf's `charset_encoding`.
fn named_table(name: &[u8]) -> Box<[String; 256]> {
    match font_data::named_encoding(name) {
        Some(table) => from_table(table),
        None => Box::new(std::array::from_fn(|code| {
            char::from(code as u8).to_string()
        })),
    }
}

fn from_table(table: &'static [char; 256]) -> Box<[String; 256]> {
    Box::new(std::array::from_fn(|code| table[code].to_string()))
}

/// pypdf's `/Differences` loop: an integer sets the next code, a glyph name fills it.
fn apply_differences(
    document: &Document,
    encoding_dict: &Dictionary,
    mut encoding: Box<[String; 256]>,
) -> Box<[String; 256]> {
    let Ok(Object::Array(entries)) = encoding_dict.get_deref(b"Differences", document) else {
        return encoding;
    };
    let mut code: usize = 0;
    for entry in entries {
        let (_, entry) = dereference(document, entry);
        match entry {
            Object::Integer(value) => code = (*value).max(0) as usize,
            Object::Name(name) => {
                if code < 256 {
                    let glyph_name = String::from_utf8_lossy(name);
                    encoding[code] = glyph_name_to_unicode(&glyph_name)
                        .unwrap_or_else(|| glyph_name.into_owned());
                }
                code += 1;
            }
            // pypdf advances the code for anything that is neither an integer nor a name.
            _ => code += 1,
        }
    }
    encoding
}

/// pypdf's `_glyph_name_to_unicode`; the caller has already stripped the `/`.
fn glyph_name_to_unicode(name: &str) -> Option<String> {
    if let Some(character) = font_data::glyph(name) {
        return Some(character.to_string());
    }
    let code_point = name
        .strip_prefix("uni")
        .or_else(|| name.strip_prefix('u'))?;
    u32::from_str_radix(code_point, 16)
        .ok()
        .and_then(char::from_u32)
        .map(String::from)
}

/// pypdf's `_parse_to_unicode` for a simple font.
struct ToUnicode {
    /// The `/ToUnicode` map, keyed by source character.
    map: HashMap<char, String>,
    /// pypdf's `int_entry`: the source codes, which override the encoding's characters.
    codes: Vec<u32>,
}

fn parse_to_unicode(document: &Document, dictionary: &Dictionary) -> ToUnicode {
    let Ok(object) = dictionary.get(b"ToUnicode") else {
        return ToUnicode {
            map: HashMap::new(),
            codes: Vec::new(),
        };
    };
    let (_, object) = dereference(document, object);
    let Object::Stream(stream) = object else {
        return ToUnicode {
            map: HashMap::new(),
            codes: Vec::new(),
        };
    };
    let Ok(data) = stream.decompressed_content() else {
        return ToUnicode {
            map: HashMap::new(),
            codes: Vec::new(),
        };
    };
    parse_cmap(&data)
}

/// A token from a CMap program.
enum Token<'a> {
    Word(&'a [u8]),
    Hex(&'a [u8]),
    Open,
    Close,
}

/// pypdf's line reader over `beginbfchar`/`beginbfrange` blocks: pairs, and ranges in both
/// the `[ … ]` and the incrementing form. Code-space declarations and metadata are skipped,
/// as they are there.
fn parse_cmap(data: &[u8]) -> ToUnicode {
    let mut result = ToUnicode {
        map: HashMap::new(),
        codes: Vec::new(),
    };
    let tokens = tokens(data);
    let mut index = 0;
    while index < tokens.len() {
        let Token::Word(word) = tokens[index] else {
            index += 1;
            continue;
        };
        match word {
            b"beginbfchar" => {
                index += 1;
                while index + 1 < tokens.len() {
                    let (Token::Hex(source), Token::Hex(destination)) =
                        (&tokens[index], &tokens[index + 1])
                    else {
                        break;
                    };
                    if let (Some(code), Some(character)) =
                        (hex_value(source), source_character(source))
                        && result.map.len() < MAPPING_LIMIT
                    {
                        result
                            .map
                            .insert(character, decode_destination(destination));
                        result.codes.push(code);
                    }
                    index += 2;
                }
            }
            b"beginbfrange" => {
                index += 1;
                while index + 2 < tokens.len() {
                    let (Token::Hex(low), Token::Hex(high)) = (&tokens[index], &tokens[index + 1])
                    else {
                        break;
                    };
                    let Some(start) = hex_value(low) else { break };
                    let Some(end) = hex_value(high) else { break };
                    if start > end {
                        index += 3;
                        continue;
                    }
                    let bytes = low.len().max(high.len()).div_ceil(2);
                    match &tokens[index + 2] {
                        Token::Hex(destination) => {
                            let Some(mut target) = hex_value(destination) else {
                                break;
                            };
                            let width = destination.len().max(4);
                            for code in start..=end {
                                if result.map.len() >= MAPPING_LIMIT {
                                    break;
                                }
                                let hex = format!("{target:0width$X}", width = width);
                                if let Some(character) = unhex(hex.as_bytes())
                                    .as_deref()
                                    .and_then(decode_utf16_string)
                                {
                                    result.map.insert(counter_character(code, bytes), character);
                                    result.codes.push(code);
                                }
                                target += 1;
                            }
                            index += 3;
                        }
                        Token::Open => {
                            let mut entry = index + 3;
                            let mut code = start;
                            while entry < tokens.len() {
                                match &tokens[entry] {
                                    Token::Close => {
                                        entry += 1;
                                        break;
                                    }
                                    Token::Hex(destination) => {
                                        // The whole destination, as the reference keeps it: a
                                        // multi-character target is one mapping value. An empty
                                        // one is the placeholder the reference's line reader
                                        // turns into a broken line, and no mapping.
                                        let target = decode_destination(destination);
                                        if code <= end
                                            && result.map.len() < MAPPING_LIMIT
                                            && !target.is_empty()
                                        {
                                            result
                                                .map
                                                .insert(counter_character(code, bytes), target);
                                            result.codes.push(code);
                                        }
                                        code += 1;
                                        entry += 1;
                                    }
                                    _ => break,
                                }
                            }
                            index = entry;
                        }
                        _ => {
                            index += 3;
                        }
                    }
                }
            }
            _ => index += 1,
        }
    }
    result
}

/// pypdf's `__parse_bfrange__decode`: `code.to_bytes(nbytes, "big")` decoded as charmap for
/// a one-byte code space and as UTF-16BE otherwise.
fn counter_character(code: u32, nbytes: usize) -> char {
    match nbytes {
        1 => char::from(code as u8),
        _ => char::from_u32(code).unwrap_or('\u{fffd}'),
    }
}

/// pypdf's `"charmap" if map_dict[-1] == 1 else "utf-16-be"` for a source code.
fn source_character(source: &[u8]) -> Option<char> {
    let bytes = unhex(source)?;
    match bytes.len() {
        0 => None,
        1 => Some(char::from(bytes[0])),
        _ => utf16_be(&bytes),
    }
}

fn hex_value(source: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(source).ok()?;
    u32::from_str_radix(text, 16).ok()
}

/// `unhexlify` over a hex run; whitespace inside the run is dropped, as `prepare_cm` does.
fn unhex(source: &[u8]) -> Option<Vec<u8>> {
    let mut digits: Vec<u8> = Vec::with_capacity(source.len());
    for &byte in source {
        if byte.is_ascii_hexdigit() {
            digits.push(byte);
        } else if byte.is_ascii_whitespace() {
            continue;
        } else {
            return None;
        }
    }
    if digits.len() % 2 == 1 {
        digits.push(b'0');
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let text = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

fn utf16_be(bytes: &[u8]) -> Option<char> {
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
        .collect();
    String::from_utf16_lossy(&units).chars().next()
}

/// One `/ToUnicode` destination: `"charmap" if len(destination) < 4 else "utf-16-be"` in
/// pypdf's `parse_bfchar`.
fn decode_destination(destination: &[u8]) -> String {
    match unhex(destination) {
        Some(bytes) if bytes.len() == 1 => char::from(bytes[0]).to_string(),
        Some(bytes) if bytes.len() >= 2 => String::from_utf16_lossy(
            &bytes
                .chunks(2)
                .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))
                .collect::<Vec<u16>>(),
        ),
        _ => String::new(),
    }
}

/// The CMap tokenizer: whitespace and `%` comments separate tokens; `< …>` is one hex run.
fn tokens(data: &[u8]) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let byte = data[index];
        if byte.is_ascii_whitespace() || byte == 0 {
            index += 1;
        } else if byte == b'%' {
            while index < data.len() && data[index] != b'\n' && data[index] != b'\r' {
                index += 1;
            }
        } else if byte == b'<' {
            let start = index + 1;
            index = start;
            while index < data.len() && data[index] != b'>' {
                index += 1;
            }
            out.push(Token::Hex(&data[start..index.min(data.len())]));
            index += 1;
        } else if byte == b'[' {
            out.push(Token::Open);
            index += 1;
        } else if byte == b']' {
            out.push(Token::Close);
            index += 1;
        } else if matches!(byte, b'>' | b')' | b'{' | b'}') {
            // A stray closing delimiter: no token, but the scan must still advance.
            index += 1;
        } else {
            let start = index;
            while index < data.len()
                && !data[index].is_ascii_whitespace()
                && !matches!(data[index], b'<' | b'>' | b'[' | b']' | b'%')
            {
                index += 1;
            }
            out.push(Token::Word(&data[start..index]));
        }
    }
    out
}

/// pypdf's `cname in adobe_glyphs for cname in /CharProcs`: a Type3 font without a
/// `/ToUnicode` is interpretable only when every glyph is a standard Adobe name.
fn char_procs_are_glyphs(document: &Document, dictionary: &Dictionary) -> bool {
    match dictionary.get_deref(b"CharProcs", document) {
        Ok(Object::Dictionary(procs)) => procs.iter().all(|(name, _)| {
            let name = String::from_utf8_lossy(name);
            font_data::glyph(name.trim_start_matches('/')).is_some()
        }),
        _ => false,
    }
}

fn dereference<'a>(
    document: &'a Document,
    object: &'a Object,
) -> (Option<lopdf::ObjectId>, &'a Object) {
    document
        .dereference(object)
        .unwrap_or((None, &Object::Null))
}

fn name(document: &Document, object: &Object) -> Option<String> {
    let (_, object) = dereference(document, object);
    match object {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

fn integer(document: &Document, object: &Object) -> Option<i64> {
    let (_, object) = dereference(document, object);
    match object {
        Object::Integer(value) => Some(*value),
        Object::Real(value) => Some(*value as i64),
        _ => None,
    }
}

/// A number as the reference keeps it: `/W` and `/DW` values are stored unconverted, so a
/// fractional width stays fractional.
fn number(document: &Document, object: &Object) -> Option<f64> {
    let (_, object) = dereference(document, object);
    match object {
        Object::Integer(value) => Some(*value as f64),
        Object::Real(value) => Some(f64::from(*value)),
        _ => None,
    }
}
