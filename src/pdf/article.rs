//! The reference's `cut_article` (`pdf_text.py:88-131`): one article out of a consolidated
//! text, with its ambiguity rule.
//!
//! A superscript article is first looked up in its exact form (`Art. 43^1.`). Only when that is
//! absent is the flattened form some PDFs print (`Art. 431.`) accepted, and only if it is
//! unambiguous: exactly one such heading, and the heading before it is the base article
//! (`Art. 43.`) or the previous superscript one (`Art. 43^1.` for 43^2). Anything else is an
//! ambiguity the caller reports rather than guessing between `43^1` and a real `Art. 431`.

use std::sync::LazyLock;

use regex::Regex;

/// The flattened heading is ambiguous: the value is the flat label (e.g. `431`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousArticle(pub String);

fn art_head() -> &'static Regex {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^Art\.\s*(\d+[a-z]*(?:\^\d+)?)\.(?:\s|$)")
            .expect("the article-head pattern is valid")
    });
    &PATTERN
}

fn heading() -> &'static Regex {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:Art\.\s*\d|DZIAŁ\b|Dział\b|ROZDZIAŁ\b|Rozdział\b|TYTUŁ\b|Tytuł\b|KSIĘGA\b|Księga\b)",
        )
        .expect("the heading pattern is valid")
    });
    &PATTERN
}

/// One article: its heading line through the line before the next heading.
fn article_end(lines: &[&str], index: usize) -> String {
    let mut end = index + 1;
    while end < lines.len() && !heading().is_match(lines[end]) {
        end += 1;
    }
    lines[index..end].join("\n")
}

/// The article whose ELI suffix is `suffix` (`133`, `133a`, `449_1`), or `None` when absent.
pub fn cut_article(text: &str, suffix: &str) -> Result<Option<String>, AmbiguousArticle> {
    let (number, superscript) = match suffix.split_once('_') {
        Some((number, superscript)) => (number, Some(superscript)),
        None => (suffix, None),
    };
    let lines: Vec<&str> = text.split('\n').collect();
    let heads: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            art_head()
                .captures(line)
                .map(|captures| (index, captures[1].to_owned()))
        })
        .collect();

    let exact = match superscript {
        Some(superscript) => format!("{number}^{superscript}"),
        None => number.to_owned(),
    };
    for (index, label) in &heads {
        if *label == exact {
            return Ok(Some(article_end(&lines, *index)));
        }
    }

    let Some(superscript) = superscript else {
        return Ok(None);
    };
    let flat = format!("{number}{superscript}");
    let hits: Vec<usize> = heads
        .iter()
        .enumerate()
        .filter(|(_, (_, label))| *label == flat)
        .map(|(position, _)| position)
        .collect();
    if hits.is_empty() {
        return Ok(None);
    }

    let mut previous_ok = vec![number.to_owned()];
    // `int(sup)` cannot fail for a suffix `article_id` produced (superscript digits only).
    if let Ok(superscript) = superscript.parse::<u32>()
        && superscript > 1
    {
        previous_ok.push(format!("{number}^{}", superscript - 1));
        previous_ok.push(format!("{number}{}", superscript - 1));
    }
    let previous = hits[0]
        .checked_sub(1)
        .and_then(|position| heads.get(position))
        .map(|(_, label)| label.as_str());
    if hits.len() != 1
        || hits[0] == 0
        || !previous.is_some_and(|label| previous_ok.iter().any(|ok| ok == label))
    {
        return Err(AmbiguousArticle(flat));
    }
    Ok(Some(article_end(&lines, heads[hits[0]].0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "Art. 42.\nfirst\nArt. 43.\nbase\nArt. 43^1.\nsup one\nArt. 44.\nlast";

    #[test]
    fn the_exact_superscript_heading_wins() {
        assert_eq!(
            cut_article(TEXT, "43_1").expect("unambiguous"),
            Some("Art. 43^1.\nsup one".to_owned())
        );
    }

    #[test]
    fn a_base_article_stops_at_the_next_heading() {
        assert_eq!(
            cut_article(TEXT, "43").expect("unambiguous"),
            Some("Art. 43.\nbase".to_owned())
        );
    }

    #[test]
    fn a_flattened_heading_is_accepted_after_its_base_article() {
        let flat = "Art. 43.\nbase\nArt. 431.\nflat";
        assert_eq!(
            cut_article(flat, "43_1").expect("unambiguous"),
            Some("Art. 431.\nflat".to_owned())
        );
    }

    #[test]
    fn a_flattened_heading_without_its_base_is_ambiguous() {
        let flat = "Art. 42.\nother\nArt. 431.\nflat";
        assert_eq!(
            cut_article(flat, "43_1").expect_err("ambiguous"),
            AmbiguousArticle("431".to_owned())
        );
    }

    #[test]
    fn an_absent_article_is_none() {
        assert_eq!(cut_article(TEXT, "99").expect("absent"), None);
        assert_eq!(cut_article(TEXT, "99_1").expect("absent"), None);
    }
}
