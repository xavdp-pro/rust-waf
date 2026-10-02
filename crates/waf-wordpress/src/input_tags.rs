//! Bounded no-allowlist PHP 8.3 tag-removal projection of valid UTF-8 inputs.
//! A lexical projection, not an HTML sanitizer or a payload safety verdict.
//! Compatibility reference: PHP 8.3.35 php_strip_tags_ex (PHP Group).
//! See licenses/php-8.3.35.txt for the reference implementation notice.
use super::{Result, bad};

#[derive(Clone, Copy)]
enum Mode {
    Text,
    Tag,
    Processing,
    Declaration,
    Comment,
}

pub(crate) fn strip(value: &str) -> Result<String> {
    if value.len() > 8192 || value.contains('\0') {
        return Err(bad("invalid_wordpress_projection_value"));
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut mode = Mode::Text;
    let mut quote = None;
    let mut last = 0;
    let mut depth = 0usize;
    let mut parentheses = 0i32;
    let mut xml = false;
    for (index, &byte) in bytes.iter().enumerate() {
        let previous = index.checked_sub(1).map(|i| bytes[i]);
        let less_space = bytes
            .get(index + 1)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c));
        let close = byte == b'>' && depth == 0 && quote.is_none();
        match mode {
            Mode::Text => match byte {
                b'<' if quote.is_none() && !less_space => {
                    mode = Mode::Tag;
                    last = b'<';
                }
                b'>' if depth != 0 => depth -= 1,
                b'<' | b'>' if quote.is_some() => {}
                _ => output.push(byte),
            },
            Mode::Tag => match byte {
                b'<' if quote.is_none() && !less_space => depth += 1,
                b'>' if depth != 0 => depth -= 1,
                b'>' if close => {
                    last = b'>';
                    if !(xml && previous == Some(b'-')) {
                        mode = Mode::Text;
                        quote = None;
                        xml = false;
                    }
                }
                b'\'' | b'"' => toggle(&mut quote, byte),
                b'!' if previous == Some(b'<') => {
                    mode = Mode::Declaration;
                    last = byte;
                }
                b'?' if previous == Some(b'<') => {
                    mode = Mode::Processing;
                    parentheses = 0;
                }
                _ => {}
            },
            Mode::Processing => match byte {
                b'(' | b')' if last != b'\'' && last != b'"' => {
                    last = byte;
                    parentheses += if byte == b'(' { 1 } else { -1 };
                }
                b'>' if depth != 0 => depth -= 1,
                b'>' if close && parentheses == 0 && last != b'"' && previous == Some(b'?') => {
                    mode = Mode::Text;
                    quote = None;
                }
                b'\'' | b'"' if previous != Some(b'\\') => {
                    if last == byte {
                        last = 0;
                    } else if last != b'\\' {
                        last = byte;
                    }
                    toggle(&mut quote, byte);
                }
                b'l' | b'L'
                    if index > 4 && bytes[index - 4..=index].eq_ignore_ascii_case(b"<?xml") =>
                {
                    mode = Mode::Tag;
                    xml = true;
                }
                _ => {}
            },
            Mode::Declaration => match byte {
                b'>' if depth != 0 => depth -= 1,
                b'>' if close => {
                    mode = Mode::Text;
                    quote = None;
                }
                b'\'' | b'"' if previous != Some(b'\\') => toggle(&mut quote, byte),
                b'-' if index >= 2 && &bytes[index - 2..index] == b"!-" => mode = Mode::Comment,
                b'e' | b'E'
                    if index > 6 && bytes[index - 6..=index].eq_ignore_ascii_case(b"doctype") =>
                {
                    mode = Mode::Tag;
                }
                _ => {}
            },
            Mode::Comment => {
                if close && index >= 2 && &bytes[index - 2..index] == b"--" {
                    mode = Mode::Text;
                    quote = None;
                }
            }
        }
    }
    // Removed spans start/end at ASCII delimiters, never within a UTF-8 scalar.
    String::from_utf8(output).map_err(|_| bad("invalid_wordpress_projection_utf8"))
}

fn toggle(quote: &mut Option<u8>, byte: u8) {
    if quote.is_none() {
        *quote = Some(byte);
    } else if *quote == Some(byte) {
        *quote = None;
    }
}

#[cfg(test)]
mod tests {
    use super::strip;

    #[test]
    fn text_tags_quotes_and_incomplete_spans() {
        for (input, expected) in [
            ("", ""),
            ("0", "0"),
            ("é猫>text", "é猫>text"),
            ("<b>alpha</b>", "alpha"),
            ("a<<b>>z", "az"),
            ("<b title=\"a>b\">alpha</b>", "alpha"),
            ("<b title='a>b'>alpha</b>", "alpha"),
            ("a< unfinished", "a< unfinished"),
            ("a<1>z", "az"),
            ("a<b unfinished", "a"),
            ("a<b title=\"x>z", "a"),
            ("&lt;b&gt;alpha&lt;/b&gt;", "&lt;b&gt;alpha&lt;/b&gt;"),
            ("a<!-- > -->z", "az"),
            ("a<!-- unfinished", "a"),
            ("<!DOCTYPE html>alpha", "alpha"),
            ("<?php echo \"marker\"; ?>alpha", "alpha"),
            ("<?xml x=\"y\"?>alpha", "alpha"),
        ] {
            assert_eq!(strip(input).unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn processing_parentheses_and_offset_sensitive_xml_transitions() {
        for (input, expected) in [
            ("<?(?>z", ""),
            ("<?()?>z", "z"),
            ("<?)?>z", ""),
            ("<?xml>z", ""),
            ("x<?xml>z", "xz"),
            ("x<?XML>z", "xz"),
            ("x<?xml -->z", "x"),
            ("a<!--' > -->z", "az"),
            ("x<!doctype '>'>z", "xz"),
        ] {
            assert_eq!(strip(input).unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn bound_and_utf8_preservation() {
        let input = "é".repeat(4096);
        assert_eq!(strip(&input).unwrap(), input);
        assert!(strip(&"x".repeat(8193)).is_err());
        assert!(strip("a\0b").is_err());
        assert_eq!(strip(&"<".repeat(8192)).unwrap(), "");
        assert_eq!(strip("猫<b>é</b>😀").unwrap(), "猫é😀");
    }
    #[test]
    #[ignore = "Diagnostic collection: compare with an independent PHP oracle"]
    fn collect_short_tag_projection_fingerprint() {
        use sha2::{Digest, Sha256};
        let alphabet = [
            "a", "<", ">", "!", "?", "-", "'", "\"", "\\", "(", ")", " ", "é",
        ];
        let mut hash = Sha256::new();
        let mut count = 0;
        for width in 0..=4u32 {
            for mut code in 0..13usize.pow(width) {
                let mut input = String::new();
                for _ in 0..width {
                    input.push_str(alphabet[code % 13]);
                    code /= 13;
                }
                for prefix in ["", "x"] {
                    for suffix in ["", "z"] {
                        let value = format!("{prefix}{input}{suffix}");
                        let result = strip(&value).unwrap();
                        hash.update((value.len() as u32).to_be_bytes());
                        hash.update(value.as_bytes());
                        hash.update((result.len() as u32).to_be_bytes());
                        hash.update(result.as_bytes());
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, 123764);
        let digest = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        println!("TAG_PROJECTION_FINGERPRINT {{\"cases\":{count},\"sha256\":\"{digest}\"}}");
    }
}
