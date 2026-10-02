//! Strict, borrowed physical layout for provenance; Multer remains the syntax parser.
use crate::{form_path::FormPath, form_scan::FieldSpan, profile::PolicyError};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

pub struct Part<'a> {
    pub name: &'a str,
    pub is_file: bool,
    pub value: Range<usize>,
}

/// Qualified media has exactly one unambiguous boundary parameter.
/// Other valid MIME parameter shapes remain inspected without field origins.
pub fn qualified_boundary(content_type: &str) -> Option<String> {
    let mut items = content_type.split(';');
    if !items
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    let (key, value) = items.next()?.split_once('=')?;
    if key.trim() != "boundary" || items.next().is_some() {
        return None;
    }
    let value = value.trim();
    let value = if value.starts_with('"') {
        value.strip_prefix('"')?.strip_suffix('"')?
    } else {
        value
    };
    if value.is_empty()
        || value.len() > 70
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&b))
    {
        return None;
    }
    let parsed = multer::parse_boundary(content_type).ok()?;
    (parsed == value).then_some(parsed)
}

fn position(input: &[u8], needle: &[u8]) -> Option<usize> {
    input
        .windows(needle.len())
        .position(|window| window == needle)
}

fn disposition(input: &str) -> Option<(&str, bool)> {
    let (kind, mut rest) = input.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("form-data") {
        return None;
    }
    let mut name = None;
    let mut file = false;
    let mut attributes = BTreeSet::new();
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        let end = rest.find('=')?;
        let key = rest[..end].trim().to_ascii_lowercase();
        if !["name", "filename"].contains(&key.as_str()) || !attributes.insert(key.clone()) {
            return None;
        }
        rest = rest[end + 1..].trim_start_matches([' ', '\t']);
        let value;
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            value = &quoted[..end];
            if value.contains(['\\', '\0', '\r', '\n']) {
                return None;
            }
            rest = &quoted[end + 1..];
        } else {
            let end = rest.find(';').unwrap_or(rest.len());
            value = rest[..end].trim();
            if value.is_empty() || value.bytes().any(|b| b <= b' ' || b == b'"' || b == b'\\') {
                return None;
            }
            rest = &rest[end..];
        }
        if key == "name" {
            if value.is_empty() || value.len() > 1024 {
                return None;
            }
            name = Some(value);
        } else {
            file = true;
        }
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            return Some((name?, file));
        }
        rest = rest.strip_prefix(';')?;
    }
}

/// Unsupported framing/headers withhold provenance, not normal syntax inspection.
/// Values remain borrowed from the original body and metadata is bounded by max_parts.
pub fn layout<'a>(input: &'a [u8], boundary: &str, max_parts: usize) -> Option<Vec<Part<'a>>> {
    if boundary.is_empty()
        || boundary.len() > 70
        || !boundary.is_ascii()
        || boundary.contains(['\0', '\r', '\n'])
        || max_parts == 0
    {
        return None;
    }
    let marker = format!("--{boundary}").into_bytes();
    let separator = format!("\r\n--{boundary}").into_bytes();
    let mut cursor = marker.len();
    if !input.starts_with(&marker) {
        return None;
    }
    let mut parts = Vec::new();
    loop {
        let tail = input.get(cursor..)?;
        if tail.starts_with(b"--") {
            let tail = &tail[2..];
            return (tail.is_empty() || tail == b"\r\n").then_some(parts);
        }
        if !tail.starts_with(b"\r\n") || parts.len() >= max_parts {
            return None;
        }
        cursor += 2;
        let header_length = position(input.get(cursor..)?, b"\r\n\r\n")?;
        if header_length > 8192 {
            return None;
        }
        let headers = std::str::from_utf8(&input[cursor..cursor + header_length]).ok()?;
        let mut seen = BTreeSet::new();
        let mut selected = None;
        for line in headers.split("\r\n") {
            let (key, value) = line.split_once(':')?;
            let key = key.to_ascii_lowercase();
            if !["content-disposition", "content-type"].contains(&key.as_str())
                || !seen.insert(key.clone())
            {
                return None;
            }
            if key == "content-disposition" {
                selected = Some(disposition(value.trim())?);
            }
        }
        let (name, is_file) = selected?;
        let start = cursor + header_length + 4;
        let end = start + position(input.get(start..)?, &separator)?;
        parts.push(Part {
            name,
            is_file,
            value: start..end,
        });
        cursor = end + separator.len();
    }
}

pub(crate) fn spans(
    parts: &[Part<'_>],
    body: &[u8],
    selected: &BTreeSet<&str>,
) -> Result<Vec<FieldSpan>, PolicyError> {
    let paths = selected
        .iter()
        .map(|name| {
            FormPath::parse(name)
                .map(|path| (*name, path))
                .ok_or_else(|| PolicyError("invalid_form_selector".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut bindings: BTreeMap<&str, Option<Range<usize>>> = BTreeMap::new();
    for part in parts.iter().filter(|part| !part.is_file) {
        let candidate = FormPath::canonical_prefix(part.name);
        let root = part.name.split('[').next().unwrap_or("");
        for (name, path) in &paths {
            if part.name == *name {
                let range = std::str::from_utf8(&body[part.value.clone()])
                    .is_ok()
                    .then_some(part.value.clone());
                bindings
                    .entry(name)
                    .and_modify(|old| *old = None)
                    .or_insert(range);
            } else if candidate.as_ref().map_or(root == path.root(), |candidate| {
                candidate.is_prefix_of(path) || path.is_prefix_of(candidate)
            }) {
                bindings.insert(name, None);
            }
        }
    }
    let mut spans = bindings
        .into_iter()
        .filter_map(|(name, range)| {
            range.map(|range| FieldSpan {
                name: name.to_owned(),
                range,
            })
        })
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| span.range.start);
    Ok(spans)
}

/// Verify every physical part against the normal MIME parser before assigning origins.
/// Verify that the borrowed physical layout agrees with the independent MIME parser.
pub async fn agrees(
    body: bytes::Bytes,
    boundary: &str,
    parts: &[Part<'_>],
    max_parts: usize,
) -> Result<bool, PolicyError> {
    let input = body.clone();
    let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
    let mut multipart = multer::Multipart::new(stream, boundary);
    let mut count = 0;
    let mut agrees = true;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| PolicyError("invalid_multipart".into()))?
    {
        if count >= max_parts {
            return Err(PolicyError("multipart_part_limit".into()));
        }
        let part = parts.get(count);
        agrees &= part.is_some_and(|part| {
            field.name() == Some(part.name) && field.file_name().is_some() == part.is_file
        });
        let value = field
            .bytes()
            .await
            .map_err(|_| PolicyError("invalid_multipart".into()))?;
        agrees &= part.is_some_and(|part| {
            input
                .get(part.value.clone())
                .is_some_and(|expected| value.as_ref() == expected)
        });
        count += 1;
    }
    Ok(agrees && count == parts.len())
}

pub(crate) fn lossy_offsets(body: &[u8], spans: &mut [FieldSpan]) {
    let mut original_cursor = 0;
    let mut text_cursor = 0;
    for span in spans {
        text_cursor += String::from_utf8_lossy(&body[original_cursor..span.range.start]).len();
        original_cursor = span.range.end;
        let start = text_cursor;
        text_cursor += String::from_utf8_lossy(&body[span.range.clone()]).len();
        span.range = start..text_cursor;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BODY: &[u8] = b"--b\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\nneedle\r\n--b\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"file;name.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\xff\r\n--b--\r\n";
    #[test]
    fn boundary_contract_withholds_ambiguous_or_unqualified_parameters() {
        for header in [
            "multipart/form-data; boundary=b",
            "multipart/form-data; boundary=\"b\"",
            "Multipart/Form-Data; boundary=b",
        ] {
            assert_eq!(qualified_boundary(header).as_deref(), Some("b"), "{header}");
        }
        for header in [
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=b; boundary=other",
            "multipart/form-data; boundary=b; boundary=b",
            "multipart/form-data; boundary=b; charset=utf-8",
            "multipart/form-data; boundary*=b",
            "multipart/form-data; Boundary=b",
            "multipart/form-data; boundary=\"b b\"",
            "multipart/form-data; boundary=\"b\\b\"",
            "multipart/form-data; boundary=\"b",
            "application/json; boundary=b",
        ] {
            assert!(qualified_boundary(header).is_none(), "{header}");
        }
        assert!(
            qualified_boundary(&format!("multipart/form-data; boundary={}", "b".repeat(71)))
                .is_none()
        );
    }
    #[test]
    fn physical_layout_is_borrowed_bounded_and_withholds_ambiguous_headers() {
        let parts = layout(BODY, "b", 2).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "secret");
        assert!(!parts[0].is_file);
        assert_eq!(&BODY[parts[0].value.clone()], b"needle");
        assert!(parts[1].is_file);
        assert_eq!(&BODY[parts[1].value.clone()], b"\xff");
        assert!(layout(BODY, "b", 1).is_none());
        assert!(layout(BODY, "", 2).is_none());
        assert!(layout(BODY, "b", 0).is_none());
        let base =
            b"--b\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\nneedle\r\n--b--\r\n";
        let text = std::str::from_utf8(base).unwrap();
        for bad in [
            text.replace("name=\"secret\"", "name=\"secret\"; name=\"other\""),
            text.replace("name=\"secret\"", "name*=\"secret\""),
            text.replace(
                "\r\n\r\n",
                "\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\n",
            ),
            text.replace("\r\n\r\n", "\r\nContent-Transfer-Encoding: base64\r\n\r\n"),
            format!("preamble\r\n{text}"),
            format!("{text}epilogue"),
            text.replace("name=\"secret\"", "name=\"sec\\ret\""),
        ] {
            assert!(layout(bad.as_bytes(), "b", 8).is_none());
        }
    }
    #[tokio::test]
    async fn independent_mime_comparison_rejects_name_value_count_and_file_disagreement() {
        let body = bytes::Bytes::from_static(BODY);
        let mut parts = layout(BODY, "b", 2).unwrap();
        assert!(agrees(body.clone(), "b", &parts, 2).await.unwrap());
        parts[0].name = "other";
        assert!(!agrees(body.clone(), "b", &parts, 2).await.unwrap());
        parts[0].name = "secret";
        parts[0].is_file = true;
        assert!(!agrees(body.clone(), "b", &parts, 2).await.unwrap());
        parts[0].is_file = false;
        parts[0].value.end -= 1;
        assert!(!agrees(body.clone(), "b", &parts, 2).await.unwrap());
        let parts = layout(BODY, "b", 2).unwrap();
        assert!(!agrees(body.clone(), "b", &parts[..1], 2).await.unwrap());
        let mut invalid = layout(BODY, "b", 2).unwrap();
        invalid[0].value.end = usize::MAX;
        assert!(!agrees(body.clone(), "b", &invalid, 2).await.unwrap());
        assert!(agrees(body, "b", &parts, 1).await.is_err());
    }
}
