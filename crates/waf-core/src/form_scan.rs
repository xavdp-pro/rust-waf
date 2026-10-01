//! Original form-value spans retained through whole-body decoding, never retokenized.
use crate::{
    inspect::{decode_once, needs_decode, scan_variants},
    profile::PolicyError,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};
type Result<T> = std::result::Result<T, PolicyError>;

pub(crate) struct FieldSpan {
    pub name: String,
    pub range: Range<usize>,
}

pub(crate) fn scan(
    input: &str,
    passes: usize,
    selected: &BTreeSet<&str>,
    emit: &mut impl FnMut(&str, &[FieldSpan]) -> Result<()>,
) -> Result<()> {
    if selected.is_empty() {
        return scan_variants(input, passes, true, true, &mut |text| emit(text, &[]));
    }
    // Only configured names occupy metadata. Arbitrarily many other parameters
    // cannot allocate a per-parameter map. A duplicate removes that binding.
    let mut bindings: BTreeMap<&str, Option<Range<usize>>> = BTreeMap::new();
    let mut offset = 0;
    for pair in input.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // A <=64-byte ASCII selector needs at most 192 encoded name bytes.
            if key.len() <= 192 {
                let decoded = decode_once(key, true, true)?;
                if let Some(name) = selected.get(decoded.as_str()) {
                    let start = offset + key.len() + 1;
                    bindings
                        .entry(name)
                        .and_modify(|range| *range = None)
                        .or_insert(Some(start..start + value.len()));
                }
            }
        } else if pair.len() <= 192 {
            let decoded = decode_once(pair, true, true)?;
            if let Some(name) = selected.get(decoded.as_str()) {
                // PHP/other parsers can consume a valueless duplicate as empty.
                bindings
                    .entry(name)
                    .and_modify(|range| *range = None)
                    .or_insert(None);
            }
        }
        offset += pair.len() + 1;
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
    emit(input, &spans)?;
    let mut current = Cow::Borrowed(input);
    for pass in 0..passes {
        if !needs_decode(&current, pass == 0) {
            return Ok(());
        }
        let mut decoded = String::with_capacity(current.len());
        let mut cursor = 0;
        for span in &mut spans {
            decoded.push_str(&decode_once(
                &current[cursor..span.range.start],
                pass == 0,
                pass == 0,
            )?);
            let start = decoded.len();
            decoded.push_str(&decode_once(
                &current[span.range.clone()],
                pass == 0,
                pass == 0,
            )?);
            cursor = span.range.end;
            span.range = start..decoded.len();
        }
        decoded.push_str(&decode_once(&current[cursor..], pass == 0, pass == 0)?);
        if decoded == current {
            return Ok(());
        }
        emit(&decoded, &spans)?;
        current = Cow::Owned(decoded);
    }
    if needs_decode(&current, false) && decode_once(&current, false, false)? != current {
        return Err(PolicyError("encoding_depth_exceeded".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_decoding_preserves_complete_views_and_error_codes() {
        let selected = BTreeSet::from(["secret", "second"]);
        for input in [
            "secret=needle",
            "a=1&secret=x%26other%3Dneedle&b=2",
            "a=%25FF&secret=%25FFneedle%25FF&b=%25FF",
            "secret=hello+world&second=x%2526y",
            "%73ecret=hello&second=%E2%82%AC",
            "secret=x&secret=y",
            "secret&secret=y",
            "secret=%zz",
            "a=%25&secret=%2525",
            "secret=%2525252541",
            "a=%F0%9F%98%80&secret=%F0%9F%98%80&second=%F0%9F%98%80",
        ] {
            let mut baseline = Vec::new();
            let baseline_result = scan_variants(input, 3, true, true, &mut |text| {
                baseline.push(text.to_owned());
                Ok(())
            });
            let mut actual = Vec::new();
            let actual_result = scan(input, 3, &selected, &mut |text, spans| {
                actual.push(text.to_owned());
                assert!(spans.len() <= selected.len());
                for span in spans {
                    assert!(text.get(span.range.clone()).is_some());
                }
                Ok(())
            });
            assert_eq!(baseline_result, actual_result, "{input}");
            // Both failures must discard completed scan evidence. The failing
            // callback order need not match, but successful views must be exact.
            if actual_result.is_ok() {
                assert_eq!(baseline, actual, "{input}");
            }
        }
    }

    #[test]
    fn unselected_parameter_count_does_not_expand_origin_metadata() {
        let input = "other=benign&".repeat(100_000) + "secret=needle";
        scan(
            &input,
            3,
            &BTreeSet::from(["secret"]),
            &mut |text, spans| {
                assert_eq!(spans.len(), 1);
                assert_eq!(&text[spans[0].range.clone()], "needle");
                Ok(())
            },
        )
        .unwrap();
    }
}
