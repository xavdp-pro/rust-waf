//! Bounded, opt-in projections of one selected application input. Never rewrites HTTP bytes.
use super::{Result, bad};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

pub(crate) const MAX_STAGES: usize = 16;
const VALUE_LIMIT: usize = 8192;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Stage {
    Replace {
        pattern: String,
        replacement: String,
    },
    RemoveSequences {
        sequences: Vec<String>,
    },
    Trim {
        characters: String,
    },
    BeforeQuery {},
    FormEncodeSegments {
        skip_pattern: String,
        skip_if_decoding_changes: bool,
        lowercase_when_escaped: bool,
    },
    EmptyFallback {
        value: String,
    },
}
pub(crate) enum Token {
    Literal(String),
    Group(usize),
}
pub(crate) enum CompiledStage {
    Replace {
        pattern: Regex,
        tokens: Vec<Token>,
    },
    RemoveSequences(Vec<String>),
    Trim(String),
    BeforeQuery,
    FormEncodeSegments {
        skip: Regex,
        skip_changed: bool,
        lowercase: bool,
    },
    EmptyFallback(String),
}

fn pattern(value: &str) -> Result<Regex> {
    if value.is_empty() || value.len() > 2048 {
        return Err(bad("invalid_wordpress_projection_pattern"));
    }
    RegexBuilder::new(value)
        .size_limit(64 * 1024)
        .dfa_size_limit(64 * 1024)
        .build()
        .map_err(|_| bad("invalid_wordpress_projection_pattern"))
}
impl Stage {
    pub(crate) fn compile(&self) -> Result<CompiledStage> {
        Ok(match self {
            Self::Replace {
                pattern: source,
                replacement,
            } => {
                let pattern = pattern(source)?;
                if replacement.len() > 1024 || replacement.contains('\0') {
                    return Err(bad("invalid_wordpress_projection_replacement"));
                }
                // Only explicit ${N} references are accepted. No implicit/unknown capture deletion.
                let mut tokens = Vec::new();
                let mut rest = replacement.as_str();
                while let Some(index) = rest.find('$') {
                    tokens.push(Token::Literal(rest[..index].into()));
                    rest = &rest[index..];
                    let end = rest
                        .find('}')
                        .ok_or_else(|| bad("invalid_wordpress_projection_replacement"))?;
                    let number = rest
                        .get(2..end)
                        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or_else(|| bad("invalid_wordpress_projection_replacement"))?;
                    if !rest.starts_with("${") {
                        return Err(bad("invalid_wordpress_projection_replacement"));
                    }
                    let group: usize = number
                        .parse()
                        .map_err(|_| bad("invalid_wordpress_projection_replacement"))?;
                    if group >= pattern.captures_len() || tokens.len() >= 32 {
                        return Err(bad("invalid_wordpress_projection_replacement"));
                    }
                    tokens.push(Token::Group(group));
                    rest = &rest[end + 1..];
                }
                tokens.push(Token::Literal(rest.into()));
                if tokens.len() > 32 {
                    return Err(bad("invalid_wordpress_projection_replacement"));
                }
                CompiledStage::Replace { pattern, tokens }
            }
            Self::RemoveSequences { sequences } => {
                // Equal-length words without prefix/suffix overlaps have a unique deletion
                // fixed point. Streaming removal therefore agrees with repeated global deletion.
                let width = sequences.first().map_or(0, |s| s.len());
                if sequences.is_empty()
                    || sequences.len() > 8
                    || !(2..=64).contains(&width)
                    || sequences
                        .iter()
                        .any(|s| s.len() != width || s.contains('\0'))
                {
                    return Err(bad("invalid_wordpress_projection_sequences"));
                }
                for (i, left) in sequences.iter().enumerate() {
                    for (j, right) in sequences.iter().enumerate() {
                        if (i != j && left == right)
                            || (1..width)
                                .any(|n| left.as_bytes()[width - n..] == right.as_bytes()[..n])
                        {
                            return Err(bad("ambiguous_wordpress_projection_sequences"));
                        }
                    }
                }
                CompiledStage::RemoveSequences(sequences.clone())
            }
            Self::Trim { characters } => {
                if characters.is_empty() || characters.len() > 64 || characters.contains('\0') {
                    return Err(bad("invalid_wordpress_projection_trim"));
                }
                CompiledStage::Trim(characters.clone())
            }
            Self::BeforeQuery {} => CompiledStage::BeforeQuery,
            Self::FormEncodeSegments {
                skip_pattern,
                skip_if_decoding_changes,
                lowercase_when_escaped,
            } => CompiledStage::FormEncodeSegments {
                skip: pattern(skip_pattern)?,
                skip_changed: *skip_if_decoding_changes,
                lowercase: *lowercase_when_escaped,
            },
            Self::EmptyFallback { value } => {
                if value.is_empty() || value.len() > 256 || value.contains('\0') {
                    return Err(bad("invalid_wordpress_projection_fallback"));
                }
                CompiledStage::EmptyFallback(value.clone())
            }
        })
    }
}

fn append(output: &mut String, value: &str) -> Result<()> {
    if output.len() + value.len() > VALUE_LIMIT {
        return Err(bad("wordpress_projection_value_limit"));
    }
    output.push_str(value);
    Ok(())
}
fn decoding_changes(value: &str) -> bool {
    value.bytes().any(|b| b == b'+')
        || value
            .as_bytes()
            .windows(3)
            .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}
pub(crate) fn apply(stages: &[CompiledStage], mut value: String) -> Result<String> {
    if value.len() > VALUE_LIMIT || value.contains('\0') {
        return Err(bad("wordpress_projection_value_limit"));
    }
    for stage in stages {
        value = match stage {
            CompiledStage::Replace { pattern, tokens } => {
                let mut out = String::new();
                let mut end = 0;
                for captures in pattern.captures_iter(&value) {
                    let matched = captures.get(0).unwrap();
                    append(&mut out, &value[end..matched.start()])?;
                    for token in tokens {
                        match token {
                            Token::Literal(text) => append(&mut out, text)?,
                            Token::Group(index) => {
                                if let Some(part) = captures.get(*index) {
                                    append(&mut out, part.as_str())?;
                                }
                            }
                        }
                    }
                    end = matched.end();
                }
                append(&mut out, &value[end..])?;
                out
            }
            CompiledStage::RemoveSequences(sequences) => {
                let mut out = String::with_capacity(value.len());
                for character in value.chars() {
                    out.push(character);
                    while let Some(sequence) = sequences.iter().find(|s| out.ends_with(s.as_str()))
                    {
                        out.truncate(out.len() - sequence.len());
                    }
                }
                out
            }
            CompiledStage::Trim(chars) => value.trim_matches(|c| chars.contains(c)).into(),
            CompiledStage::BeforeQuery => value.split('?').next().unwrap().into(),
            CompiledStage::EmptyFallback(fallback) => {
                if value.is_empty() {
                    fallback.clone()
                } else {
                    value
                }
            }
            CompiledStage::FormEncodeSegments {
                skip,
                skip_changed,
                lowercase,
            } => {
                let mut out = String::new();
                for (index, segment) in value.split('/').enumerate() {
                    if index > 0 {
                        append(&mut out, "/")?;
                    }
                    let encoded =
                        if skip.is_match(segment) || (*skip_changed && decoding_changes(segment)) {
                            segment.into()
                        } else {
                            let mut encoded = String::new();
                            for byte in segment.bytes() {
                                if byte.is_ascii_alphanumeric() || b"-_.".contains(&byte) {
                                    append(&mut encoded, &(byte as char).to_string())?;
                                } else if byte == b' ' {
                                    append(&mut encoded, "+")?;
                                } else {
                                    append(&mut encoded, &format!("%{byte:02X}"))?;
                                }
                            }
                            encoded
                        };
                    if *lowercase && decoding_changes(&encoded) {
                        append(&mut out, &encoded.to_ascii_lowercase())?;
                    } else {
                        append(&mut out, &encoded)?;
                    }
                }
                out
            }
        };
        if value.len() > VALUE_LIMIT || value.contains('\0') {
            return Err(bad("wordpress_projection_value_limit"));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn project(stages: serde_json::Value, input: &str) -> Result<String> {
        let stages: Vec<Stage> = serde_json::from_value(stages).unwrap();
        let compiled = stages
            .iter()
            .map(Stage::compile)
            .collect::<Result<Vec<_>>>()?;
        apply(&compiled, input.into())
    }
    #[test]
    fn captures_unicode_zero_width_and_order_preserve_exact_projection() {
        assert_eq!(
            project(
                json!([
                    {"kind":"replace","pattern":"^item:([^?]+)","replacement":"/${1}"},
                    {"kind":"replace","pattern":"[ ]","replacement":"%20"},
                    {"kind":"before_query"},
                    {"kind":"trim","characters":"/"}
                ]),
                "item:café noir?keep=1"
            )
            .unwrap(),
            "café%20noir"
        );
        assert_eq!(
            project(
                json!([{ "kind":"replace","pattern":"^|$","replacement":"x" }]),
                "é"
            )
            .unwrap(),
            "xéx"
        );
        assert_eq!(
            project(
                json!([{ "kind":"replace","pattern":"(a)?b","replacement":"${1}" },
            {"kind":"empty_fallback","value":"home"}]),
                "b"
            )
            .unwrap(),
            "home"
        );
        assert_eq!(
            project(json!([{ "kind":"empty_fallback","value":"home"}]), "0").unwrap(),
            "0"
        );
    }
    #[test]
    fn segment_encoding_is_byte_based_and_has_explicit_skip_and_case_semantics() {
        let stage = json!([{"kind":"form_encode_segments","skip_pattern":"[~]",
            "skip_if_decoding_changes":true,"lowercase_when_escaped":false}]);
        for (input, output) in [
            ("/A B/café/", "/A+B/caf%C3%A9/"),
            ("a+b", "a+b"),
            ("%2F", "%2F"),
            ("%xx", "%25xx"),
            ("mark!~", "mark!~"),
            ("_-.*", "_-.%2A"),
            ("//", "//"),
        ] {
            assert_eq!(project(stage.clone(), input).unwrap(), output);
        }
        assert_eq!(
            project(
                json!([{"kind":"form_encode_segments","skip_pattern":"[~]",
            "skip_if_decoding_changes":true,"lowercase_when_escaped":true}]),
                "Plain/A B/%AF/~ABC"
            )
            .unwrap(),
            "Plain/a+b/%af/~ABC"
        );
        assert_eq!(
            project(
                json!([{"kind":"form_encode_segments","skip_pattern":"[~]",
            "skip_if_decoding_changes":false,"lowercase_when_escaped":false}]),
                "%2F/a+b"
            )
            .unwrap(),
            "%252F/a%2Bb"
        );
    }
    #[test]
    fn expansion_limits_fail_instead_of_truncating_or_allocating_unbounded_replacements() {
        assert!(project(json!([]), &"a".repeat(8193)).is_err());
        assert!(project(json!([]), "a\0b").is_err());
        for stages in [
            json!([{ "kind":"replace","pattern":"(.*)","replacement":"${1}${1}" }]),
            json!([{ "kind":"replace","pattern":"", "replacement":"x" }]),
            json!([{ "kind":"form_encode_segments","skip_pattern":"never","skip_if_decoding_changes":false,"lowercase_when_escaped":false }]),
        ] {
            assert!(project(stages, &"!".repeat(8192)).is_err());
        }
        // A nonempty regex that matches empty positions still has bounded insertion output.
        assert!(
            project(
                json!([{ "kind":"replace","pattern":"a*","replacement":"xx" }]),
                &"b".repeat(4096)
            )
            .is_err()
        );
        assert_eq!(
            project(
                json!([{ "kind":"replace","pattern":"a","replacement":"b" }]),
                &"a".repeat(8192)
            )
            .unwrap()
            .len(),
            8192
        );
    }
    #[test]
    fn invalid_projection_contracts_fail_compilation() {
        for value in [
            json!({"kind":"replace","pattern":"(a)","replacement":"${2}"}),
            json!({"kind":"replace","pattern":"a","replacement":"$1"}),
            json!({"kind":"replace","pattern":"a","replacement":"${name}"}),
            json!({"kind":"replace","pattern":"a","replacement":"${999999999999999999999999}"}),
            json!({"kind":"replace","pattern":"[","replacement":""}),
            json!({"kind":"trim","characters":""}),
            json!({"kind":"empty_fallback","value":""}),
            json!({"kind":"form_encode_segments","skip_pattern":"","skip_if_decoding_changes":true,"lowercase_when_escaped":true}),
        ] {
            let stage: Stage = serde_json::from_value(value).unwrap();
            assert!(stage.compile().is_err());
        }
        assert!(
            serde_json::from_value::<Stage>(json!({"kind":"before_query","unknown":true})).is_err()
        );
    }
}

#[cfg(test)]
mod sequence_tests {
    use super::*;
    use serde_json::json;
    fn compile(words: &[&str]) -> Result<CompiledStage> {
        let stage: Stage =
            serde_json::from_value(json!({"kind":"remove_sequences","sequences":words})).unwrap();
        stage.compile()
    }
    #[test]
    fn streaming_deletion_agrees_with_independent_repeated_global_deletion() {
        let words = ["AB", "AC"];
        let stage = compile(&words).unwrap();
        for length in 0..=8 {
            for mut index in 0..3_usize.pow(length) {
                let mut input = String::new();
                for _ in 0..length {
                    input.push(b"ABC"[index % 3] as char);
                    index /= 3;
                }
                let mut expected = input.clone();
                loop {
                    let before = expected.clone();
                    for word in words {
                        expected = expected.replace(word, "");
                    }
                    if expected == before {
                        break;
                    }
                }
                assert_eq!(
                    apply(std::slice::from_ref(&stage), input).unwrap(),
                    expected
                );
            }
        }
    }
    #[test]
    fn nested_sequences_and_unicode_reach_full_fixed_point_within_the_input_bound() {
        let stage = compile(&["XY"]).unwrap();
        assert_eq!(
            apply(std::slice::from_ref(&stage), "prefixXXYYsuffix".into()).unwrap(),
            "prefixsuffix"
        );
        assert_eq!(
            apply(
                &[stage],
                format!("{}{}", "X".repeat(4096), "Y".repeat(4096))
            )
            .unwrap(),
            ""
        );
        assert_eq!(
            apply(&[compile(&["αβ"]).unwrap()], "ααββé".into()).unwrap(),
            "é"
        );
    }
    #[test]
    fn empty_duplicate_variable_width_and_overlapping_sequence_sets_fail_startup() {
        for words in [
            vec![],
            vec![""],
            vec!["X"],
            vec!["XY", "XY"],
            vec!["XY", "XYZ"],
            vec!["AB", "BC"],
            vec!["AA"],
            vec!["ABAB"],
            vec!["X\0"],
        ] {
            assert!(compile(&words).is_err());
        }
        let too_many = (0..9)
            .map(|i| format!("A{}", char::from(b'b' + i)))
            .collect::<Vec<_>>();
        let references = too_many.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(compile(&references).is_err());
        assert!(compile(&[&"X".repeat(65)]).is_err());
    }
}
