//! Opt-in bounded PHP 8.3 scalar/one-level array binding union, not plugin dispatch.
use super::input_projection::{self, CompiledStage, Stage};
use super::{Request, Result, bad, decode, normalized_key};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;

const VALUE_BYTES: usize = 8192;
const ENTRY_LIMIT: usize = 128;
const TOTAL_BYTES: usize = 65536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParameterMatch {
    name: String,
    binding: String,
    pattern: String,
    #[serde(default)]
    stages: Vec<Stage>,
}
pub(crate) struct CompiledMatch {
    pattern: Regex,
    stages: Vec<CompiledStage>,
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Integer(i64),
    Text(String),
}
#[derive(Default)]
enum Values {
    #[default]
    Absent,
    Scalar(String),
    Array {
        entries: BTreeMap<Key, String>,
        max_index: Option<i64>,
        bytes: usize,
    },
}
impl Values {
    fn bind(&mut self, raw_key: &str, raw_value: &str, name: &str, encoded: bool) -> Result<()> {
        let root = raw_key.split('[').next().unwrap_or("");
        if normalized_key(root) != name {
            return Ok(());
        }
        if raw_key.contains('\0') || raw_key.len() > 512 {
            return Err(bad("wordpress_unqualified_match_parameter"));
        }
        let key = if let Some((_, tail)) = raw_key.split_once('[') {
            let (inner, suffix) = tail
                .split_once(']')
                .ok_or_else(|| bad("wordpress_unqualified_match_parameter"))?;
            // PHP continues nesting only at an immediately following '['.
            // Other suffix bytes are ignored; '[' inside a closed key is literal.
            if suffix.starts_with('[') {
                return Err(bad("wordpress_unqualified_match_parameter"));
            }
            // PHP treats a single C-whitespace character as an append key,
            // while two whitespace characters remain a literal text key.
            Some(
                if inner.len() == 1
                    && matches!(
                        inner.as_bytes()[0],
                        b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c
                    )
                {
                    ""
                } else {
                    inner
                },
            )
        } else {
            None
        };
        if raw_value.len()
            > if encoded {
                3 * VALUE_BYTES
            } else {
                VALUE_BYTES
            }
        {
            return Err(bad("wordpress_input_value_limit"));
        }
        let value = if encoded {
            decode(raw_value, true)?
        } else {
            raw_value.to_owned()
        };
        if value.len() > VALUE_BYTES || value.contains('\0') {
            return Err(bad("wordpress_input_value_limit"));
        }
        let Some(key) = key else {
            *self = Self::Scalar(value);
            return Ok(());
        };
        if !matches!(self, Self::Array { .. }) {
            *self = Self::Array {
                entries: BTreeMap::new(),
                max_index: None,
                bytes: 0,
            };
        }
        let Self::Array {
            entries,
            max_index,
            bytes,
        } = self
        else {
            unreachable!()
        };
        let key = if key.is_empty() {
            Key::Integer(match max_index {
                Some(index) => index
                    .checked_add(1)
                    .ok_or_else(|| bad("wordpress_input_append_overflow"))?,
                None => 0,
            })
        } else if let Ok(index) = key.parse::<i64>() {
            if index.to_string() == key {
                Key::Integer(index)
            } else {
                Key::Text(key.to_owned())
            }
        } else {
            Key::Text(key.to_owned())
        };
        let key_bytes = match &key {
            Key::Integer(_) => 8,
            Key::Text(key) => key.len(),
        };
        let previous = entries.get(&key);
        if previous.is_none() && entries.len() == ENTRY_LIMIT {
            return Err(bad("wordpress_match_entry_limit"));
        }
        let next_bytes = *bytes - previous.map_or(0, String::len)
            + value.len()
            + if previous.is_none() { key_bytes } else { 0 };
        if next_bytes > TOTAL_BYTES {
            return Err(bad("wordpress_match_binding_limit"));
        }
        if let Key::Integer(index) = &key {
            *max_index = Some(max_index.map_or(*index, |old| old.max(*index)));
        }
        *bytes = next_bytes;
        entries.insert(key, value);
        Ok(())
    }
    fn into_values(self) -> Vec<String> {
        match self {
            Self::Absent => Vec::new(),
            Self::Scalar(value) => vec![value],
            Self::Array { entries, .. } => entries.into_values().collect(),
        }
    }
}
impl ParameterMatch {
    pub(crate) fn compile(&self) -> Result<CompiledMatch> {
        if self.name.is_empty()
            || self.name.len() > 96
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || self.binding != "php83_form_query_union"
            || self.pattern.is_empty()
            || self.pattern.len() > 2048
            || self.stages.len() > input_projection::MAX_STAGES
        {
            return Err(bad("invalid_wordpress_parameter_match"));
        }
        let pattern = regex::RegexBuilder::new(&self.pattern)
            .size_limit(64 * 1024)
            .dfa_size_limit(64 * 1024)
            .build()
            .map_err(|_| bad("invalid_wordpress_parameter_match"))?;
        let stages = self
            .stages
            .iter()
            .map(Stage::compile)
            .collect::<Result<_>>()?;
        Ok(CompiledMatch { pattern, stages })
    }
    pub(crate) async fn matches(
        &self,
        compiled: &CompiledMatch,
        request: &Request<'_>,
        max_vars: usize,
    ) -> Result<bool> {
        let mut query = Values::default();
        for (count, pair) in request.query.split('&').enumerate() {
            if count >= max_vars {
                return Err(bad("wordpress_input_variable_limit"));
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            query.bind(&decode(key, true)?, value, &self.name, true)?;
        }
        let mut post = Values::default();
        if request.wire_method == "POST" {
            let media = request
                .content_type
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if media == "application/x-www-form-urlencoded" {
                for (count, pair) in request.body.split(|b| *b == b'&').enumerate() {
                    if count >= max_vars {
                        return Err(bad("wordpress_input_variable_limit"));
                    }
                    let (key, value) = pair
                        .iter()
                        .position(|b| *b == b'=')
                        .map_or((pair, &b""[..]), |i| (&pair[..i], &pair[i + 1..]));
                    let key = decode(
                        std::str::from_utf8(key).map_err(|_| bad("wordpress_invalid_input_key"))?,
                        true,
                    )?;
                    if normalized_key(key.split('[').next().unwrap_or("")) == self.name {
                        post.bind(
                            &key,
                            std::str::from_utf8(value)
                                .map_err(|_| bad("wordpress_invalid_input_value"))?,
                            &self.name,
                            true,
                        )?;
                    }
                }
            } else if media == "multipart/form-data" {
                let boundary = waf_core::multipart_origin::qualified_boundary(request.content_type)
                    .ok_or_else(|| bad("wordpress_unqualified_input_multipart"))?;
                let parts =
                    waf_core::multipart_origin::layout(&request.body, &boundary, request.max_parts)
                        .ok_or_else(|| bad("wordpress_unqualified_input_multipart"))?;
                if !waf_core::multipart_origin::agrees(
                    request.body.clone(),
                    &boundary,
                    &parts,
                    request.max_parts,
                )
                .await?
                {
                    return Err(bad("wordpress_input_multipart_disagreement"));
                }
                for (count, part) in parts.iter().filter(|p| !p.is_file).enumerate() {
                    if count >= max_vars {
                        return Err(bad("wordpress_input_variable_limit"));
                    }
                    if normalized_key(part.name.split('[').next().unwrap_or("")) == self.name {
                        post.bind(
                            part.name,
                            std::str::from_utf8(&request.body[part.value.clone()])
                                .map_err(|_| bad("wordpress_invalid_input_value"))?,
                            &self.name,
                            false,
                        )?;
                    }
                }
            }
        }
        let mut matched = false;
        // Bind/validate both sources fully, and apply all value projections even after a hit.
        for value in query.into_values().into_iter().chain(post.into_values()) {
            let value = input_projection::apply(&compiled.stages, value)?;
            matched |= compiled.pattern.is_match(&value);
        }
        Ok(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn guard() -> ParameterMatch {
        serde_json::from_value(json!({
            "name":"command_name", "binding":"php83_form_query_union",
            "pattern":"(?i)^apply_changes$", "stages":[{"kind":"trim","characters":" "}]
        }))
        .unwrap()
    }
    fn values(pairs: &[(&str, &str)]) -> Vec<String> {
        let mut result = Values::default();
        for (key, value) in pairs {
            result.bind(key, value, "command_name", false).unwrap();
        }
        result.into_values()
    }
    #[test]
    fn ordered_binding_replaces_scalars_arrays_and_duplicate_keys() {
        assert_eq!(
            values(&[("command_name", "apply_changes"), ("command_name", "noop")]),
            ["noop"]
        );
        assert_eq!(
            values(&[
                ("command_name[k]", "apply_changes"),
                ("command_name[k]", "noop")
            ]),
            ["noop"]
        );
        assert_eq!(
            values(&[
                ("command_name", "apply_changes"),
                ("command_name[]", "noop")
            ]),
            ["noop"]
        );
        assert_eq!(
            values(&[
                ("command_name[]", "apply_changes"),
                ("command_name", "noop")
            ]),
            ["noop"]
        );
        assert_eq!(
            values(&[
                ("command_name[k]", "apply_changes"),
                ("command_name[]", "noop")
            ]),
            ["noop", "apply_changes"]
        );
        assert_eq!(
            values(&[
                (" command.name[01]", "apply_changes"),
                ("command_name[1]", "noop")
            ]),
            ["noop", "apply_changes"]
        );
        assert_eq!(
            values(&[
                ("command_name[a b]", "apply_changes"),
                ("command_name[a.b]", "noop")
            ])
            .len(),
            2
        );
    }
    #[test]
    fn closed_keys_ignore_suffixes_and_single_c_whitespace_appends() {
        for key in [
            "command_name[k]tail",
            "command_name[k]tail[x]",
            "command_name[k]]",
            "command_name[a[b]",
        ] {
            let mut values = Values::default();
            values
                .bind(key, "apply_changes", "command_name", false)
                .unwrap();
            assert_eq!(values.into_values(), vec!["apply_changes"]);
        }
        let mut values = Values::default();
        values
            .bind(
                "command_name[k]tail",
                "apply_changes",
                "command_name",
                false,
            )
            .unwrap();
        values
            .bind("command_name[k]", "noop", "command_name", false)
            .unwrap();
        assert_eq!(values.into_values(), vec!["noop"]);
        for whitespace in [' ', '\t', '\n', '\r', '\u{b}', '\u{c}'] {
            let mut values = Values::default();
            values
                .bind(
                    &format!("command_name[{whitespace}]tail"),
                    "apply_changes",
                    "command_name",
                    false,
                )
                .unwrap();
            values
                .bind("command_name[0]", "noop", "command_name", false)
                .unwrap();
            assert_eq!(values.into_values(), vec!["noop"]);
        }
        for key in ["command_name[  ]", "command_name[\t ]", "command_name[é]"] {
            let mut values = Values::default();
            values
                .bind(key, "apply_changes", "command_name", false)
                .unwrap();
            values
                .bind("command_name[0]", "noop", "command_name", false)
                .unwrap();
            assert_eq!(values.into_values(), vec!["noop", "apply_changes"]);
        }
        assert!(
            Values::default()
                .bind("command_name[k][nested]", "x", "command_name", false)
                .is_err()
        );
        assert!(
            Values::default()
                .bind(
                    &format!("command_name[k]{}", "x".repeat(512)),
                    "x",
                    "command_name",
                    false
                )
                .is_err()
        );
        assert!(
            Values::default()
                .bind("command_name[k]tail\0ignored", "x", "command_name", false)
                .is_err()
        );
    }
    #[test]
    fn php83_integer_keys_and_negative_append_are_explicit() {
        let mut result = Values::default();
        result
            .bind("command_name[-5]", "first", "command_name", false)
            .unwrap();
        result
            .bind("command_name[]", "second", "command_name", false)
            .unwrap();
        let Values::Array { entries, .. } = result else {
            panic!("expected array")
        };
        assert_eq!(
            entries.get(&Key::Integer(-4)).map(String::as_str),
            Some("second")
        );
        for key in ["01", "+1", "-0", "9223372036854775808"] {
            let mut result = Values::default();
            result
                .bind(&format!("command_name[{key}]"), "x", "command_name", false)
                .unwrap();
            let Values::Array { entries, .. } = result else {
                panic!("expected array")
            };
            assert!(entries.contains_key(&Key::Text(key.into())));
        }
        let mut result = Values::default();
        result
            .bind(
                "command_name[9223372036854775807]",
                "x",
                "command_name",
                false,
            )
            .unwrap();
        assert!(
            result
                .bind("command_name[]", "x", "command_name", false)
                .is_err()
        );
    }
    #[test]
    fn selected_binding_syntax_and_storage_limits_fail_closed() {
        for key in [
            "command_name[a][b]",
            "command_name[",
            "command_name\0suffix",
        ] {
            assert!(
                Values::default()
                    .bind(key, "x", "command_name", false)
                    .is_err()
            );
        }
        assert!(
            Values::default()
                .bind("other[a][b]", "x", "command_name", false)
                .is_ok()
        );
        assert!(
            Values::default()
                .bind(
                    "command_name",
                    &"x".repeat(VALUE_BYTES),
                    "command_name",
                    false
                )
                .is_ok()
        );
        assert!(
            Values::default()
                .bind(
                    "command_name",
                    &"x".repeat(VALUE_BYTES + 1),
                    "command_name",
                    false
                )
                .is_err()
        );
        assert!(
            Values::default()
                .bind(
                    "command_name",
                    &"%61".repeat(VALUE_BYTES),
                    "command_name",
                    true
                )
                .is_ok()
        );
        for value in ["%00", "%FF", "%ZZ"] {
            assert!(
                Values::default()
                    .bind("command_name", value, "command_name", true)
                    .is_err()
            );
        }
        let mut result = Values::default();
        for _ in 0..ENTRY_LIMIT {
            result
                .bind("command_name[]", "x", "command_name", false)
                .unwrap();
        }
        result
            .bind("command_name[0]", "replacement", "command_name", false)
            .unwrap();
        assert!(
            result
                .bind("command_name[]", "x", "command_name", false)
                .is_err()
        );
        let mut result = Values::default();
        for _ in 0..7 {
            result
                .bind(
                    "command_name[]",
                    &"x".repeat(VALUE_BYTES),
                    "command_name",
                    false,
                )
                .unwrap();
        }
        assert!(
            result
                .bind(
                    "command_name[]",
                    &"x".repeat(VALUE_BYTES),
                    "command_name",
                    false
                )
                .is_err()
        );
        result
            .bind("command_name", "reset", "command_name", false)
            .unwrap();
        result
            .bind("command_name[]", "fresh", "command_name", false)
            .unwrap();
        assert_eq!(result.into_values(), ["fresh"]);
    }
    #[test]
    fn invalid_contracts_and_stages_fail_before_requests() {
        for patch in [
            json!({"binding":"GP"}),
            json!({"name":"nested[k]"}),
            json!({"pattern":"["}),
            json!({"pattern":""}),
            json!({"stages":[{"kind":"replace","pattern":"[","replacement":""}]}),
        ] {
            let mut contract = serde_json::to_value(
                json!({"name":"command_name","binding":"php83_form_query_union","pattern":"^$"}),
            )
            .unwrap();
            for (key, value) in patch.as_object().unwrap() {
                contract[key] = value.clone();
            }
            let guard: ParameterMatch = serde_json::from_value(contract).unwrap();
            assert!(guard.compile().is_err());
        }
        let empty: ParameterMatch = serde_json::from_value(
            json!({"name":"command_name","binding":"php83_form_query_union","pattern":"^$"}),
        )
        .unwrap();
        assert!(empty.compile().is_ok());
    }
    async fn matches(
        method: &str,
        query: &str,
        media: &str,
        body: &str,
        limit: usize,
    ) -> Result<bool> {
        let guard = guard();
        let compiled = guard.compile()?;
        guard
            .matches(
                &compiled,
                &Request {
                    path: "/articles",
                    query,
                    wire_method: method,
                    headers: &[],
                    content_type: media,
                    body: bytes::Bytes::copy_from_slice(body.as_bytes()),
                    max_parts: 128,
                },
                limit,
            )
            .await
    }
    #[tokio::test]
    async fn source_union_honors_last_write_and_ignores_non_form_bodies() {
        for (query, body, expected) in [
            ("command_name=apply_changes", "command_name=", true),
            ("command_name=noop", "command_name=+APPLY_CHANGES+", true),
            ("", "command_name=apply_changes&command_name=noop", false),
            ("", "command_name=noop&command_name=apply_changes", true),
            ("", "command_name=apply_changes&command_name[]=noop", false),
            ("", "command_name[]=apply_changes&command_name=noop", false),
            (
                "",
                "command_name[01]=apply_changes&command_name[1]=noop",
                true,
            ),
            (
                "",
                "command_name[k]=apply_changes&command_name[k]=noop",
                false,
            ),
            ("command_name[]=apply_changes", "command_name[]=noop", true),
            ("", "other=apply_changes", false),
        ] {
            assert_eq!(
                matches("POST", query, "application/x-www-form-urlencoded", body, 20)
                    .await
                    .unwrap(),
                expected,
                "{query} / {body}"
            );
        }
        assert!(
            !matches(
                "GET",
                "",
                "application/x-www-form-urlencoded",
                "command_name=apply_changes",
                20
            )
            .await
            .unwrap()
        );
        assert!(
            !matches(
                "POST",
                "",
                "application/json",
                r#"{"command_name":"apply_changes"}"#,
                20
            )
            .await
            .unwrap()
        );
        assert!(
            matches(
                "POST",
                "command_name=apply_changes",
                "application/json",
                "{}",
                20
            )
            .await
            .unwrap()
        );
    }
    #[tokio::test]
    async fn query_hit_does_not_hide_post_parser_or_binding_errors() {
        for body in ["command_name[a][b]=noop", "command_name=%00", "x=1&x=2&x=3"] {
            assert!(
                matches(
                    "POST",
                    "command_name=apply_changes",
                    "application/x-www-form-urlencoded",
                    body,
                    2
                )
                .await
                .is_err()
            );
        }
        assert!(
            matches(
                "POST",
                "command_name=apply_changes",
                "multipart/form-data; boundary=test",
                "broken",
                20
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn every_retained_projection_is_validated_after_a_match() {
        let guard: ParameterMatch = serde_json::from_value(json!({
            "name":"command_name","binding":"php83_form_query_union","pattern":"^apply_changes$",
            "stages":[{"kind":"replace","pattern":"x","replacement":"xx"}]
        }))
        .unwrap();
        let compiled = guard.compile().unwrap();
        let body = format!(
            "command_name[]=apply_changes&command_name[]={}",
            "x".repeat(5000)
        );
        assert!(
            guard
                .matches(
                    &compiled,
                    &Request {
                        path: "/articles",
                        query: "",
                        wire_method: "POST",
                        headers: &[],
                        content_type: "application/x-www-form-urlencoded",
                        body: bytes::Bytes::from(body),
                        max_parts: 128
                    },
                    20
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn multipart_binding_preserves_duplicates_and_excludes_files() {
        let multipart = |parts: &[(&str, &str, bool)]| {
            let mut body = String::new();
            for (name, value, file) in parts {
                body.push_str(&format!("--test\r\nContent-Disposition: form-data; name=\"{name}\"{}\r\n\r\n{value}\r\n",if *file { "; filename=\"example.txt\"" } else { "" }));
            }
            body.push_str("--test--\r\n");
            body
        };
        for (parts, expected) in [
            (
                vec![
                    ("command_name", "apply_changes", false),
                    ("command_name", "noop", false),
                ],
                false,
            ),
            (
                vec![
                    ("command_name[]", "apply_changes", false),
                    ("command_name[]", "noop", false),
                ],
                true,
            ),
            (vec![("command_name", "apply_changes", true)], false),
            (vec![("command.name", " APPLY_CHANGES ", false)], true),
        ] {
            assert_eq!(
                matches(
                    "POST",
                    "",
                    "multipart/form-data; boundary=test",
                    &multipart(&parts),
                    20
                )
                .await
                .unwrap(),
                expected
            );
        }
    }
}
