//! Site-qualified scalar inputs and explicit PHP GP/header/target fallback selection.
use super::input_projection::{self, CompiledStage, Stage};
use super::{Result, bad, clean_path, decode, normalized_key};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Source {
    RequestParameter {
        name: String,
        #[serde(default)]
        stages: Vec<Stage>,
    },
    Header {
        name: String,
        #[serde(default)]
        stages: Vec<Stage>,
    },
    RequestTarget {
        #[serde(default)]
        stages: Vec<Stage>,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Projection {
    Raw,
    BeforeQuery,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PathMatch {
    #[default]
    Exact,
    Prefix,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputConstraint {
    pub(crate) id: String,
    pub(crate) path: String,
    #[serde(default)]
    path_match: PathMatch,
    #[serde(default)]
    when_parameter_present: Option<String>,
    pub(crate) actions: Vec<String>,
    pub(crate) methods: Vec<String>,
    request_order: String,
    arg_separator: String,
    max_input_vars: usize,
    pub(crate) sources: Vec<Source>,
    projection: Projection,
    #[serde(default)]
    stages: Vec<Stage>,
    reject_pattern: String,
    evidence: String,
}
pub(crate) struct CompiledInput {
    pattern: Regex,
    source_stages: Vec<Vec<CompiledStage>>,
    stages: Vec<CompiledStage>,
}
impl Source {
    fn stages(&self) -> &[Stage] {
        match self {
            Self::RequestParameter { stages, .. }
            | Self::Header { stages, .. }
            | Self::RequestTarget { stages } => stages,
        }
    }
}
impl InputConstraint {
    pub(crate) fn matches_path(&self, path: &str) -> bool {
        match self.path_match {
            PathMatch::Exact => path == self.path,
            PathMatch::Prefix => {
                self.path == "/"
                    || path == self.path
                    || path
                        .strip_prefix(&self.path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
        }
    }
    pub(crate) fn compile(
        &self,
        base_path: &str,
        ids: &mut BTreeSet<String>,
    ) -> Result<CompiledInput> {
        let ident = |v: &str| {
            !v.is_empty()
                && v.len() <= 96
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        };
        let policy_id = !self.id.is_empty()
            && self.id.len() <= 96
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !policy_id
            || !ids.insert(self.id.clone())
            || self
                .when_parameter_present
                .as_ref()
                .is_some_and(|v| !ident(v))
            || (matches!(self.path_match, PathMatch::Prefix)
                && ((base_path != "/"
                    && self.path != base_path.trim_end_matches('/')
                    && !self.path.starts_with(base_path))
                    || !self.actions.is_empty()))
            || self.path.len() > 512
            || clean_path(&self.path)? != self.path
            || (!self.actions.is_empty()
                && ![
                    format!("{base_path}wp-admin/admin-ajax.php"),
                    format!("{base_path}wp-admin/admin-post.php"),
                ]
                .contains(&self.path))
            || self.actions.len() > 32
            || self.actions.iter().any(|v| !ident(v))
            || self.actions.iter().collect::<BTreeSet<_>>().len() != self.actions.len()
            || self.methods.is_empty()
            || self.methods.len() > 7
            || self
                .methods
                .iter()
                .any(|m| !super::METHODS.contains(&m.as_str()))
            || self.methods.iter().collect::<BTreeSet<_>>().len() != self.methods.len()
            || self.request_order != "GP"
            || self.arg_separator != "&"
            || !(1..=10000).contains(&self.max_input_vars)
            || self.sources.is_empty()
            || self.sources.len() > 4
            || self.reject_pattern.is_empty()
            || self.reject_pattern.len() > 4096
            || self.evidence.trim().is_empty()
            || self.evidence.len() > 4096
        {
            return Err(bad("invalid_wordpress_input_constraint"));
        }
        let mut sources = BTreeSet::new();
        for (index, source) in self.sources.iter().enumerate() {
            let key = match source {
                Source::RequestParameter { name, .. } if ident(name) => format!("parameter:{name}"),
                Source::Header { name, .. } if ident(name) => {
                    format!("header:{}", name.to_ascii_lowercase())
                }
                Source::RequestTarget { .. } if index + 1 == self.sources.len() => "target".into(),
                _ => return Err(bad("invalid_wordpress_input_source")),
            };
            if !sources.insert(key) {
                return Err(bad("invalid_wordpress_input_source"));
            }
        }
        let pattern = regex::RegexBuilder::new(&self.reject_pattern)
            .size_limit(1024 * 1024)
            .build()
            .map_err(|_| bad("invalid_wordpress_input_pattern"))?;
        if pattern.is_match("") {
            return Err(bad("empty_wordpress_input_pattern"));
        }
        if self.stages.len() + self.sources.iter().map(|s| s.stages().len()).sum::<usize>()
            > input_projection::MAX_STAGES
        {
            return Err(bad("wordpress_projection_stage_limit"));
        }
        Ok(CompiledInput {
            pattern,
            source_stages: self
                .sources
                .iter()
                .map(|s| s.stages().iter().map(Stage::compile).collect())
                .collect::<Result<_>>()?,
            stages: self
                .stages
                .iter()
                .map(Stage::compile)
                .collect::<Result<_>>()?,
        })
    }
    pub(crate) async fn rejects(
        &self,
        compiled: &CompiledInput,
        request: &super::Request<'_>,
    ) -> Result<bool> {
        if let Some(name) = &self.when_parameter_present {
            // Presence is a union of form POST and query bindings, including arrays,
            // duplicates and falsey values. It does not resolve a plugin action value.
            let query = query_parameter(request.query, name, self.max_input_vars, true)?;
            let post = if request.wire_method == "POST" {
                post_parameter(request, name, self.max_input_vars, true).await?
            } else {
                None
            };
            if query.is_none() && post.is_none() {
                return Ok(false);
            }
        }
        let mut selected = None;
        for (index, source) in self.sources.iter().enumerate() {
            let value = match source {
                Source::RequestParameter { name, .. } => {
                    let post = if request.wire_method == "POST" {
                        post_parameter(request, name, self.max_input_vars, false).await?
                    } else {
                        None
                    };
                    // Any present POST binding suppresses GET; falsey values advance to the next source.
                    if post.is_some() {
                        post
                    } else {
                        query_parameter(request.query, name, self.max_input_vars, false)?
                    }
                }
                Source::Header { name, .. } => {
                    let values: Vec<_> = request
                        .headers
                        .iter()
                        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                        .collect();
                    if values.len() > 1 {
                        return Err(bad("wordpress_ambiguous_input_header"));
                    }
                    values.first().map(|(_, value)| value.clone())
                }
                Source::RequestTarget { .. } => Some(if request.query.is_empty() {
                    request.path.into()
                } else {
                    format!("{}?{}", request.path, request.query)
                }),
            };
            if let Some(value) = value.filter(|v| !v.is_empty() && v != "0") {
                if value.len() > 8192 || value.contains('\0') {
                    return Err(bad("wordpress_input_value_limit"));
                }
                selected = Some(input_projection::apply(
                    &compiled.source_stages[index],
                    value,
                )?);
                break;
            }
        }
        let Some(value) = selected else {
            return Ok(false);
        };
        let value = input_projection::apply(&compiled.stages, value)?;
        let value = match self.projection {
            Projection::Raw => value.as_str(),
            Projection::BeforeQuery => value.split('?').next().unwrap(),
        };
        Ok(compiled.pattern.is_match(value))
    }
}
fn binding(
    output: &mut Option<String>,
    raw_key: &str,
    value: &str,
    name: &str,
    encoded: bool,
    presence_only: bool,
) -> Result<()> {
    let key = normalized_key(raw_key);
    if key.split('[').next() != Some(name) {
        return Ok(());
    }
    if presence_only {
        *output = Some(String::new());
        return Ok(());
    }
    if key != name || raw_key.contains('\0') || output.is_some() {
        return Err(bad("wordpress_ambiguous_input_parameter"));
    }
    // Form percent encoding needs at most three wire bytes for each selected byte.
    // Bound the raw representation before decoding/allocation, then enforce the
    // same decoded scalar limit used by headers, MIME values and projections.
    let wire_limit = if encoded { 3 * 8192 } else { 8192 };
    if value.len() > wire_limit {
        return Err(bad("wordpress_input_value_limit"));
    }
    let value = if encoded {
        decode(value, true)?
    } else {
        value.into()
    };
    if value.len() > 8192 {
        return Err(bad("wordpress_input_value_limit"));
    }
    if value.contains('\0') {
        return Err(bad("wordpress_ambiguous_input_parameter"));
    }
    *output = Some(value);
    Ok(())
}
fn query_parameter(
    input: &str,
    name: &str,
    max_vars: usize,
    presence_only: bool,
) -> Result<Option<String>> {
    let mut output = None;
    for (count, pair) in input.split('&').enumerate() {
        if count >= max_vars {
            return Err(bad("wordpress_input_variable_limit"));
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        binding(
            &mut output,
            &decode(key, true)?,
            value,
            name,
            true,
            presence_only,
        )?;
    }
    Ok(output)
}
async fn post_parameter(
    request: &super::Request<'_>,
    name: &str,
    max_vars: usize,
    presence_only: bool,
) -> Result<Option<String>> {
    let media = request
        .content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut output = None;
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
            if normalized_key(&key).split('[').next() == Some(name) {
                binding(
                    &mut output,
                    &key,
                    if presence_only {
                        ""
                    } else {
                        std::str::from_utf8(value)
                            .map_err(|_| bad("wordpress_invalid_input_value"))?
                    },
                    name,
                    true,
                    presence_only,
                )?;
            }
        }
    } else if media == "multipart/form-data" {
        let boundary = waf_core::multipart_origin::qualified_boundary(request.content_type)
            .ok_or_else(|| bad("wordpress_unqualified_input_multipart"))?;
        let parts = waf_core::multipart_origin::layout(&request.body, &boundary, request.max_parts)
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
        let mut count = 0;
        for part in parts.iter().filter(|p| !p.is_file) {
            count += 1;
            if count > max_vars {
                return Err(bad("wordpress_input_variable_limit"));
            }
            if normalized_key(part.name).split('[').next() == Some(name) {
                binding(
                    &mut output,
                    part.name,
                    if presence_only {
                        ""
                    } else {
                        std::str::from_utf8(&request.body[part.value.clone()])
                            .map_err(|_| bad("wordpress_invalid_input_value"))?
                    },
                    name,
                    false,
                    presence_only,
                )?;
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod binding_size_tests {
    use super::*;

    #[test]
    fn encoded_ascii_and_utf8_can_reach_the_same_decoded_limit_as_mime_values() {
        for (wire, expected) in [
            ("%41".repeat(8192), "A".repeat(8192)),
            ("%C3%A9".repeat(4096), "é".repeat(4096)),
        ] {
            let mut output = None;
            binding(&mut output, "selected", &wire, "selected", true, false).unwrap();
            assert_eq!(output.as_deref(), Some(expected.as_str()));
            let mut mime = None;
            binding(&mut mime, "selected", &expected, "selected", false, false).unwrap();
            assert_eq!(mime, output);
        }
    }

    #[test]
    fn raw_and_decoded_oversize_invalid_encoding_and_nul_still_fail_closed() {
        for wire in [
            "%41".repeat(8193),
            "A".repeat(8193),
            "%00".into(),
            "%ZZ".into(),
        ] {
            let mut output = None;
            assert!(binding(&mut output, "selected", &wire, "selected", true, false).is_err());
            assert!(output.is_none());
        }
        let mut output = None;
        assert!(
            binding(
                &mut output,
                "selected",
                &"A".repeat(8193),
                "selected",
                false,
                false
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    fn rule() -> InputConstraint {
        serde_json::from_value(serde_json::json!({
            "id":"example.target", "path":"/app/articles", "path_match":"prefix",
            "when_parameter_present":"command_name", "actions":[], "methods":["GET","POST"],
            "request_order":"GP", "arg_separator":"&", "max_input_vars":4,
            "sources":[{"kind":"request_target"}], "projection":"before_query",
            "reject_pattern":"FORBIDDEN", "evidence":"fictional-consumer"
        }))
        .unwrap()
    }
    #[test]
    fn explicit_prefix_requires_segment_boundary_installation_and_no_actions() {
        let mut r = rule();
        assert!(r.compile("/app/", &mut BTreeSet::new()).is_ok());
        assert!(r.matches_path("/app/articles/child/"));
        assert!(!r.matches_path("/app/articles-other/"));
        r.path = "/".into();
        assert!(r.compile("/", &mut BTreeSet::new()).is_ok());
        assert!(r.matches_path("/outside/child"));
        assert!(r.compile("/app/", &mut BTreeSet::new()).is_err());
        r.path = "/app".into();
        assert!(r.compile("/app/", &mut BTreeSet::new()).is_ok());
        assert!(r.matches_path("/app"));
        assert!(!r.matches_path("/application"));
        for path in ["/app/articles/", "/other/", "/app/../other/"] {
            r.path = path.into();
            assert!(r.compile("/app/", &mut BTreeSet::new()).is_err());
        }
        r = rule();
        r.actions.push("example".into());
        assert!(r.compile("/app/", &mut BTreeSet::new()).is_err());
        r = rule();
        r.when_parameter_present = Some("bad[field]".into());
        assert!(r.compile("/app/", &mut BTreeSet::new()).is_err());
        r = rule();
        r.path_match = PathMatch::Exact;
        assert!(!r.matches_path("/app/articles/child/"));
    }
    #[test]
    fn presence_includes_falsey_duplicate_array_and_php_alias_bindings() {
        for input in [
            "command_name=",
            "command_name=0",
            "command.name=x",
            "command+name[]=a",
            "+command.name[]=a",
            "command_name[x]=a",
            "command_name=a&command_name=b",
            "command_name%00suffix=x",
        ] {
            assert!(
                query_parameter(input, "command_name", 4, true)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            query_parameter("other=command_name", "command_name", 4, true)
                .unwrap()
                .is_none()
        );
        assert!(
            query_parameter(
                "other=a&other=b&other=c&other=d&command_name=x",
                "command_name",
                4,
                true
            )
            .is_err()
        );
        assert!(query_parameter("%ZZ=x", "command_name", 4, true).is_err());
    }
    #[tokio::test]
    async fn presence_is_post_query_union_not_scalar_fallback_or_json_dispatch() {
        let r = rule();
        let compiled = r.compile("/app/", &mut BTreeSet::new()).unwrap();
        for (method, query, content_type, body, expected) in [
            (
                "POST",
                "",
                "application/x-www-form-urlencoded",
                "command_name[]=x&command_name[]=y",
                true,
            ),
            (
                "POST",
                "command_name=x",
                "application/x-www-form-urlencoded",
                "command_name=0",
                true,
            ),
            (
                "POST",
                "",
                "application/json",
                "{\"command_name\":\"x\"}",
                false,
            ),
            (
                "PATCH",
                "",
                "application/x-www-form-urlencoded",
                "command_name=x",
                false,
            ),
            (
                "PUT",
                "",
                "application/x-www-form-urlencoded",
                "command_name=x",
                false,
            ),
            ("GET", "command_name=0", "", "", true),
        ] {
            let request = super::super::Request {
                path: "/app/articles/FORBIDDEN",
                query,
                wire_method: method,
                headers: &[],
                content_type,
                body: bytes::Bytes::from(body),
                max_parts: 8,
            };
            assert_eq!(r.rejects(&compiled, &request).await.unwrap(), expected);
        }
    }
}
