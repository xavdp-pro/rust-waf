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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputConstraint {
    pub(crate) id: String,
    pub(crate) path: String,
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
        let mut selected = None;
        for (index, source) in self.sources.iter().enumerate() {
            let value = match source {
                Source::RequestParameter { name, .. } => {
                    let post = if request.wire_method == "POST" {
                        scalar_post(request, name, self.max_input_vars).await?
                    } else {
                        None
                    };
                    // Any present POST binding suppresses GET; falsey values advance to the next source.
                    if post.is_some() {
                        post
                    } else {
                        scalar_query(request.query, name, self.max_input_vars)?
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
) -> Result<()> {
    let key = normalized_key(raw_key);
    if key.split('[').next() != Some(name) {
        return Ok(());
    }
    if key != name || raw_key.contains('\0') || output.is_some() {
        return Err(bad("wordpress_ambiguous_input_parameter"));
    }
    if value.len() > 8192 {
        return Err(bad("wordpress_input_value_limit"));
    }
    let value = if encoded {
        decode(value, true)?
    } else {
        value.into()
    };
    if value.contains('\0') {
        return Err(bad("wordpress_ambiguous_input_parameter"));
    }
    *output = Some(value);
    Ok(())
}
fn scalar_query(input: &str, name: &str, max_vars: usize) -> Result<Option<String>> {
    let mut output = None;
    for (count, pair) in input.split('&').enumerate() {
        if count >= max_vars {
            return Err(bad("wordpress_input_variable_limit"));
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        binding(&mut output, &decode(key, true)?, value, name, true)?;
    }
    Ok(output)
}
async fn scalar_post(
    request: &super::Request<'_>,
    name: &str,
    max_vars: usize,
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
                    std::str::from_utf8(value).map_err(|_| bad("wordpress_invalid_input_value"))?,
                    name,
                    true,
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
                    std::str::from_utf8(&request.body[part.value.clone()])
                        .map_err(|_| bad("wordpress_invalid_input_value"))?,
                    name,
                    false,
                )?;
            }
        }
    }
    Ok(output)
}
