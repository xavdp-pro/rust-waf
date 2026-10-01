//! Explicit site-qualified AJAX form consumers; no plugin is enabled by default.
use super::{Result, bad, clean_path, decode};
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::BTreeSet;
use waf_core::form_path::FormPath;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Guard {
    field: String,
    equals: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FormConsumer {
    id: String,
    pub(crate) path: String,
    pub(crate) action: String,
    request_order: String,
    arg_separator: String,
    max_input_vars: usize,
    max_input_nesting_level: usize,
    pub(crate) form_field: String,
    guards: Vec<Guard>,
    #[serde(default = "urlencoded")]
    media_types: Vec<String>,
    evidence: String,
}
fn urlencoded() -> Vec<String> {
    vec!["application/x-www-form-urlencoded".into()]
}

impl FormConsumer {
    pub(crate) fn validate(&self, base_path: &str, ids: &mut BTreeSet<String>) -> Result<()> {
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 96
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        };
        if self.id.is_empty()
            || self.id.len() > 96
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !ids.insert(self.id.clone())
            || !identifier(&self.action)
            || self.path != format!("{base_path}wp-admin/admin-ajax.php")
            || clean_path(&self.path)? != self.path
            || self.request_order != "GP"
            || self.arg_separator != "&"
            || !(1..=10000).contains(&self.max_input_vars)
            || !(1..=64).contains(&self.max_input_nesting_level)
            || self.guards.is_empty()
            || self.guards.len() > 8
            || self.max_input_vars < self.guards.len() + 2
            || self.media_types.is_empty()
            || self.media_types.len() > 2
            || self.media_types.iter().collect::<BTreeSet<_>>().len() != self.media_types.len()
            || self.media_types.iter().any(|media| {
                !["application/x-www-form-urlencoded", "multipart/form-data"]
                    .contains(&media.as_str())
            })
            || self.evidence.trim().is_empty()
            || self.evidence.len() > 4096
        {
            return Err(bad("invalid_wordpress_form_consumer"));
        }
        let field = FormPath::parse(&self.form_field)
            .ok_or_else(|| bad("invalid_wordpress_form_consumer_field"))?;
        if field.root() == "action" {
            return Err(bad("invalid_wordpress_form_consumer_field"));
        }
        let mut paths = vec![field, FormPath::parse("action").unwrap()];
        for guard in &self.guards {
            let path = FormPath::parse(&guard.field)
                .ok_or_else(|| bad("invalid_wordpress_form_consumer_guard"))?;
            if guard.equals.is_empty()
                || guard.equals.len() > 256
                || !guard
                    .equals
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || paths
                    .iter()
                    .any(|other| path.is_prefix_of(other) || other.is_prefix_of(&path))
            {
                return Err(bad("invalid_wordpress_form_consumer_guard"));
            }
            paths.push(path);
        }
        if paths
            .iter()
            .any(|path| path.segments().len() - 1 > self.max_input_nesting_level)
        {
            return Err(bad("invalid_wordpress_form_consumer_nesting"));
        }
        Ok(())
    }

    pub(crate) fn confirms(
        &self,
        body: &[u8],
        media: &str,
        content_type: &str,
        max_parts: usize,
    ) -> Result<bool> {
        if !self.media_types.iter().any(|allowed| allowed == media) {
            return Ok(false);
        }
        if media == "multipart/form-data" {
            let Some(boundary) = waf_core::multipart_origin::qualified_boundary(content_type)
            else {
                return Ok(false);
            };
            let Some(parts) = waf_core::multipart_origin::layout(body, &boundary, max_parts) else {
                return Ok(false);
            };
            return self.binds(
                parts.iter().map(|part| {
                    (
                        part.name.as_bytes(),
                        Some(&body[part.value.clone()]),
                        part.is_file,
                    )
                }),
                false,
            );
        }
        self.binds(
            body.split(|byte| *byte == b'&').map(|pair| {
                let (key, value) = pair
                    .iter()
                    .position(|byte| *byte == b'=')
                    .map_or((pair, None), |i| (&pair[..i], Some(&pair[i + 1..])));
                (key, value, false)
            }),
            true,
        )
    }

    fn binds<'a>(
        &self,
        fields: impl Iterator<Item = (&'a [u8], Option<&'a [u8]>, bool)>,
        encoded: bool,
    ) -> Result<bool> {
        // Metadata is bounded by the declared field, action and <=8 guards.
        // Values for the content field are never decoded or retained here.
        let mut names = vec![self.form_field.as_str(), "action"];
        names.extend(self.guards.iter().map(|guard| guard.field.as_str()));
        let paths = names
            .iter()
            .map(|name| FormPath::parse(name).unwrap())
            .collect::<Vec<_>>();
        let mut present = vec![false; names.len()];
        for (count, (key, value, file)) in fields.enumerate() {
            if count >= self.max_input_vars {
                return Ok(false);
            }
            if key.len() > 192 {
                return Ok(false);
            }
            let raw_key =
                std::str::from_utf8(key).map_err(|_| bad("wordpress_invalid_form_key"))?;
            let key = if encoded {
                Cow::Owned(decode(raw_key, true)?)
            } else {
                Cow::Borrowed(raw_key)
            };
            // A strict canonical tree avoids PHP root normalization, NUL,
            // ignored suffixes and append-index ambiguities. Unsupported keys
            // withhold confirmation; they do not themselves deny forwarding.
            let Some(candidate) = FormPath::parse(&key) else {
                return Ok(false);
            };
            if candidate.segments().len() - 1 > self.max_input_nesting_level {
                return Ok(false);
            }
            // File parts populate $_FILES and cannot select a POST consumer.
            if file {
                continue;
            }
            for (index, selected) in paths.iter().enumerate() {
                if key == names[index] {
                    if present[index] || value.is_none() {
                        return Ok(false);
                    }
                    present[index] = true;
                    if index == 0 && !encoded && std::str::from_utf8(value.unwrap()).is_err() {
                        return Ok(false);
                    }
                    if index > 0 {
                        let expected = if index == 1 {
                            &self.action
                        } else {
                            &self.guards[index - 2].equals
                        };
                        let value = value.unwrap();
                        if value.len() > 768 {
                            return Ok(false);
                        }
                        let raw_value = std::str::from_utf8(value)
                            .map_err(|_| bad("wordpress_invalid_dispatch_value"))?;
                        let value = if encoded {
                            Cow::Owned(decode(raw_value, true)?)
                        } else {
                            Cow::Borrowed(raw_value)
                        };
                        if value.as_ref() != expected {
                            return Ok(false);
                        }
                    }
                } else if candidate.is_prefix_of(selected) || selected.is_prefix_of(&candidate) {
                    return Ok(false);
                }
            }
        }
        Ok(present.iter().all(|present| *present))
    }
}
