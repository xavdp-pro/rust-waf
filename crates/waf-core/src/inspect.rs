//! Bounded normalization and application-independent detection.
use crate::profile::{EffectivePolicy, PolicyError, Target};
use bytes::Bytes;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, PolicyError>;
fn error(code: &str) -> PolicyError {
    PolicyError(code.into())
}

/// Each view is inspected. Normalization never changes forwarded request bytes.
#[derive(Debug)]
pub struct Views {
    pub path: Vec<String>,
    pub query: Vec<String>,
    pub body: Vec<String>,
    pub headers: Vec<String>,
}

fn decode_once(input: &str, plus: bool, strict: bool) -> Result<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = |b: u8| (b as char).to_digit(16).map(|x| x as u8);
            if let Some((a, b)) = bytes
                .get(index + 1)
                .and_then(|a| hex(*a))
                .zip(bytes.get(index + 2).and_then(|b| hex(*b)))
            {
                out.push(a * 16 + b);
                index += 3;
                continue;
            } else if strict {
                return Err(error("invalid_percent_encoding"));
            }
        }
        out.push(if plus && bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    if strict {
        String::from_utf8(out).map_err(|_| error("invalid_utf8_encoding"))
    } else {
        Ok(String::from_utf8_lossy(&out).to_string())
    }
}
fn variants(input: &str, passes: usize, plus: bool, strict: bool) -> Result<Vec<String>> {
    let mut views = vec![input.to_string()];
    for pass in 0..passes {
        let decoded = decode_once(
            views.last().unwrap(),
            plus && pass == 0,
            strict && pass == 0,
        )?;
        if decoded == *views.last().unwrap() {
            return Ok(views);
        }
        views.push(decoded);
    }
    if decode_once(views.last().unwrap(), false, false)? != *views.last().unwrap() {
        return Err(error("encoding_depth_exceeded"));
    }
    Ok(views)
}
// Reject duplicate JSON keys at every level, rather than trusting last-key-wins.
struct StrictJson(serde_json::Value);
impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJson(n.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictJson>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictJson(values.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn json_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => output.push(s.clone()),
        serde_json::Value::Array(a) => {
            for v in a {
                json_strings(v, output)
            }
        }
        serde_json::Value::Object(o) => {
            for (key, v) in o {
                output.push(key.clone());
                json_strings(v, output)
            }
        }
        _ => {}
    }
}

pub async fn normalize(
    policy: &EffectivePolicy,
    path: &str,
    query: &str,
    content_type: &str,
    body: Bytes,
) -> Result<Views> {
    if path.len() + query.len() > policy.limits.uri_bytes {
        return Err(error("uri_limit"));
    }
    if body.len() > policy.limits.body_bytes {
        return Err(error("body_limit"));
    }
    let passes = policy.limits.decode_passes;
    let paths = variants(path, passes, false, true)?;
    if paths.iter().any(|p| {
        p.contains(['\0', '\\', '\r', '\n']) || p.split('/').any(|s| s == "." || s == "..")
    }) {
        return Err(error("ambiguous_path"));
    }
    let queries = variants(query, passes, true, true)?;
    let raw = String::from_utf8_lossy(&body).to_string();
    let mut bodies = vec![raw.clone()];
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media == "application/json" || media.ends_with("+json") {
        let parsed: StrictJson =
            serde_json::from_slice(&body).map_err(|_| error("invalid_or_ambiguous_json"))?;
        let mut strings = Vec::new();
        json_strings(&parsed.0, &mut strings);
        for value in strings {
            bodies.extend(variants(&value, passes, false, false)?);
        }
    } else if media == "application/x-www-form-urlencoded" {
        let text = std::str::from_utf8(&body).map_err(|_| error("invalid_form_utf8"))?;
        bodies.extend(variants(text, passes, true, true)?);
    } else if media == "multipart/form-data" {
        let boundary = multer::parse_boundary(content_type)
            .map_err(|_| error("invalid_multipart_boundary"))?;
        if boundary.len() > 70 {
            return Err(error("invalid_multipart_boundary"));
        }
        let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
        let mut multipart = multer::Multipart::new(stream, boundary);
        let mut count = 0;
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|_| error("invalid_multipart"))?
        {
            count += 1;
            if count > policy.limits.multipart_parts {
                return Err(error("multipart_part_limit"));
            }
            if let Some(name) = field.name() {
                bodies.extend(variants(name, passes, false, false)?);
            }
            if let Some(name) = field.file_name() {
                bodies.extend(variants(name, passes, false, false)?);
            }
            let value = field
                .bytes()
                .await
                .map_err(|_| error("invalid_multipart"))?;
            bodies.extend(variants(
                &String::from_utf8_lossy(&value),
                passes,
                false,
                false,
            )?);
        }
    } else {
        bodies.extend(variants(&raw, passes, false, false)?);
    }
    Ok(Views {
        path: paths,
        query: queries,
        body: bodies,
        headers: Vec::new(),
    })
}

#[derive(Debug, Serialize)]
pub struct Match {
    pub rule_id: String,
    pub profile_id: String,
    pub high_confidence: bool,
    pub exception_profile: Option<String>,
}
pub struct Inspector {
    pub policy: EffectivePolicy,
    rules: BTreeMap<String, Regex>,
    exceptions: Vec<Regex>,
}
impl Inspector {
    pub fn new(policy: EffectivePolicy) -> Result<Self> {
        let rules = policy
            .rules
            .iter()
            .map(|(id, entry)| {
                Regex::new(&entry.rule.pattern)
                    .map(|r| (id.clone(), r))
                    .map_err(|_| error("invalid_rule"))
            })
            .collect::<Result<_>>()?;
        let exceptions = policy
            .exceptions
            .iter()
            .map(|e| Regex::new(&e.exception.path_pattern).map_err(|_| error("invalid_exception")))
            .collect::<Result<_>>()?;
        Ok(Self {
            policy,
            rules,
            exceptions,
        })
    }
    pub fn inspect(&self, views: &Views, method: &str) -> Vec<Match> {
        self.policy
            .rules
            .iter()
            .filter_map(|(id, entry)| {
                let regex = &self.rules[id];
                let hit = entry.rule.targets.iter().any(|target| {
                    match target {
                        Target::Path => &views.path,
                        Target::Query => &views.query,
                        Target::Body => &views.body,
                        Target::Headers => &views.headers,
                    }
                    .iter()
                    .any(|value| regex.is_match(value))
                });
                if !hit {
                    return None;
                }
                let path = views.path.last().unwrap();
                let exception =
                    self.policy
                        .exceptions
                        .iter()
                        .zip(&self.exceptions)
                        .find(|(e, r)| {
                            e.exception.rule_id == *id
                                && e.exception.methods.iter().any(|m| m == method)
                                && r.is_match(path)
                        });
                Some(Match {
                    rule_id: id.clone(),
                    profile_id: entry.profile_id.clone(),
                    high_confidence: entry.rule.high_confidence,
                    exception_profile: exception.map(|(e, _)| e.profile_id.clone()),
                })
            })
            .collect()
    }
}

/// All header values are inspected; raw values and credentials are never logged.
pub fn normalize_headers(
    policy: &EffectivePolicy,
    headers: &[(String, String)],
) -> Result<Vec<String>> {
    let bytes: usize = headers
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if headers.len() > policy.limits.header_count || bytes > policy.limits.header_bytes {
        return Err(error("header_limit"));
    }
    let mut output = Vec::new();
    for (key, value) in headers {
        output.push(key.clone());
        output.extend(variants(value, policy.limits.decode_passes, false, false)?);
    }
    Ok(output)
}
