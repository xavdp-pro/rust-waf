//! Bounded normalization and application-independent detection.
use crate::profile::{EffectivePolicy, PolicyError, Target};
use bytes::Bytes;
use regex::Regex;
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

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
        Ok(match String::from_utf8(out) {
            Ok(text) => text,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        })
    }
}
fn variants(input: &str, passes: usize, plus: bool, strict: bool) -> Result<Vec<String>> {
    variants_owned(input.to_owned(), passes, plus, strict)
}
fn needs_decode(input: &str, plus: bool) -> bool {
    input.bytes().any(|b| b == b'%' || (plus && b == b'+'))
}
fn variants_owned(input: String, passes: usize, plus: bool, strict: bool) -> Result<Vec<String>> {
    let mut views = vec![input];
    for pass in 0..passes {
        if !needs_decode(views.last().unwrap(), plus && pass == 0) {
            return Ok(views);
        }
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
    if needs_decode(views.last().unwrap(), false)
        && decode_once(views.last().unwrap(), false, false)? != *views.last().unwrap()
    {
        return Err(error("encoding_depth_exceeded"));
    }
    Ok(views)
}
fn scan_variants(
    input: &str,
    passes: usize,
    plus: bool,
    strict: bool,
    emit: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    emit(input)?;
    let mut current = Cow::Borrowed(input);
    for pass in 0..passes {
        if !needs_decode(&current, plus && pass == 0) {
            return Ok(());
        }
        let decoded = decode_once(&current, plus && pass == 0, strict && pass == 0)?;
        if decoded == current {
            return Ok(());
        }
        emit(&decoded)?;
        current = Cow::Owned(decoded);
    }
    if needs_decode(&current, false) && decode_once(&current, false, false)? != current {
        return Err(error("encoding_depth_exceeded"));
    }
    Ok(())
}

/// Collect views for diagnostics/tests. The proxy uses Inspector::scan instead.
pub async fn normalize(
    policy: &EffectivePolicy,
    path: &str,
    query: &str,
    content_type: &str,
    body: Bytes,
) -> Result<Views> {
    let mut bodies = Vec::new();
    let mut views = normalize_into(policy, path, query, content_type, body, &mut |text| {
        bodies.push(text.to_owned());
        Ok(())
    })
    .await?;
    views.body = bodies;
    Ok(views)
}

async fn normalize_into(
    policy: &EffectivePolicy,
    path: &str,
    query: &str,
    content_type: &str,
    body: Bytes,
    emit: &mut impl FnMut(&str) -> Result<()>,
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
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    // A Content-Type on a bodyless request does not create a JSON document.
    if !body.is_empty() && (media == "application/json" || media.ends_with("+json")) {
        emit(&String::from_utf8_lossy(&body))?;
        crate::json_scan::scan_strings(&body, |text| {
            scan_variants(text, passes, false, false, emit)
        })?;
    } else if media == "application/x-www-form-urlencoded" {
        let text = std::str::from_utf8(&body).map_err(|_| error("invalid_form_utf8"))?;
        scan_variants(text, passes, true, true, emit)?;
    } else if media == "multipart/form-data" {
        emit(&String::from_utf8_lossy(&body))?;
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
                scan_variants(name, passes, false, false, emit)?;
            }
            if let Some(name) = field.file_name() {
                scan_variants(name, passes, false, false, emit)?;
            }
            let value = field
                .bytes()
                .await
                .map_err(|_| error("invalid_multipart"))?;
            scan_variants(&String::from_utf8_lossy(&value), passes, false, false, emit)?;
        }
    } else {
        scan_variants(&String::from_utf8_lossy(&body), passes, false, false, emit)?;
    }
    Ok(Views {
        path: paths,
        query: queries,
        body: Vec::new(),
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

/// Completed syntax/normalization with body rule hits, never retained body values.
pub struct ScannedRequest {
    pub views: Views,
    body_matches: BTreeSet<String>,
}
pub struct Inspector {
    pub policy: EffectivePolicy,
    rules: BTreeMap<String, Regex>,
    exceptions: Vec<Regex>,
}
impl Inspector {
    pub async fn scan(
        &self,
        path: &str,
        query: &str,
        content_type: &str,
        body: Bytes,
    ) -> Result<ScannedRequest> {
        let mut body_matches = BTreeSet::new();
        let views = normalize_into(&self.policy, path, query, content_type, body, &mut |text| {
            for (id, entry) in &self.policy.rules {
                if !body_matches.contains(id)
                    && entry
                        .rule
                        .targets
                        .iter()
                        .any(|target| matches!(target, Target::Body))
                    && self.rules[id].is_match(text)
                {
                    body_matches.insert(id.clone());
                }
            }
            Ok(())
        })
        .await?;
        Ok(ScannedRequest {
            views,
            body_matches,
        })
    }

    pub fn inspect_scanned(&self, request: &ScannedRequest, method: &str) -> Vec<Match> {
        self.inspect_with_hits(&request.views, method, &request.body_matches)
    }

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
        self.inspect_with_hits(views, method, &BTreeSet::new())
    }

    fn inspect_with_hits(
        &self,
        views: &Views,
        method: &str,
        body_matches: &BTreeSet<String>,
    ) -> Vec<Match> {
        self.policy
            .rules
            .iter()
            .filter_map(|(id, entry)| {
                let regex = &self.rules[id];
                let hit = body_matches.contains(id)
                    || entry.rule.targets.iter().any(|target| {
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
                let exception =
                    self.policy
                        .exceptions
                        .iter()
                        .zip(&self.exceptions)
                        .find(|(e, r)| {
                            e.exception.rule_id == *id
                                && e.exception.methods.iter().any(|m| m == method)
                                && views.path.iter().all(|path| r.is_match(path))
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
