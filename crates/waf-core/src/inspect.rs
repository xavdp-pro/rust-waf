//! Bounded normalization and application-independent detection.
use crate::profile::{EffectivePolicy, PolicyError, Target};
use bytes::Bytes;
use regex::Regex;
use regex_automata::nfa::thompson::{self, NFA};
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

pub(crate) fn decode_once(input: &str, plus: bool, strict: bool) -> Result<String> {
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
pub(crate) fn needs_decode(input: &str, plus: bool) -> bool {
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
pub(crate) fn scan_variants(
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
    normalize_tagged(
        policy,
        (path, query),
        content_type,
        body,
        &BTreeSet::new(),
        &mut |text, _| emit(text),
    )
    .await
}

async fn normalize_tagged(
    policy: &EffectivePolicy,
    location: (&str, &str),
    content_type: &str,
    body: Bytes,
    selected: &BTreeSet<&str>,
    emit_tagged: &mut impl FnMut(&str, &[crate::form_scan::FieldSpan]) -> Result<()>,
) -> Result<Views> {
    let (path, query) = location;
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
        emit_tagged(&String::from_utf8_lossy(&body), &[])?;
        crate::json_scan::scan_strings(&body, |text| {
            scan_variants(text, passes, false, false, &mut |text| {
                emit_tagged(text, &[])
            })
        })?;
    } else if media == "application/x-www-form-urlencoded" {
        let text = std::str::from_utf8(&body).map_err(|_| error("invalid_form_utf8"))?;
        crate::form_scan::scan(text, passes, selected, emit_tagged)?;
    } else if media == "multipart/form-data" {
        let mut emit = |text: &str| emit_tagged(text, &[]);
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
                scan_variants(name, passes, false, false, &mut emit)?;
            }
            if let Some(name) = field.file_name() {
                scan_variants(name, passes, false, false, &mut emit)?;
            }
            let value = field
                .bytes()
                .await
                .map_err(|_| error("invalid_multipart"))?;
            scan_variants(
                &String::from_utf8_lossy(&value),
                passes,
                false,
                false,
                &mut emit,
            )?;
        }
    } else {
        scan_variants(
            &String::from_utf8_lossy(&body),
            passes,
            false,
            false,
            &mut |text| emit_tagged(text, &[]),
        )?;
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
    // Every touched field must be confirmed and separately scoped; an unscoped
    // occurrence in any view prevents all field exceptions for that rule.
    body_matches: BTreeMap<String, crate::field_coverage::Coverage>,
}
pub struct Inspector {
    pub policy: EffectivePolicy,
    rules: BTreeMap<String, Regex>,
    exceptions: Vec<Regex>,
    field_coverage: BTreeMap<String, NFA>,
}
impl Inspector {
    pub async fn scan(
        &self,
        path: &str,
        query: &str,
        content_type: &str,
        body: Bytes,
    ) -> Result<ScannedRequest> {
        let mut body_matches: BTreeMap<String, crate::field_coverage::Coverage> = BTreeMap::new();
        let mut coverage_caches = BTreeMap::new();
        let selected = self
            .policy
            .exceptions
            .iter()
            .filter_map(|entry| entry.exception.form_field.as_deref())
            .collect();
        let views = normalize_tagged(
            &self.policy,
            (path, query),
            content_type,
            body,
            &selected,
            &mut |text, spans| {
                for (id, entry) in &self.policy.rules {
                    if !body_matches.get(id).is_some_and(|hit| hit.unscoped)
                        && entry
                            .rule
                            .targets
                            .iter()
                            .any(|target| matches!(target, Target::Body))
                        && self.rules[id].is_match(text)
                    {
                        let coverage = if let Some(nfa) = self.field_coverage.get(id) {
                            let cache = coverage_caches
                                .entry(id.clone())
                                .or_insert_with(|| crate::field_coverage::Cache::new(nfa));
                            let coverage = cache.scan(nfa, text, spans)?;
                            if !coverage.unscoped && coverage.fields.is_empty() {
                                return Err(error("field_coverage_disagreement"));
                            }
                            coverage
                        } else {
                            crate::field_coverage::Coverage {
                                fields: BTreeSet::new(),
                                unscoped: true,
                            }
                        };
                        let combined = body_matches.entry(id.clone()).or_default();
                        combined.fields.extend(coverage.fields);
                        combined.unscoped |= coverage.unscoped;
                    }
                }
                Ok(())
            },
        )
        .await?;
        Ok(ScannedRequest {
            views,
            body_matches,
        })
    }

    pub fn inspect_scanned(&self, request: &ScannedRequest, method: &str) -> Vec<Match> {
        self.inspect_scanned_with_fields(request, method, &[])
    }

    /// Only the application adapter can confirm scalar field bindings after
    /// resolving dispatch, aliases, duplicates, arrays and the actual action.
    /// No field is confirmed by default or by a client-supplied header.
    pub fn inspect_scanned_with_fields(
        &self,
        request: &ScannedRequest,
        method: &str,
        confirmed_fields: &[&str],
    ) -> Vec<Match> {
        self.inspect_with_hits(
            &request.views,
            method,
            &request.body_matches,
            confirmed_fields,
        )
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
        let mut field_coverage = BTreeMap::new();
        for exception in &policy.exceptions {
            if exception.exception.form_field.is_some() {
                let id = &exception.exception.rule_id;
                if !field_coverage.contains_key(id) {
                    let matcher = NFA::compiler()
                        .configure(
                            thompson::Config::new()
                                .nfa_size_limit(Some(1024 * 1024))
                                .which_captures(thompson::WhichCaptures::Implicit),
                        )
                        .build(&policy.rules[id].rule.pattern)
                        .map_err(|_| error("invalid_field_coverage_rule"))?;
                    if matcher.has_empty() {
                        return Err(error("empty_match_field_rule"));
                    }
                    field_coverage.insert(id.clone(), matcher);
                }
            }
        }
        Ok(Self {
            policy,
            rules,
            exceptions,
            field_coverage,
        })
    }
    pub fn inspect(&self, views: &Views, method: &str) -> Vec<Match> {
        self.inspect_with_hits(views, method, &BTreeMap::new(), &[])
    }

    fn inspect_with_hits(
        &self,
        views: &Views,
        method: &str,
        body_matches: &BTreeMap<String, crate::field_coverage::Coverage>,
        confirmed_fields: &[&str],
    ) -> Vec<Match> {
        self.policy
            .rules
            .iter()
            .filter_map(|(id, entry)| {
                let regex = &self.rules[id];
                let other_hit = entry.rule.targets.iter().any(|target| {
                    match target {
                        Target::Path => &views.path,
                        Target::Query => &views.query,
                        Target::Body => &views.body,
                        Target::Headers => &views.headers,
                    }
                    .iter()
                    .any(|value| regex.is_match(value))
                });
                if !body_matches.contains_key(id) && !other_hit {
                    return None;
                }
                let eligible = self
                    .policy
                    .exceptions
                    .iter()
                    .zip(&self.exceptions)
                    .filter(|(e, r)| {
                        e.exception.rule_id == *id
                            && e.exception.methods.iter().any(|m| m == method)
                            && views.path.iter().all(|path| r.is_match(path))
                    })
                    .collect::<Vec<_>>();
                let route_exception = eligible
                    .iter()
                    .find(|(e, _)| e.exception.form_field.is_none());
                let field_exceptions = body_matches
                    .get(id)
                    .filter(|hit| !other_hit && !hit.unscoped && !hit.fields.is_empty())
                    .and_then(|hit| {
                        hit.fields
                            .iter()
                            .map(|name| {
                                confirmed_fields
                                    .contains(&name.as_str())
                                    .then(|| {
                                        eligible.iter().find(|(e, _)| {
                                            e.exception.form_field.as_ref() == Some(name)
                                        })
                                    })
                                    .flatten()
                            })
                            .collect::<Option<Vec<_>>>()
                    });
                let exception_profile =
                    route_exception
                        .map(|(e, _)| e.profile_id.clone())
                        .or_else(|| {
                            field_exceptions
                                .as_ref()
                                .and_then(|scopes| scopes.first())
                                .map(|(e, _)| e.profile_id.clone())
                        });
                Some(Match {
                    rule_id: id.clone(),
                    profile_id: entry.profile_id.clone(),
                    high_confidence: entry.rule.high_confidence,
                    exception_profile,
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
