//! WordPress semantics, separate from the application-independent shared engine.
mod form_consumer;
mod input_constraint;
mod input_projection;
mod parameter_match;
use bytes::Bytes;
use form_consumer::FormConsumer;
use input_constraint::{CompiledInput, InputConstraint};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use waf_core::profile::{Layer, PolicyError, SourcedModule};
type Result<T> = std::result::Result<T, PolicyError>;
fn bad(reason: &str) -> PolicyError {
    PolicyError(reason.into())
}
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Base {
    schema_version: u32,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Rest,
    Path,
    Ajax,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodRule {
    pub id: String,
    pub scope: Scope,
    pub pattern: String,
    pub methods: Vec<String>,
    pub evidence: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginConsumer {
    path: String,
    request_order: String,
    evidence: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Site {
    schema_version: u32,
    #[serde(default = "root")]
    base_path: String,
    #[serde(default = "prefix")]
    rest_prefix: String,
    #[serde(default)]
    rest_entry_paths: Vec<String>,
    #[serde(default)]
    method_rules: Vec<MethodRule>,
    #[serde(default)]
    login_consumers: Vec<LoginConsumer>,
    #[serde(default)]
    form_consumers: Vec<FormConsumer>,
    #[serde(default)]
    input_constraints: Vec<InputConstraint>,
}
fn root() -> String {
    "/".into()
}
fn prefix() -> String {
    "wp-json".into()
}
impl Default for Site {
    fn default() -> Self {
        Self {
            schema_version: 1,
            base_path: root(),
            rest_prefix: prefix(),
            rest_entry_paths: Vec::new(),
            method_rules: Vec::new(),
            login_consumers: Vec::new(),
            form_consumers: Vec::new(),
            input_constraints: Vec::new(),
        }
    }
}
pub struct Wordpress {
    site: Site,
    rules: Vec<Regex>,
    input_patterns: Vec<CompiledInput>,
    pub profile_id: String,
    site_profile_id: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Context {
    pub family: &'static str,
    pub effective_method: String,
    pub method_source: &'static str,
    #[serde(skip)]
    pub rest_route: Option<String>,
    #[serde(skip)]
    pub path: String,
    #[serde(skip)]
    pub action: Option<String>,
    #[serde(skip)]
    pub confirmed_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer_profile: Option<String>,
    #[serde(skip)]
    input_denial: Option<String>,
}
#[derive(Debug)]
pub struct Denial {
    pub status: u16,
    pub reason: &'static str,
    pub policy_id: Option<String>,
    pub profile_id: String,
}
fn decode(input: &str, plus: bool) -> Result<String> {
    let mut output = Vec::new();
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
            let (a, b) = bytes
                .get(index + 1)
                .and_then(|b| digit(*b))
                .zip(bytes.get(index + 2).and_then(|b| digit(*b)))
                .ok_or_else(|| bad("wordpress_invalid_encoding"))?;
            output.push(a * 16 + b);
            index += 3;
        } else {
            output.push(if plus && bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| bad("wordpress_invalid_utf8"))
}
fn normalized_key(key: &str) -> String {
    // PHP truncates decoded parameter names at NUL before normalizing spaces/dots.
    // Dispatch aliases must share an identity, including duplicate/array checks.
    key.split('\0')
        .next()
        .unwrap_or("")
        .trim_start_matches(' ')
        .replace([' ', '.'], "_")
}
fn relevant(name: &str, names: &[&str]) -> bool {
    names.contains(&name)
}
fn insert(parameters: &mut BTreeMap<String, String>, raw_key: &str, value: String) -> Result<()> {
    let key = normalized_key(raw_key);
    let root = key.split('[').next().unwrap_or("");
    if key != root || value.contains('\0') || parameters.insert(key, value).is_some() {
        return Err(bad("wordpress_ambiguous_dispatch_parameter"));
    }
    Ok(())
}
fn parameters(input: &str, names: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut output = BTreeMap::new();
    if input.len() > 65536 {
        return Err(bad("wordpress_parameter_limit"));
    }
    for pair in input.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key, true)?;
        // Non-dispatch parameters can be binary and need no semantic interpretation here.
        if relevant(normalized_key(&key).split('[').next().unwrap_or(""), names) {
            insert(&mut output, &key, decode(value, true)?)?;
        }
    }
    Ok(output)
}
fn clean_path(path: &str) -> Result<String> {
    let decoded = decode(path, false)?;
    if !decoded.starts_with('/')
        || decoded.contains(['\\', '\0', '\r', '\n', '?', '#'])
        || decoded.split('/').any(|p| p == "." || p == "..")
    {
        return Err(bad("wordpress_ambiguous_route"));
    }
    let cleaned = format!(
        "/{}",
        decoded
            .split('/')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    );
    Ok(cleaned)
}
fn route(value: &str) -> Result<String> {
    if !value.starts_with('/')
        || value.contains(['\\', '\0', '\r', '\n', '?', '#'])
        || value.split('/').any(|part| part == "." || part == "..")
    {
        return Err(bad("wordpress_ambiguous_route"));
    }
    Ok(if value.trim_end_matches('/').is_empty() {
        "/".into()
    } else {
        value.trim_end_matches('/').into()
    })
}
pub struct Request<'a> {
    pub path: &'a str,
    pub query: &'a str,
    pub wire_method: &'a str,
    pub headers: &'a [(String, String)],
    pub content_type: &'a str,
    pub body: Bytes,
    pub max_parts: usize,
}
impl Wordpress {
    pub fn from_modules(modules: &BTreeMap<String, SourcedModule>) -> Result<Option<Self>> {
        for name in modules.keys() {
            if !["wordpress", "wordpress-site"].contains(&name.as_str()) {
                return Err(bad("unknown_application_module"));
            }
        }
        let Some(base) = modules.get("wordpress") else {
            if modules.contains_key("wordpress-site") {
                return Err(bad("wordpress_site_without_base"));
            }
            return Ok(None);
        };
        let config: Base = serde_json::from_value(base.settings.clone())
            .map_err(|_| bad("invalid_wordpress_module"))?;
        if config.schema_version != 1 || base.layer != Layer::Application {
            return Err(bad("invalid_wordpress_module_layer_or_version"));
        }
        let site = if let Some(module) = modules.get("wordpress-site") {
            if module.layer != Layer::Site {
                return Err(bad("wordpress_settings_require_site_layer"));
            }
            serde_json::from_value(module.settings.clone())
                .map_err(|_| bad("invalid_wordpress_site_module"))?
        } else {
            Site::default()
        };
        if site.schema_version != 1
            || site.base_path.len() > 256
            || !site.base_path.starts_with('/')
            || !site.base_path.ends_with('/')
            || clean_path(&site.base_path)?.trim_end_matches('/')
                != site.base_path.trim_end_matches('/')
            || site.rest_prefix.is_empty()
            || site.rest_prefix.len() > 64
            || !site
                .rest_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || site.method_rules.len() > 512
            || site.rest_entry_paths.len() > 32
            || site.login_consumers.len() > 32
            || site.form_consumers.len() > 32
            || site.input_constraints.len() > 32
        {
            return Err(bad("invalid_wordpress_site_bounds"));
        }
        for path in &site.rest_entry_paths {
            if path.len() > 512 || clean_path(path)? != *path {
                return Err(bad("invalid_wordpress_rest_entry"));
            }
        }
        let mut consumer_paths = BTreeSet::new();
        for consumer in &site.login_consumers {
            if consumer.path.len() > 512
                || clean_path(&consumer.path)? != consumer.path
                || consumer.request_order != "GP"
                || consumer.evidence.trim().is_empty()
                || !consumer_paths.insert(&consumer.path)
            {
                return Err(bad("invalid_wordpress_login_consumer"));
            }
        }
        let mut ids = BTreeSet::new();
        for consumer in &site.form_consumers {
            consumer.validate(&site.base_path, &mut ids)?;
        }
        let mut rules = Vec::new();
        for rule in &site.method_rules {
            if rule.id.is_empty()
                || rule.id.len() > 96
                || !ids.insert(rule.id.clone())
                || rule.evidence.trim().is_empty()
                || rule.methods.is_empty()
                || !rule.pattern.starts_with('^')
                || !rule.pattern.ends_with('$')
                || rule.pattern.len() > 4096
                || rule
                    .methods
                    .iter()
                    .any(|method| !METHODS.contains(&method.as_str()))
            {
                return Err(bad("invalid_wordpress_method_rule"));
            }
            rules.push(
                regex::RegexBuilder::new(&rule.pattern)
                    .size_limit(1024 * 1024)
                    .build()
                    .map_err(|_| bad("invalid_wordpress_route_regex"))?,
            );
        }
        let input_patterns = site
            .input_constraints
            .iter()
            .map(|rule| rule.compile(&site.base_path, &mut ids))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Self {
            site,
            input_patterns,
            rules,
            profile_id: base.profile_id.clone(),
            site_profile_id: modules
                .get("wordpress-site")
                .map(|module| module.profile_id.clone()),
        }))
    }
    pub async fn analyze(&self, request: Request<'_>) -> Result<Context> {
        let input_request = Request {
            path: request.path,
            query: request.query,
            wire_method: request.wire_method,
            headers: request.headers,
            content_type: request.content_type,
            body: request.body.clone(),
            max_parts: request.max_parts,
        };
        let Request {
            path,
            query,
            wire_method,
            headers,
            content_type,
            body,
            max_parts,
        } = request;
        let path = clean_path(path)?;
        let login_consumer = self
            .site
            .login_consumers
            .iter()
            .any(|consumer| consumer.path == path);
        let relative = if self.site.base_path == "/" {
            path.as_str()
        } else {
            path.strip_prefix(self.site.base_path.trim_end_matches('/'))
                .filter(|p| p.starts_with('/'))
                .unwrap_or("")
        };
        let is_admin = relative == "/wp-admin" || relative.starts_with("/wp-admin/");
        let is_ajax = relative == "/wp-admin/admin-ajax.php";
        let is_admin_post = relative == "/wp-admin/admin-post.php";
        let query_front = !relative.is_empty()
            && !is_admin
            && (!relative.ends_with(".php")
                || relative == "/index.php"
                || self
                    .site
                    .rest_entry_paths
                    .iter()
                    .any(|entry| entry == &path));
        let names: &[&str] = if login_consumer && !is_admin {
            &["action", "rest_route", "key", "checkemail"]
        } else if is_ajax || is_admin_post {
            &["action"]
        } else if query_front {
            &["rest_route"]
        } else {
            &[]
        };
        let query_params = parameters(query, names)?;
        let media = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let form_body = body.clone();
        let mut post = BTreeMap::new();
        let mut password_count = 0;
        let mut password_scalar = true;
        let mut password_canonical = false;
        let mut password_nonempty = false;
        // PHP populates $_POST only for wire POST forms; JSON and PUT bodies cannot select rest_route.
        if wire_method == "POST" && media == "application/x-www-form-urlencoded" {
            // Do not impose the small query bound on legitimate large form content.
            for pair in body.split(|byte| *byte == b'&') {
                let split = pair.iter().position(|byte| *byte == b'=');
                let (key, value) = split
                    .map(|i| (&pair[..i], &pair[i + 1..]))
                    .unwrap_or((pair, b""));
                let key = decode(
                    std::str::from_utf8(key).map_err(|_| bad("wordpress_invalid_form_key"))?,
                    true,
                )?;
                if login_consumer
                    && !is_admin
                    && normalized_key(&key).split('[').next() == Some("pwd")
                {
                    password_count += 1;
                    password_scalar &= !normalized_key(&key).contains('[');
                    // The shared form scanner binds single-decoded names. PHP
                    // aliases need separate evidence; they cannot borrow pwd's
                    // origin. Never decode or retain the password value here.
                    password_canonical = key == "pwd";
                    password_nonempty = !value.is_empty() && value != b"0" && value != b"%30";
                }
                if relevant(normalized_key(&key).split('[').next().unwrap_or(""), names) {
                    insert(
                        &mut post,
                        &key,
                        decode(
                            std::str::from_utf8(value)
                                .map_err(|_| bad("wordpress_invalid_dispatch_value"))?,
                            true,
                        )?,
                    )?;
                }
            }
        } else if wire_method == "POST" && media == "multipart/form-data" {
            let boundary = multer::parse_boundary(content_type)
                .map_err(|_| bad("wordpress_invalid_multipart"))?;
            let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(body) });
            let mut multipart = multer::Multipart::new(stream, boundary);
            let mut count = 0;
            while let Some(field) = multipart
                .next_field()
                .await
                .map_err(|_| bad("wordpress_invalid_multipart"))?
            {
                count += 1;
                if count > max_parts {
                    return Err(bad("wordpress_multipart_part_limit"));
                }
                if field.file_name().is_none() {
                    if let Some(name) = field.name() {
                        let name = name.to_string();
                        if relevant(normalized_key(&name).split('[').next().unwrap_or(""), names) {
                            let value = field
                                .bytes()
                                .await
                                .map_err(|_| bad("wordpress_invalid_multipart"))?;
                            if value.len() > 8192 {
                                return Err(bad("wordpress_dispatch_value_limit"));
                            }
                            insert(
                                &mut post,
                                &name,
                                String::from_utf8(value.to_vec())
                                    .map_err(|_| bad("wordpress_invalid_dispatch_value"))?,
                            )?;
                        }
                    }
                }
            }
        }
        let endpoint = format!("/{}/", self.site.rest_prefix);
        let pretty = relative
            .strip_prefix(&endpoint)
            .or_else(|| relative.strip_prefix(&format!("/index.php{endpoint}")));
        if let (Some(post_route), Some(query_route)) =
            (post.get("rest_route"), query_params.get("rest_route"))
        {
            if post_route != query_route {
                return Err(bad("wordpress_dispatch_variable_mismatch"));
            }
        }
        let explicit = if query_front {
            post.get("rest_route")
                .or_else(|| query_params.get("rest_route"))
        } else {
            None
        };
        let rest_route = if let Some(explicit) = explicit {
            if explicit.is_empty() || explicit == "0" {
                None
            } else {
                Some(route(explicit)?)
            }
        } else if let Some(pretty) = pretty {
            Some(route(&format!("/{pretty}"))?)
        } else if relative == endpoint.trim_end_matches('/')
            || relative == format!("/index.php/{}", self.site.rest_prefix)
        {
            Some("/".into())
        } else {
            None
        };
        let family = if is_ajax {
            "ajax"
        } else if is_admin_post {
            "admin_post"
        } else if is_admin {
            "administration"
        } else if rest_route.is_some() {
            "rest"
        } else if relative == "/wp-login.php" || login_consumer {
            "member_login"
        } else {
            "unqualified"
        };
        let mut effective = wire_method.to_string();
        let mut source = "wire";
        if rest_route.is_some() {
            let overrides = headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("x-http-method-override"))
                .collect::<Vec<_>>();
            if overrides.len() > 1 {
                return Err(bad("wordpress_duplicate_method_override"));
            }
            // Query parameter wins, matching WP_REST_Server::serve_request.
            let method_params = parameters(query, &["_method"])?;
            if let Some(method) = method_params.get("_method") {
                effective = method.to_ascii_uppercase();
                source = "query";
            } else if let Some((_, method)) = overrides.first() {
                effective = method.to_ascii_uppercase();
                source = "header";
            }
            if !METHODS.contains(&effective.as_str()) {
                return Err(bad("wordpress_invalid_effective_method"));
            }
        }
        let action = post
            .get("action")
            .or_else(|| query_params.get("action"))
            .cloned();
        let login_action = action.as_deref().is_none_or(|action| action == "login");
        let action_agrees = match (post.get("action"), query_params.get("action")) {
            (Some(post), Some(query)) => post == query,
            _ => true,
        };
        let mut confirmed_fields = Vec::new();
        if login_consumer
            && family == "member_login"
            && login_action
            && wire_method == "POST"
            && media == "application/x-www-form-urlencoded"
        {
            if password_count > 1 || !password_scalar {
                return Err(bad("wordpress_ambiguous_login_password"));
            }
            if password_count == 1
                && password_canonical
                && password_nonempty
                && action_agrees
                && !query_params.contains_key("key")
                && !query_params.contains_key("checkemail")
                && !post.contains_key("rest_route")
                && !query_params.contains_key("rest_route")
            {
                confirmed_fields.push("pwd".into());
            }
        }
        if family == "ajax" && wire_method == "POST" && !query_params.contains_key("action") {
            for consumer in &self.site.form_consumers {
                if consumer.path == path
                    && action.as_deref() == Some(consumer.action.as_str())
                    && consumer.confirms(&form_body, &media, content_type, max_parts)?
                    && !confirmed_fields.contains(&consumer.form_field)
                {
                    confirmed_fields.push(consumer.form_field.clone());
                }
            }
        }
        let consumer_profile = if confirmed_fields.is_empty() {
            None
        } else {
            self.site_profile_id.clone()
        };
        let mut input_denial = None;
        for (rule, pattern) in self.site.input_constraints.iter().zip(&self.input_patterns) {
            if rule.matches_path(&path)
                && rule.methods.iter().any(|method| method == wire_method)
                && (rule.actions.is_empty()
                    || action.as_ref().is_some_and(|a| rule.actions.contains(a)))
                && rule.rejects(pattern, &input_request).await?
            {
                input_denial = Some(rule.id.clone());
                break;
            }
        }
        Ok(Context {
            family,
            effective_method: effective,
            method_source: source,
            rest_route,
            path,
            action,
            confirmed_fields,
            consumer_profile,
            input_denial,
        })
    }
    pub fn check(&self, context: &Context, trusted: bool) -> Option<Denial> {
        if context.family == "administration" && !trusted {
            return Some(Denial {
                status: 403,
                reason: "wordpress_administration_requires_trust",
                policy_id: None,
                profile_id: self.profile_id.clone(),
            });
        }
        if let Some(id) = &context.input_denial {
            return Some(Denial {
                status: 403,
                reason: "wordpress_input_constraint",
                policy_id: Some(id.clone()),
                profile_id: self
                    .site_profile_id
                    .as_ref()
                    .unwrap_or(&self.profile_id)
                    .clone(),
            });
        }
        for (rule, pattern) in self.site.method_rules.iter().zip(&self.rules) {
            let value = match rule.scope {
                Scope::Rest => context.rest_route.as_deref(),
                Scope::Path => Some(context.path.as_str()),
                Scope::Ajax => {
                    if context.family == "ajax" {
                        context.action.as_deref()
                    } else {
                        None
                    }
                }
            };
            if value.is_some_and(|value| pattern.is_match(value)) {
                let method = &context.effective_method;
                // WordPress REST HEAD falls back to GET; REST OPTIONS is discovery, not a write.
                let implicit = matches!(rule.scope, Scope::Rest)
                    && (method == "OPTIONS"
                        || (method == "HEAD" && rule.methods.iter().any(|m| m == "GET")));
                if !implicit && !rule.methods.contains(method) {
                    return Some(Denial {
                        status: 405,
                        reason: "wordpress_method_policy",
                        policy_id: Some(rule.id.clone()),
                        profile_id: self
                            .site_profile_id
                            .as_ref()
                            .unwrap_or(&self.profile_id)
                            .clone(),
                    });
                }
            }
        }
        None
    }
}
