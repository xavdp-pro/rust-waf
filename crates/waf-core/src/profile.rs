use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const INVARIANTS: [&str; 5] = [
    "deny_dynamic_forwarding_on_engine_failure",
    "trusted_ingress_identity_only",
    "bounded_request_parsing",
    "no_public_backend_bypass",
    "application_authentication_remains_required",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for PolicyError {}
type Result<T> = std::result::Result<T, PolicyError>;
fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(PolicyError(message.into()))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Core,
    #[serde(alias = "wordpress")]
    Application,
    Site,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub body_bytes: usize,
    pub uri_bytes: usize,
    pub header_bytes: usize,
    pub header_count: usize,
    pub decode_passes: usize,
    pub multipart_parts: usize,
}
impl Limits {
    pub fn hard_maximum() -> Self {
        Self {
            body_bytes: 32 * 1024 * 1024,
            uri_bytes: 8192,
            header_bytes: 65536,
            header_count: 128,
            decode_passes: 3,
            multipart_parts: 128,
        }
    }
    fn values(&self) -> [usize; 6] {
        [
            self.body_bytes,
            self.uri_bytes,
            self.header_bytes,
            self.header_count,
            self.decode_passes,
            self.multipart_parts,
        ]
    }
    fn tighten(&self, next: &Self) -> Result<Self> {
        if next
            .values()
            .into_iter()
            .zip(self.values())
            .any(|(new, old)| new == 0 || new > old)
        {
            return invalid("limits must be nonzero and may only tighten inherited bounds");
        }
        Ok(next.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiPolicy {
    pub mode: String,
    pub read_only: bool,
    pub controls: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiPolicy {
    pub per_request_api_calls: bool,
    pub per_detection_api_calls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Path,
    Query,
    Body,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub targets: Vec<Target>,
    pub pattern: String,
    pub high_confidence: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub rule_id: String,
    pub path_pattern: String,
    pub methods: Vec<String>,
    pub reason: String,
    pub evidence: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub profile_id: String,
    pub layer: Layer,
    pub version: String,
    pub extends: Option<String>,
    #[serde(default)]
    pub invariants: Vec<String>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub ui: Option<UiPolicy>,
    #[serde(default)]
    pub cloudflare: Option<ApiPolicy>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub exceptions: Vec<Exception>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourcedRule {
    pub profile_id: String,
    pub layer: Layer,
    pub rule: Rule,
}
#[derive(Debug, Clone, Serialize)]
pub struct SourcedException {
    pub profile_id: String,
    pub exception: Exception,
}
#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicy {
    pub schema_version: u32,
    pub fingerprint: String,
    pub chain: Vec<(String, String)>,
    pub limits: Limits,
    pub invariants: BTreeSet<String>,
    pub rules: BTreeMap<String, SourcedRule>,
    pub exceptions: Vec<SourcedException>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn expression(pattern: &str) -> Result<()> {
    if pattern.is_empty() || pattern.len() > 4096 {
        return invalid("empty or oversized regex");
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(1024 * 1024)
        .build()
        .map_err(|_| PolicyError("invalid or oversized regex program".into()))?;
    Ok(())
}
impl Profile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return invalid("profile exceeds one MiB");
        }
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|e| PolicyError(format!("invalid profile JSON: {e}")))?;
        if profile.schema_version != 1
            || !identifier(&profile.profile_id)
            || !identifier(&profile.version)
        {
            return invalid("unsupported schema or invalid profile identity");
        }
        if let Some(ui) = &profile.ui {
            if ui.mode != "statistics-only" || !ui.read_only || ui.controls {
                return invalid("only read-only statistics are allowed");
            }
        }
        if let Some(api) = &profile.cloudflare {
            if api.per_request_api_calls || api.per_detection_api_calls {
                return invalid("per-request and per-detection upstream API calls are forbidden");
            }
        }
        if profile.rules.len() > 1024 || profile.exceptions.len() > 1024 {
            return invalid("too many rules or exceptions");
        }
        for rule in &profile.rules {
            if !identifier(&rule.id)
                || rule.id.starts_with("core.invariant.")
                || rule.targets.is_empty()
            {
                return invalid("invalid rule identity or empty target set");
            }
            expression(&rule.pattern)?;
        }
        for exception in &profile.exceptions {
            if profile.layer != Layer::Site
                || exception.reason.trim().is_empty()
                || exception.evidence.trim().is_empty()
                || exception.methods.is_empty()
                || !exception.path_pattern.starts_with('^')
                || !exception.path_pattern.ends_with('$')
            {
                return invalid(
                    "exceptions require a site, anchored path, methods, reason and evidence",
                );
            }
            expression(&exception.path_pattern)?;
            for method in &exception.methods {
                if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
                    .contains(&method.as_str())
                {
                    return invalid("unsupported exception method");
                }
            }
        }
        Ok(profile)
    }
}

pub fn compose(profiles: Vec<Profile>, site_id: &str) -> Result<EffectivePolicy> {
    if profiles.len() > 256 {
        return invalid("profile registry exceeds 256 entries");
    }
    let mut registry = BTreeMap::new();
    for profile in profiles {
        // Validate manually constructed profiles as strictly as parsed profiles.
        let validated =
            Profile::parse(&serde_json::to_vec(&profile).map_err(|e| PolicyError(e.to_string()))?)?;
        if registry
            .insert(validated.profile_id.clone(), validated)
            .is_some()
        {
            return invalid("duplicate profile identifier");
        }
    }
    let mut reverse = Vec::new();
    let mut visited = BTreeSet::new();
    let mut current = Some(site_id);
    while let Some(id) = current {
        if !visited.insert(id.to_string()) {
            return invalid("cyclic profile inheritance");
        }
        let profile = registry
            .get(id)
            .ok_or_else(|| PolicyError("missing profile parent or selected site".into()))?;
        reverse.push(profile);
        current = profile.extends.as_deref();
    }
    reverse.reverse();
    if reverse.iter().map(|p| p.layer).collect::<Vec<_>>()
        != [Layer::Core, Layer::Application, Layer::Site]
    {
        return invalid("selected policy must have exactly core -> application -> site layers");
    }
    let required: BTreeSet<String> = INVARIANTS.into_iter().map(str::to_string).collect();
    let mut limits = Limits::hard_maximum();
    let mut invariants = BTreeSet::new();
    let mut rules = BTreeMap::new();
    let mut exceptions = Vec::new();
    let mut chain = Vec::new();
    for profile in &reverse {
        if profile.layer == Layer::Core && (profile.ui.is_none() || profile.cloudflare.is_none()) {
            return invalid("core must explicitly declare statistics-only and offline API policy");
        }
        let declared: BTreeSet<String> = profile.invariants.iter().cloned().collect();
        if profile.layer == Layer::Core && declared != required {
            return invalid("core invariants must match the mandatory contract");
        }
        if profile.layer != Layer::Core && !declared.is_subset(&required) {
            return invalid("unknown child invariant");
        }
        invariants.extend(declared);
        if let Some(next) = &profile.limits {
            limits = limits.tighten(next)?;
        }
        for rule in &profile.rules {
            if rules
                .insert(
                    rule.id.clone(),
                    SourcedRule {
                        profile_id: profile.profile_id.clone(),
                        layer: profile.layer,
                        rule: rule.clone(),
                    },
                )
                .is_some()
            {
                return invalid("duplicate rule identifier; silent rule overrides are forbidden");
            }
        }
        for exception in &profile.exceptions {
            exceptions.push(SourcedException {
                profile_id: profile.profile_id.clone(),
                exception: exception.clone(),
            });
        }
        chain.push((profile.profile_id.clone(), profile.version.clone()));
    }
    let mut exception_keys = BTreeSet::new();
    for item in &exceptions {
        if !rules.contains_key(&item.exception.rule_id) {
            return invalid("exception references an unknown rule");
        }
        let key = serde_json::to_string(&item.exception).map_err(|e| PolicyError(e.to_string()))?;
        if !exception_keys.insert(key) {
            return invalid("duplicate exception declaration");
        }
    }
    // Struct field order and BTreeMap keys establish a canonical representation.
    let canonical = serde_json::to_vec(&reverse).map_err(|e| PolicyError(e.to_string()))?;
    let fingerprint = Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(EffectivePolicy {
        schema_version: 1,
        fingerprint,
        chain,
        limits,
        invariants,
        rules,
        exceptions,
    })
}

impl EffectivePolicy {
    pub fn exception_for(
        &self,
        rule_id: &str,
        path: &str,
        method: &str,
    ) -> Option<&SourcedException> {
        self.exceptions.iter().find(|e| {
            e.exception.rule_id == rule_id
                && e.exception.methods.iter().any(|m| m == method)
                && Regex::new(&e.exception.path_pattern).is_ok_and(|r| r.is_match(path))
        })
    }
}
