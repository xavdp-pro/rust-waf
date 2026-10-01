use waf_core::profile::{Exception, Layer, Limits, Profile, Rule, Target, compose};
fn profiles() -> Vec<Profile> {
    [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(|bytes| Profile::parse(bytes).unwrap())
    .collect()
}
#[test]
fn composition_is_independent_of_registry_order_and_json_key_order() {
    let mut input = profiles();
    let first = compose(input.clone(), "example-site").unwrap();
    input.reverse();
    let second = compose(input, "example-site").unwrap();
    assert_eq!(first.fingerprint, second.fingerprint);
    let reordered = profiles()
        .into_iter()
        .map(|profile| {
            let value = serde_json::to_value(profile).unwrap();
            let fields = value
                .as_object()
                .unwrap()
                .iter()
                .rev()
                .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
                .collect::<Vec<_>>()
                .join(",");
            Profile::parse(format!("{{{fields}}}").as_bytes()).unwrap()
        })
        .collect();
    assert_eq!(
        first.fingerprint,
        compose(reordered, "example-site").unwrap().fingerprint
    );
    assert_eq!(first.chain.len(), 3);
    assert_eq!(first.invariants.len(), 5);
}
#[test]
fn profile_changes_change_the_fingerprint() {
    let first = compose(profiles(), "example-site").unwrap();
    let mut input = profiles();
    input[2].version = "0.2.0".into();
    assert_ne!(
        first.fingerprint,
        compose(input, "example-site").unwrap().fingerprint
    );
}
#[test]
fn unknown_fields_and_duplicate_json_fields_are_rejected() {
    let value = serde_json::json!({"schema_version":1,"profile_id":"a","layer":"core","version":"1","extends":null,"silent_disable":true});
    assert!(Profile::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Profile::parse(br#"{"schema_version":1,"schema_version":1,"profile_id":"a","layer":"core","version":"1","extends":null}"#).is_err());
}
#[test]
fn missing_parents_cycles_and_duplicate_profiles_are_rejected() {
    let mut input = profiles();
    input[2].extends = Some("missing".into());
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input[0].extends = Some("example-site".into());
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input.push(input[0].clone());
    assert!(compose(input, "example-site").is_err());
}
#[test]
fn core_invariants_and_product_constraints_cannot_be_weakened() {
    let mut input = profiles();
    input[0].invariants.pop();
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input[2].ui = input[0].ui.clone();
    input[2].ui.as_mut().unwrap().controls = true;
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input[2].cloudflare = input[0].cloudflare.clone();
    input[2]
        .cloudflare
        .as_mut()
        .unwrap()
        .per_detection_api_calls = true;
    assert!(compose(input, "example-site").is_err());
}
#[test]
fn limits_can_tighten_but_not_expand_or_be_zero() {
    let mut input = profiles();
    let mut limit = Limits::hard_maximum();
    limit.body_bytes = 4096;
    input[1].limits = Some(limit.clone());
    assert_eq!(
        compose(input.clone(), "example-site")
            .unwrap()
            .limits
            .body_bytes,
        4096
    );
    input[2].limits = Some(Limits::hard_maximum());
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    limit.body_bytes = 0;
    input[1].limits = Some(limit);
    assert!(compose(input, "example-site").is_err());
}
#[test]
fn site_exception_is_scoped_and_preserves_rule_provenance() {
    let mut input = profiles();
    input[0].rules.push(Rule {
        id: "common.test".into(),
        targets: vec![Target::Body],
        pattern: "sentinel".into(),
        high_confidence: false,
    });
    input[2].exceptions.push(Exception {
        rule_id: "common.test".into(),
        path_pattern: "^/feedback/$".into(),
        methods: vec!["POST".into()],
        reason: "Synthetic neutral-backend workflow".into(),
        evidence: "fixture/feedback".into(),
    });
    let policy = compose(input, "example-site").unwrap();
    assert_eq!(policy.rules["common.test"].layer, Layer::Core);
    assert!(
        policy
            .exception_for("common.test", "/feedback/", "POST")
            .is_some()
    );
    assert!(
        policy
            .exception_for("common.test", "/other/", "POST")
            .is_none()
    );
    assert!(
        policy
            .exception_for("common.test", "/feedback/", "GET")
            .is_none()
    );
}
#[test]
fn unknown_rules_invalid_regex_and_silent_overrides_are_rejected() {
    let mut input = profiles();
    let rule = Rule {
        id: "common.test".into(),
        targets: vec![Target::Body],
        pattern: "test".into(),
        high_confidence: false,
    };
    input[0].rules.push(rule.clone());
    input[1].rules.push(rule);
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input[0].rules.push(Rule {
        id: "bad".into(),
        targets: vec![Target::Body],
        pattern: "[".into(),
        high_confidence: false,
    });
    assert!(compose(input, "example-site").is_err());
    let mut input = profiles();
    input[2].exceptions.push(Exception {
        rule_id: "missing".into(),
        path_pattern: "^/x$".into(),
        methods: vec!["GET".into()],
        reason: "test".into(),
        evidence: "fixture".into(),
    });
    assert!(compose(input, "example-site").is_err());
}

#[test]
fn modules_preserve_provenance_reject_silent_overrides_and_nested_duplicate_keys() {
    use waf_core::profile::ModuleSpec;
    let mut input = profiles();
    input[2].modules.push(ModuleSpec {
        name: "wordpress-site".into(),
        settings: serde_json::json!({"schema_version":1}),
    });
    let policy = compose(input.clone(), "example-site").unwrap();
    assert_eq!(policy.modules["wordpress-site"].profile_id, "example-site");
    assert_eq!(policy.modules["wordpress"].layer, Layer::Application);
    let duplicate_module = input[1].modules[0].clone();
    input[2].modules.push(duplicate_module);
    assert!(compose(input, "example-site").is_err());
    let duplicate=br#"{"schema_version":1,"profile_id":"site","layer":"site","version":"1","extends":"wordpress-base","modules":[{"name":"wordpress-site","settings":{"schema_version":1,"schema_version":2}}]}"#;
    assert!(Profile::parse(duplicate).is_err());
}
