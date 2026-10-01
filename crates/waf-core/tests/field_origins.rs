use bytes::Bytes;
use waf_core::{
    inspect::{Inspector, ScannedRequest},
    profile::{Exception, Profile, Rule, Target, compose},
};

fn inspector(pattern: &str) -> Inspector {
    let mut profiles = [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(|bytes| Profile::parse(bytes).unwrap())
    .collect::<Vec<_>>();
    profiles[0].rules = vec![Rule {
        id: "fixture.origin".into(),
        targets: vec![Target::Body, Target::Query, Target::Headers, Target::Path],
        pattern: pattern.into(),
        high_confidence: true,
    }];
    profiles[2].exceptions = vec![Exception {
        rule_id: "fixture.origin".into(),
        path_pattern: "^/form/$".into(),
        methods: vec!["POST".into()],
        reason: "Fictional scalar field compatibility".into(),
        evidence: "field-origin-boundary-tests".into(),
        form_field: Some("secret".into()),
    }];
    Inspector::new(compose(profiles, "example-site").unwrap()).unwrap()
}
async fn scan(i: &Inspector, body: &'static str) -> ScannedRequest {
    i.scan(
        "/form/",
        "",
        "application/x-www-form-urlencoded",
        Bytes::from(body),
    )
    .await
    .unwrap()
}
fn assert_excepted(i: &Inspector, request: &ScannedRequest, expected: bool) {
    let matches = i.inspect_scanned_with_fields(request, "POST", &["secret"]);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].exception_profile.is_some(), expected);
    assert_eq!(matches[0].profile_id, "core-base");
    assert!(matches[0].high_confidence);
    assert!(request.views.body.is_empty());
}

#[test]
fn field_rules_with_zero_length_matches_are_rejected_before_serving() {
    for pattern in ["needle|$", "^$", r"\b"] {
        let mut policy = inspector("needle").policy;
        policy.rules.get_mut("fixture.origin").unwrap().rule.pattern = pattern.into();
        let error = Inspector::new(policy)
            .err()
            .expect("zero-length field rules must fail startup");
        assert_eq!(error.0, "empty_match_field_rule");
    }
}

#[tokio::test]
async fn scalar_origin_survives_name_value_and_separator_decoding() {
    let i = inspector("needle");
    for body in [
        "secret=needle",
        "%73ecret=nee%2564le",
        "secret=before%26other%3Dneedle&other=benign",
        "prefix=%E2%82%AC&secret=%E2%82%ACneedle&tail=%E2%82%AC",
        "prefix=%25FF&secret=needle%25FF&tail=%25FF",
        "secret=needle&tail=benign",
    ] {
        let request = scan(&i, body).await;
        assert_excepted(&i, &request, true);
        // Neither configuration alone nor a diagnostic collected view can apply it.
        assert!(
            i.inspect_scanned(&request, "POST")[0]
                .exception_profile
                .is_none()
        );
        assert!(
            i.inspect_scanned_with_fields(&request, "GET", &["secret"])[0]
                .exception_profile
                .is_none()
        );
        assert!(
            i.inspect_scanned_with_fields(&request, "POST", &["other"])[0]
                .exception_profile
                .is_none()
        );
    }
}

#[tokio::test]
async fn later_sibling_hits_duplicate_bindings_and_double_encoded_names_stay_unexcepted() {
    let i = inspector("needle");
    for body in [
        "secret=needle&other=needle",
        "other=needle&secret=needle",
        "secret=needle&secret=benign",
        "secret=needle&%73ecret=benign",
        "secret&secret=needle",
        "secret=needle&secret",
        "secret[]=needle",
        "%2573ecret=needle",
    ] {
        assert_excepted(&i, &scan(&i, body).await, false);
    }
}

#[tokio::test]
async fn crossing_and_overlapping_occurrences_cannot_borrow_a_field_exception() {
    let i = inspector("abc|bc&other");
    assert_excepted(&i, &scan(&i, "secret=abc").await, true);
    assert_excepted(&i, &scan(&i, "secret=abc&other=x").await, false);
    // Leftmost-first would choose the short alternative at the same start.
    let i = inspector("abc|abc&other");
    assert_excepted(&i, &scan(&i, "secret=abc&other=x").await, false);
    let i = inspector("needle|needle.*?tail");
    assert_excepted(&i, &scan(&i, "secret=needle&other=tail").await, false);
    let i = inspector("needle.*");
    assert_excepted(&i, &scan(&i, "secret=needle&other=x").await, false);
    let i = inspector("needle\\s+tail");
    assert_excepted(&i, &scan(&i, "secret=needle+tail").await, true);
}

#[tokio::test]
async fn unicode_boundaries_and_many_long_matches_use_complete_coverage() {
    let i = inspector(r"\bneedle\b");
    for body in [
        "secret=%E2%82%AC+needle",
        "secret=é+needle",
        "before=é&secret=needle&after=é",
    ] {
        assert_excepted(&i, &scan(&i, body).await, true);
    }
    let i = inspector("a.*b");
    let body = "secret=".to_owned() + &"ab".repeat(128 * 1024);
    let request = i
        .scan(
            "/form/",
            "",
            "application/x-www-form-urlencoded",
            Bytes::from(body),
        )
        .await
        .unwrap();
    assert_excepted(&i, &request, true);
}

#[tokio::test]
async fn all_starter_rule_automata_compile_and_preserve_qualified_literal_fields() {
    let mut profiles = [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(|bytes| Profile::parse(bytes).unwrap())
    .collect::<Vec<_>>();
    profiles[2].exceptions = profiles[0]
        .rules
        .iter()
        .map(|rule| Exception {
            rule_id: rule.id.clone(),
            path_pattern: "^/form/$".into(),
            methods: vec!["POST".into()],
            reason: "Fictional literal field compatibility".into(),
            evidence: "starter-field-automaton-test".into(),
            form_field: Some("secret".into()),
        })
        .collect();
    let i = Inspector::new(compose(profiles, "example-site").unwrap()).unwrap();
    for literal in [
        " UNION SELECT ",
        " sleep(1)",
        "<script>fixture</script>",
        "javascript:fixture",
        "<?php fixture",
        "../fixture",
        "/etc/passwd",
    ] {
        let value = literal
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        let request = i
            .scan(
                "/form/",
                "",
                "application/x-www-form-urlencoded",
                Bytes::from("secret=".to_owned() + &value),
            )
            .await
            .unwrap();
        let matches = i.inspect_scanned_with_fields(&request, "POST", &["secret"]);
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .all(|hit| hit.exception_profile.as_deref() == Some("example-site"))
        );
        assert!(
            i.inspect_scanned(&request, "POST")
                .iter()
                .all(|hit| hit.exception_profile.is_none())
        );
    }
}

#[tokio::test]
async fn query_headers_other_media_and_route_scope_remain_independent() {
    let i = inspector("needle");
    let mut request = scan(&i, "secret=needle").await;
    request.views.headers.push("needle".into());
    assert_excepted(&i, &request, false);
    let request = i
        .scan(
            "/form/",
            "q=needle",
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"secret=needle"),
        )
        .await
        .unwrap();
    assert_excepted(&i, &request, false);
    let request = i
        .scan(
            "/other/",
            "",
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"secret=needle"),
        )
        .await
        .unwrap();
    assert_excepted(&i, &request, false);
    for (media, body) in [
        ("text/plain", "secret=needle"),
        ("application/json", "{\"secret\":\"needle\"}"),
    ] {
        let request = i
            .scan("/form/", "", media, Bytes::from(body))
            .await
            .unwrap();
        assert_excepted(&i, &request, false);
    }
    for body in ["secret=needle&other=%zz", "secret=needle&other=%2525252541"] {
        assert!(
            i.scan(
                "/form/",
                "",
                "application/x-www-form-urlencoded",
                Bytes::from(body)
            )
            .await
            .is_err()
        );
    }
}
