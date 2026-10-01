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

fn multiple_inspector(pattern: &str) -> Inspector {
    let mut policy = inspector(pattern).policy;
    let mut second = policy.exceptions[0].clone();
    second.exception.form_field = Some("content".into());
    policy.exceptions.push(second);
    Inspector::new(policy).unwrap()
}

#[tokio::test]
async fn multiple_fields_need_separate_confirmed_scopes_for_every_view() {
    let i = multiple_inspector("needle");
    for body in [
        "secret=needle&content=needle",
        "content=nee%2564le&secret=needle",
        "secret=needle&content=needle&other=benign",
        "content=%E2%82%AC+needle&secret=needle",
    ] {
        let request = scan(&i, body).await;
        let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"]);
        assert_eq!(hits[0].exception_profile.as_deref(), Some("example-site"));
        assert!(
            i.inspect_scanned_with_fields(&request, "POST", &["secret"])[0]
                .exception_profile
                .is_none()
        );
        assert!(
            i.inspect_scanned_with_fields(&request, "POST", &["content"])[0]
                .exception_profile
                .is_none()
        );
        assert!(
            i.inspect_scanned_with_fields(&request, "GET", &["secret", "content"])[0]
                .exception_profile
                .is_none()
        );
    }
    for body in [
        "secret=needle&content=needle&other=needle",
        "other=needle&secret=needle&content=needle",
        "secret=needle&content=needle&content=benign",
        "secret=needle&content=needle&%63ontent=benign",
    ] {
        let request = scan(&i, body).await;
        assert!(
            i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"])[0]
                .exception_profile
                .is_none()
        );
    }
    let mut policy = i.policy;
    policy.exceptions[1].exception.methods = vec!["PUT".into()];
    let i = Inspector::new(policy).unwrap();
    let request = scan(&i, "secret=needle&content=needle").await;
    assert!(
        i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"])[0]
            .exception_profile
            .is_none()
    );
    assert!(
        i.inspect_scanned_with_fields(&request, "PUT", &["secret", "content"])[0]
            .exception_profile
            .is_none()
    );
}

#[tokio::test]
async fn all_alternatives_and_cross_field_matches_remain_unexcepted() {
    for pattern in [
        "needle|needle&content=needle",
        "needle|dle&content",
        "needle.*needle",
        "needle.*?needle",
        "needle.*",
    ] {
        let i = multiple_inspector(pattern);
        let request = scan(&i, "secret=needle&content=needle").await;
        let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"]);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].exception_profile.is_none(), "{pattern}");
    }
    let i = multiple_inspector(r"\bneedle\b");
    let request = scan(&i, "secret=needle&content=needle").await;
    assert!(
        i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"])[0]
            .exception_profile
            .is_some()
    );
}

#[tokio::test]
async fn unapplied_candidates_preserve_blocking_and_disclose_profiles_only() {
    let i = multiple_inspector("needle|needle.*tail");
    let request = scan(
        &i,
        "other=needle&secret=nee%2564lePRIVATE_SENTINEL&content=needle&tail=tail",
    )
    .await;
    let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"]);
    assert!(hits[0].exception_profile.is_none());
    assert!(hits[0].high_confidence);
    assert_eq!(hits[0].unapplied_field_profiles, ["example-site"]);
    let encoded = serde_json::to_string(&hits).unwrap();
    assert!(!encoded.contains("PRIVATE_SENTINEL"));
    assert!(!encoded.contains("\"secret\""));
    for (method, fields) in [
        ("GET", vec!["secret", "content"]),
        ("POST", vec![]),
        ("POST", vec!["unknown"]),
    ] {
        let hits = i.inspect_scanned_with_fields(&request, method, &fields);
        assert!(hits[0].exception_profile.is_none());
        assert!(hits[0].unapplied_field_profiles.is_empty());
    }
}

#[tokio::test]
async fn duplicate_bindings_and_global_anchors_do_not_invent_candidates() {
    for (pattern, body) in [
        ("needle", "secret=needle&secret=benign&other=needle"),
        ("needle$", "secret=needle&other=needle"),
        (r"\bneedle\b", "secret=needleX&other=needle"),
    ] {
        let i = inspector(pattern);
        let request = scan(&i, body).await;
        let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret"]);
        assert!(hits[0].exception_profile.is_none());
        assert!(hits[0].unapplied_field_profiles.is_empty(), "{pattern}");
    }
}

#[tokio::test]
async fn fully_applied_exceptions_and_unmatched_fields_have_no_unapplied_candidates() {
    let i = multiple_inspector("needle");
    let request = scan(&i, "secret=needle&content=needle").await;
    let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret", "content"]);
    assert!(hits[0].exception_profile.is_some());
    assert!(hits[0].unapplied_field_profiles.is_empty());
    let request = i
        .scan(
            "/form/",
            "q=needle",
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"secret=benign"),
        )
        .await
        .unwrap();
    let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret"]);
    assert!(hits[0].exception_profile.is_none());
    assert!(hits[0].unapplied_field_profiles.is_empty());
}

fn nested_inspector() -> Inspector {
    let mut policy = inspector("needle").policy;
    policy.exceptions[0].exception.form_field = Some("form[fields][1]".into());
    Inspector::new(policy).unwrap()
}

#[tokio::test]
async fn nested_leaf_origins_preserve_decoding_and_disjoint_sibling_arrays() {
    let i = nested_inspector();
    for body in [
        "form[fields][1]=needle",
        "%66orm%5Bfields%5D%5B1%5D=nee%2564le",
        "form[fields][1]=needle&form[fields][2]=benign",
        "form[fields][2][]=benign&form[fields][1]=needle",
        "form[fields][1]=needle&other[]=benign",
        "form[fields][1]=before%26form%5Bfields%5D%5B2%5D%3Dneedle",
        "form[fields][01]=benign&form[fields][1]=needle",
    ] {
        let request = scan(&i, body).await;
        let matches = i.inspect_scanned_with_fields(&request, "POST", &["form[fields][1]"]);
        assert_eq!(matches.len(), 1, "{body}");
        assert!(matches[0].exception_profile.is_some(), "{body}");
        assert!(
            i.inspect_scanned(&request, "POST")[0]
                .exception_profile
                .is_none()
        );
        assert!(
            i.inspect_scanned_with_fields(&request, "GET", &["form[fields][1]"])[0]
                .exception_profile
                .is_none()
        );
    }
}

#[tokio::test]
async fn nested_alias_ancestor_descendant_and_sibling_hits_withhold_exceptions() {
    let i = nested_inspector();
    for body in [
        "form[fields][1]=needle&form[fields][1]=benign",
        "form[fields][1]=needle&%66orm%5Bfields%5D%5B1%5D=benign",
        "form[fields][1]=needle&form[fields][1]",
        "form[fields][1]&form[fields][1]=needle",
        "form=benign&form[fields][1]=needle",
        "form[fields][1]=needle&form=benign",
        "form[fields]=benign&form[fields][1]=needle",
        "form[fields][1]=needle&form[fields][1][child]=benign",
        "form[fields][]=benign&form[fields][1]=needle",
        "form[fields][1]=needle&form[fields][1][]",
        "form[fields][1]=needle&form[fields][1]ignored=benign",
        "form[fields][1]=needle&form[fields][2]=needle",
        "%2566orm[fields][1]=needle",
        "form[fields][01]=needle",
    ] {
        let matches =
            i.inspect_scanned_with_fields(&scan(&i, body).await, "POST", &["form[fields][1]"]);
        assert_eq!(matches.len(), 1, "{body}");
        assert!(matches[0].exception_profile.is_none(), "{body}");
    }
    let body = "form[fields][1]=needle&".to_owned() + &"other".repeat(50) + "=benign";
    let request = i
        .scan(
            "/form/",
            "",
            "application/x-www-form-urlencoded",
            Bytes::from(body),
        )
        .await
        .unwrap();
    assert!(
        i.inspect_scanned_with_fields(&request, "POST", &["form[fields][1]"])[0]
            .exception_profile
            .is_none()
    );
}

fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> Bytes {
    let mut body = Vec::new();
    for (name, filename, value) in parts {
        body.extend_from_slice(
            format!("--fixture-boundary\r\nContent-Disposition: form-data; name=\"{name}\"")
                .as_bytes(),
        );
        if let Some(filename) = filename {
            body.extend_from_slice(format!("; filename=\"{filename}\"").as_bytes());
        }
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fixture-boundary--\r\n");
    Bytes::from(body)
}
async fn scan_multipart(i: &Inspector, parts: &[(&str, Option<&str>, &[u8])]) -> ScannedRequest {
    i.scan(
        "/form/",
        "",
        "multipart/form-data; boundary=fixture-boundary",
        multipart(parts),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn multipart_leaf_origins_preserve_decoded_values_unicode_and_binary_prefix_offsets() {
    let i = inspector("needle");
    for value in [
        b"needle".as_slice(),
        b"nee%2564le",
        b"before%26other%3Dneedle",
        "€needle€".as_bytes(),
    ] {
        let request = scan_multipart(
            &i,
            &[
                ("upload", Some("file;name.bin"), b"\xff\xf0\x9f"),
                ("secret", None, value),
                ("other", None, b"benign"),
            ],
        )
        .await;
        assert_excepted(&i, &request, true);
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
    }
    let i = nested_inspector();
    let request = scan_multipart(
        &i,
        &[
            ("form[fields][1]", None, b"needle"),
            ("form[fields][01]", None, b"benign"),
        ],
    )
    .await;
    assert!(
        i.inspect_scanned_with_fields(&request, "POST", &["form[fields][1]"])[0]
            .exception_profile
            .is_some()
    );
}

#[tokio::test]
async fn multipart_duplicates_files_names_headers_and_siblings_never_borrow_leaf_origins() {
    let i = inspector("needle");
    for parts in [
        vec![
            ("secret", None, b"needle".as_slice()),
            ("secret", None, b"benign"),
        ],
        vec![
            ("secret", None, b"benign".as_slice()),
            ("secret", None, b"needle"),
        ],
        vec![
            ("secret", None, b"needle".as_slice()),
            ("secret[child]", None, b"benign"),
        ],
        vec![("secret", Some("file.bin"), b"needle".as_slice())],
        vec![
            ("secret", None, b"needle".as_slice()),
            ("file", Some("file.bin"), b"needle"),
        ],
        vec![
            ("secret", None, b"needle".as_slice()),
            ("other", None, b"needle"),
        ],
        vec![
            ("secret", None, b"needle".as_slice()),
            ("needle", None, b"benign"),
        ],
        vec![
            ("secret", None, b"needle".as_slice()),
            ("file", Some("needle.bin"), b"benign"),
        ],
        vec![("%73ecret", None, b"needle".as_slice())],
        vec![("secret", None, b"\xffneedle".as_slice())],
    ] {
        assert_excepted(&i, &scan_multipart(&i, &parts).await, false);
    }
    let mut body = multipart(&[("secret", None, b"needle")]).to_vec();
    let marker = b"\r\n\r\n";
    let at = body
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    body.splice(at..at, b"\r\nX-Fixture: needle".iter().copied());
    let request = i
        .scan(
            "/form/",
            "",
            "multipart/form-data; boundary=fixture-boundary",
            Bytes::from(body),
        )
        .await
        .unwrap();
    assert_excepted(&i, &request, false);
}

#[tokio::test]
async fn multipart_nested_tree_writes_and_unsupported_headers_withhold_confirmation() {
    let i = nested_inspector();
    for name in [
        "form",
        "form[fields]",
        "form[fields][1][child]",
        "form[fields][1]ignored",
        "form[fields][]",
    ] {
        for before in [true, false] {
            let selected = ("form[fields][1]", None, b"needle".as_slice());
            let conflicting = (name, None, b"benign".as_slice());
            let parts = if before {
                vec![conflicting, selected]
            } else {
                vec![selected, conflicting]
            };
            let request = scan_multipart(&i, &parts).await;
            assert!(
                i.inspect_scanned_with_fields(&request, "POST", &["form[fields][1]"])[0]
                    .exception_profile
                    .is_none(),
                "{name}"
            );
        }
    }
    let i = inspector("needle");
    for extra in [
        "\r\nX-Fixture: benign",
        "\r\nContent-Transfer-Encoding: binary",
    ] {
        let body = String::from_utf8(multipart(&[("secret", None, b"needle")]).to_vec())
            .unwrap()
            .replace("\r\n\r\n", &format!("{extra}\r\n\r\n"));
        let request = i
            .scan(
                "/form/",
                "",
                "multipart/form-data; boundary=fixture-boundary",
                Bytes::from(body),
            )
            .await
            .unwrap();
        assert_excepted(&i, &request, false);
    }
}

#[tokio::test]
async fn multipart_match_hulls_truncation_and_part_limits_preserve_complete_validation() {
    for pattern in [
        "(?s)needle.*Content-Disposition",
        "(?s)needle|needle.*Content-Disposition",
    ] {
        let i = inspector(pattern);
        let request = scan_multipart(
            &i,
            &[("secret", None, b"needle"), ("other", None, b"benign")],
        )
        .await;
        assert_excepted(&i, &request, false);
    }
    let i = inspector("needle");
    let body = multipart(&[("secret", None, b"needle"), ("other", None, b"benign")]);
    let truncated = body.slice(..body.len() - 10);
    assert!(
        i.scan(
            "/form/",
            "",
            "multipart/form-data; boundary=fixture-boundary",
            truncated
        )
        .await
        .is_err()
    );
    let mut policy = i.policy.clone();
    policy.limits.multipart_parts = 1;
    let bounded = Inspector::new(policy).unwrap();
    assert!(
        bounded
            .scan(
                "/form/",
                "",
                "multipart/form-data; boundary=fixture-boundary",
                body
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn multipart_multiple_leaves_require_independent_confirmations_and_keep_candidates() {
    let mut policy = inspector("needle").policy;
    let mut extra = policy.exceptions[0].clone();
    extra.exception.form_field = Some("other".into());
    policy.exceptions.push(extra);
    let i = Inspector::new(policy).unwrap();
    let request = scan_multipart(
        &i,
        &[("secret", None, b"needle"), ("other", None, b"nee%2564le")],
    )
    .await;
    assert!(
        i.inspect_scanned_with_fields(&request, "POST", &["secret", "other"])[0]
            .exception_profile
            .is_some()
    );
    let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret"]);
    assert!(hits[0].exception_profile.is_none());
    assert_eq!(hits[0].unapplied_field_profiles, ["example-site"]);
    let request = scan_multipart(
        &i,
        &[
            ("secret", None, b"needle"),
            ("other", None, b"needle"),
            ("file", Some("file.bin"), b"needle"),
        ],
    )
    .await;
    let hits = i.inspect_scanned_with_fields(&request, "POST", &["secret", "other"]);
    assert!(hits[0].exception_profile.is_none());
    assert_eq!(hits[0].unapplied_field_profiles, ["example-site"]);
}

#[tokio::test]
async fn multipart_extra_media_parameters_cannot_grant_field_exceptions() {
    let i = inspector("needle");
    let request = i
        .scan(
            "/form/",
            "",
            "multipart/form-data; boundary=fixture-boundary; charset=utf-8",
            multipart(&[("secret", None, b"needle")]),
        )
        .await
        .unwrap();
    assert_excepted(&i, &request, false);
}
