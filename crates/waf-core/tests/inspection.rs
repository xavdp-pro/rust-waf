use bytes::Bytes;
use waf_core::{
    inspect::{Inspector, normalize},
    profile::{Exception, Profile, Rule, Target, compose},
};
fn inspector() -> Inspector {
    let mut profiles = [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(|b| Profile::parse(b).unwrap())
    .collect::<Vec<_>>();
    profiles[0].rules.push(Rule {
        id: "fixture.sentinel".into(),
        targets: vec![Target::Body, Target::Query],
        pattern: "forbidden-sentinel".into(),
        high_confidence: false,
    });
    profiles[2].exceptions.push(Exception {
        rule_id: "fixture.sentinel".into(),
        path_pattern: "^/public-search/$".into(),
        methods: vec!["POST".into()],
        reason: "Synthetic method-scoped compatibility test".into(),
        evidence: "inspection-stream-comparison".into(),
        form_field: None,
    });
    Inspector::new(compose(profiles, "example-site").unwrap()).unwrap()
}
#[tokio::test]
async fn entire_body_and_nested_form_encoding_are_inspected() {
    let i = inspector();
    let mut body = "padding=".to_string() + &"a".repeat(10000);
    body.push_str("&x=%2566orbidden-sentinel");
    let views = normalize(
        &i.policy,
        "/form/",
        "",
        "application/x-www-form-urlencoded",
        Bytes::from(body),
    )
    .await
    .unwrap();
    assert_eq!(i.inspect(&views, "POST").len(), 1);
}
#[tokio::test]
async fn json_escape_and_nested_strings_are_inspected() {
    let i = inspector();
    let views = normalize(
        &i.policy,
        "/api/",
        "",
        "application/json",
        Bytes::from_static(br#"{"nested":[{"x":"\u0066orbidden-sentinel"}]}"#),
    )
    .await
    .unwrap();
    assert_eq!(i.inspect(&views, "POST").len(), 1);
}
#[tokio::test]
async fn duplicate_nested_json_keys_invalid_encoding_and_paths_are_rejected() {
    let i = inspector();
    for json in [
        br#"{"nested":{"x":1,"x":2}}"#.as_slice(),
        br#"{"x":1} trailing"#.as_slice(),
    ] {
        assert!(
            normalize(
                &i.policy,
                "/api/",
                "",
                "application/json",
                Bytes::copy_from_slice(json)
            )
            .await
            .is_err()
        );
    }
    for path in ["/a/%2e%2e/b", "/a/%00", "/a/%zz", "/a/%255c"] {
        assert!(
            normalize(&i.policy, path, "", "", Bytes::new())
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn multipart_fields_and_file_names_are_inspected_and_truncation_is_rejected() {
    let i = inspector();
    let body=b"--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"forbidden-sentinel.txt\"\r\nContent-Type: text/plain\r\n\r\nbenign\r\n--test-boundary--\r\n";
    let views = normalize(
        &i.policy,
        "/upload/",
        "",
        "multipart/form-data; boundary=test-boundary",
        Bytes::copy_from_slice(body),
    )
    .await
    .unwrap();
    assert_eq!(i.inspect(&views, "POST").len(), 1);
    assert!(
        normalize(
            &i.policy,
            "/upload/",
            "",
            "multipart/form-data; boundary=test-boundary",
            Bytes::copy_from_slice(&body[..body.len() - 25])
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn benign_text_and_php_array_form_fields_are_preserved() {
    let i = inspector();
    for (kind, body) in [
        (
            "application/x-www-form-urlencoded",
            "items[]=one&items[]=two&text=hello+world",
        ),
        ("text/plain", "A sale of 20% is fine."),
        ("application/json", ""),
        ("application/problem+json", ""),
    ] {
        let views = normalize(&i.policy, "/form/", "", kind, Bytes::from(body))
            .await
            .unwrap();
        assert!(i.inspect(&views, "POST").is_empty());
    }
}

#[tokio::test]
async fn large_complete_views_preserve_binary_and_encoded_tail_detection() {
    let i = inspector();
    let size = 8 * 1024 * 1024;
    for media in [
        "application/octet-stream",
        "application/x-www-form-urlencoded",
    ] {
        let mut body = vec![
            if media == "application/octet-stream" {
                0xff
            } else {
                b'a'
            };
            size
        ];
        let tail = b"%2566orbidden-sentinel";
        body[size - tail.len()..].copy_from_slice(tail);
        let views = normalize(&i.policy, "/fixture/", "", media, Bytes::from(body))
            .await
            .unwrap();
        assert_eq!(i.inspect(&views, "POST").len(), 1);
        assert_eq!(views.body.len(), 3);
    }
    let views = normalize(
        &i.policy,
        "/fixture/",
        "",
        "application/octet-stream",
        Bytes::from(vec![0xff; size]),
    )
    .await
    .unwrap();
    assert!(i.inspect(&views, "POST").is_empty());
    // Every invalid byte remains visible as a replacement character; no byte sampling.
    assert_eq!(views.body.len(), 1);
    assert_eq!(views.body[0].len(), size * 3);
    let views = normalize(
        &i.policy,
        "/fixture/",
        "",
        "application/x-www-form-urlencoded",
        Bytes::from(vec![b'a'; size]),
    )
    .await
    .unwrap();
    assert_eq!(views.body.len(), 1);
    assert_eq!(views.body[0].len(), size);
}

#[tokio::test]
async fn owned_json_and_multipart_views_preserve_keys_escapes_and_file_tail() {
    let i = inspector();
    for body in [
        br#"{"%2566orbidden-sentinel":[0,true,null,{"safe":"ok"}]}"#.as_slice(),
        br#"{"safe":["%2566orbidden-sentinel"]}"#.as_slice(),
        br#"{"safe":"\u0066orbidden-sentinel"}"#.as_slice(),
    ] {
        let views = normalize(
            &i.policy,
            "/fixture/",
            "",
            "application/json",
            Bytes::copy_from_slice(body),
        )
        .await
        .unwrap();
        assert_eq!(i.inspect(&views, "POST").len(), 1);
    }
    let mut body = b"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.bin\"\r\n\r\n".to_vec();
    body.extend(std::iter::repeat_n(0xff, 1024 * 1024));
    body.extend_from_slice(b"%2566orbidden-sentinel\r\n--fixture--\r\n");
    let views = normalize(
        &i.policy,
        "/fixture/",
        "",
        "multipart/form-data; boundary=fixture",
        Bytes::from(body),
    )
    .await
    .unwrap();
    assert_eq!(i.inspect(&views, "POST").len(), 1);
    assert!(
        normalize(
            &i.policy,
            "/fixture/",
            "",
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"a=%zz")
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn streamed_matches_preserve_normalized_targets_methods_and_exception_provenance() {
    let i = inspector();
    let multipart = b"--fixture\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"forbidden-sentinel.txt\"\r\n\r\n%2566orbidden-sentinel\r\n--fixture--\r\n";
    for (media, body) in [
        (
            "application/json",
            br#"{"%2566orbidden-sentinel":[0,true,null,{"safe":"ok"}]}"#.as_slice(),
        ),
        (
            "application/json",
            br#"{"safe":["%2566orbidden-sentinel","\u0066orbidden-sentinel"]}"#.as_slice(),
        ),
        (
            "application/json",
            br#"[null,true,false,1,-2,1.0,1e20,[],{},""]"#.as_slice(),
        ),
        ("application/json", b"".as_slice()),
        ("text/plain", b"%2566orbidden-sentinel".as_slice()),
        (
            "application/octet-stream",
            b"\xff%2566orbidden-sentinel".as_slice(),
        ),
        (
            "application/x-www-form-urlencoded",
            b"a=%2566orbidden-sentinel&items[]=one&items[]=two".as_slice(),
        ),
        (
            "multipart/form-data; boundary=fixture",
            multipart.as_slice(),
        ),
    ] {
        for path in ["/fixture/", "/public-search/"] {
            let views = normalize(
                &i.policy,
                path,
                "x=%2566orbidden-sentinel",
                media,
                Bytes::copy_from_slice(body),
            )
            .await
            .unwrap();
            let scanned = i
                .scan(
                    path,
                    "x=%2566orbidden-sentinel",
                    media,
                    Bytes::copy_from_slice(body),
                )
                .await
                .unwrap();
            assert!(scanned.views.body.is_empty());
            for method in ["GET", "POST", "DELETE"] {
                assert_eq!(
                    serde_json::to_value(i.inspect(&views, method)).unwrap(),
                    serde_json::to_value(i.inspect_scanned(&scanned, method)).unwrap()
                );
            }
        }
    }
    let scanned = i
        .scan(
            "/public-search/",
            "",
            "application/json",
            Bytes::from_static(br#"{"x":"forbidden-sentinel"}"#),
        )
        .await
        .unwrap();
    assert_eq!(
        i.inspect_scanned(&scanned, "POST")[0]
            .exception_profile
            .as_deref(),
        Some("example-site")
    );
    assert!(
        i.inspect_scanned(&scanned, "DELETE")[0]
            .exception_profile
            .is_none()
    );
}

#[tokio::test]
async fn streamed_json_rejects_ambiguity_and_invalid_tail_after_a_detection() {
    let i = inspector();
    for body in [
        br#"{"nested":{"a":1,"\u0061":2}}"#.as_slice(),
        br#"{"x":"forbidden-sentinel","x":0}"#.as_slice(),
        br#"{"x":"forbidden-sentinel"} trailing"#.as_slice(),
        br#"{"x":"forbidden-sentinel","tail": [1,]}"#.as_slice(),
        br#"{"x":"forbidden-sentinel","tail": "\ud800"}"#.as_slice(),
        br#"[1e999]"#.as_slice(),
        br#"{"x":"%2525252566orbidden-sentinel"}"#.as_slice(),
    ] {
        assert!(
            i.scan(
                "/fixture/",
                "",
                "application/json",
                Bytes::copy_from_slice(body)
            )
            .await
            .is_err()
        );
    }
    let nested = "[".repeat(200) + "0" + &"]".repeat(200);
    assert!(
        i.scan("/fixture/", "", "application/json", Bytes::from(nested))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn streamed_large_json_and_binary_keep_tail_hits_without_retained_body_views() {
    let i = inspector();
    let mut json = b"[".to_vec();
    for _ in 0..100_000 {
        json.extend_from_slice(b"[\"\",null,0],");
    }
    json.extend_from_slice(br#"{"tail":"\u0066orbidden-sentinel"}]"#);
    let scanned = i
        .scan("/fixture/", "", "application/json", Bytes::from(json))
        .await
        .unwrap();
    assert!(scanned.views.body.is_empty());
    assert_eq!(i.inspect_scanned(&scanned, "POST").len(), 1);
    let mut binary = vec![0xff; 8 * 1024 * 1024];
    let tail = b"%2566orbidden-sentinel";
    let start = binary.len() - tail.len();
    binary[start..].copy_from_slice(tail);
    let scanned = i
        .scan(
            "/fixture/",
            "",
            "application/octet-stream",
            Bytes::from(binary),
        )
        .await
        .unwrap();
    assert!(scanned.views.body.is_empty());
    assert_eq!(i.inspect_scanned(&scanned, "POST").len(), 1);
}
