use bytes::Bytes;
use waf_core::{
    inspect::{Inspector, normalize},
    profile::{Profile, Rule, Target, compose},
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
    ] {
        let views = normalize(&i.policy, "/form/", "", kind, Bytes::from(body))
            .await
            .unwrap();
        assert!(i.inspect(&views, "POST").is_empty());
    }
}
