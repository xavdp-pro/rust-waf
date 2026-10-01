use bytes::Bytes;
use serde_json::json;
use std::collections::BTreeMap;
use waf_core::profile::{Layer, SourcedModule};
use waf_wordpress::{Request, Wordpress};
fn wordpress(settings: serde_json::Value) -> Wordpress {
    let modules = BTreeMap::from([
        (
            "wordpress".into(),
            SourcedModule {
                profile_id: "wordpress-base".into(),
                layer: Layer::Application,
                settings: json!({"schema_version":1}),
            },
        ),
        (
            "wordpress-site".into(),
            SourcedModule {
                profile_id: "fictional-site".into(),
                layer: Layer::Site,
                settings,
            },
        ),
    ]);
    Wordpress::from_modules(&modules).unwrap().unwrap()
}
fn request<'a>(path: &'a str, query: &'a str, method: &'a str) -> Request<'a> {
    Request {
        path,
        query,
        wire_method: method,
        headers: &[],
        content_type: "",
        body: Bytes::new(),
        max_parts: 128,
    }
}
fn policy() -> Wordpress {
    wordpress(
        json!({"schema_version":1,"method_rules":[{"id":"fixture.cart","scope":"rest","pattern":"^/shop/v1/cart/items/[0-9]+$","methods":["GET","DELETE"],"evidence":"fictional-cart-workflow"}]}),
    )
}
#[tokio::test]
async fn query_override_precedes_header_and_preserves_head_options() {
    let wp = policy();
    let headers = vec![("X-HTTP-Method-Override".into(), "PUT".into())];
    let mut input = request("/wp-json/shop/v1/cart/items/42", "_method=delete", "POST");
    input.headers = &headers;
    let context = wp.analyze(input).await.unwrap();
    assert_eq!(context.effective_method, "DELETE");
    assert_eq!(context.method_source, "query");
    assert!(wp.check(&context, false).is_none());
    for method in ["HEAD", "OPTIONS"] {
        let context = wp
            .analyze(request("/wp-json/shop/v1/cart/items/42", "", method))
            .await
            .unwrap();
        assert!(wp.check(&context, false).is_none());
    }
    let context = wp
        .analyze(request(
            "/wp-json/shop/v1/cart/items/42",
            "_method=PUT",
            "POST",
        ))
        .await
        .unwrap();
    let denial = wp.check(&context, false).unwrap();
    assert_eq!(denial.status, 405);
    assert_eq!(denial.profile_id, "fictional-site");
}
#[tokio::test]
async fn php_key_normalization_and_ambiguous_dispatch_are_handled() {
    let wp = policy();
    for query in ["%5Fmethod=DELETE", ".method=DELETE", "+_method=DELETE"] {
        let context = wp
            .analyze(request("/wp-json/shop/v1/cart/items/42", query, "POST"))
            .await
            .unwrap();
        assert_eq!(context.effective_method, "DELETE");
    }
    for query in [
        "_method=GET&_method=DELETE",
        "_method[]=DELETE",
        "_method=TRACE",
        "rest_route[]=x",
        "rest_route=/x&rest.route=/y",
    ] {
        assert!(
            wp.analyze(request("/wp-json/shop/v1/cart/items/42", query, "POST"))
                .await
                .is_err(),
            "{query}"
        );
    }
    // Encoded separators remain in one value; they cannot create dispatch parameters.
    let context = wp
        .analyze(request(
            "/wp-json/shop/v1/cart/items/42",
            "x=benign%26_method%3DDELETE",
            "POST",
        ))
        .await
        .unwrap();
    assert_eq!(context.effective_method, "POST");
}
#[tokio::test]
async fn front_controller_alternatives_custom_prefix_and_trailing_slash_are_resolved() {
    let wp = policy();
    for (path, query) in [
        ("/wp-json/shop/v1/cart/items/42/", ""),
        ("/index.php/wp-json/shop/v1/cart/items/42", ""),
        (
            "/index.php",
            "rest.route=%2Fshop%2Fv1%2Fcart%2Fitems%2F42%2F",
        ),
        ("/any-front-page/", "rest_route=/shop/v1/cart/items/42"),
    ] {
        let context = wp.analyze(request(path, query, "DELETE")).await.unwrap();
        assert_eq!(
            context.rest_route.as_deref(),
            Some("/shop/v1/cart/items/42")
        );
        assert!(wp.check(&context, false).is_none());
    }
    let wp = wordpress(json!({"schema_version":1,"base_path":"/blog/","rest_prefix":"api"}));
    let context = wp
        .analyze(request("/blog/index.php/api/wp/v2/posts/", "", "GET"))
        .await
        .unwrap();
    assert_eq!(context.rest_route.as_deref(), Some("/wp/v2/posts"));
    let outside = wp
        .analyze(request("/outside/", "rest_route=/wp/v2/posts", "GET"))
        .await
        .unwrap();
    assert!(outside.rest_route.is_none());
}
#[tokio::test]
async fn administration_needs_trust_but_member_login_and_ajax_remain_available() {
    let wp = policy();
    for path in [
        "/wp-admin/",
        "/%77p-admin/users.php",
        "//wp-admin/plugins.php",
    ] {
        let context = wp.analyze(request(path, "", "GET")).await.unwrap();
        assert_eq!(wp.check(&context, false).unwrap().status, 403);
        assert!(wp.check(&context, true).is_none());
    }
    for (path, family) in [
        ("/wp-login.php", "member_login"),
        ("/wp-admin/admin-ajax.php", "ajax"),
        ("/wp-admin/admin-post.php", "admin_post"),
    ] {
        let context = wp
            .analyze(request(path, "action=fixture", "POST"))
            .await
            .unwrap();
        assert_eq!(context.family, family);
        assert!(wp.check(&context, false).is_none());
    }
    let context = wp
        .analyze(request(
            "/wp-login.php",
            "rest_route=/wp/v2/posts&_method=DELETE",
            "POST",
        ))
        .await
        .unwrap();
    assert_eq!(context.family, "member_login");
    assert_eq!(context.effective_method, "POST");
}
#[tokio::test]
async fn post_form_dispatch_precedes_query_but_body_method_override_is_ignored() {
    let wp = policy();
    let mut input = request("/", "_method=DELETE", "POST");
    input.content_type = "application/x-www-form-urlencoded";
    input.body = Bytes::from_static(b"rest.route=%2Fshop%2Fv1%2Fcart%2Fitems%2F42&_method=PUT");
    let context = wp.analyze(input).await.unwrap();
    assert_eq!(
        context.rest_route.as_deref(),
        Some("/shop/v1/cart/items/42")
    );
    assert_eq!(context.effective_method, "DELETE");
    assert!(wp.check(&context, false).is_none());
    let mut mismatch = request("/", "rest_route=/other", "POST");
    mismatch.content_type = "application/x-www-form-urlencoded";
    mismatch.body = Bytes::from_static(b"rest_route=/shop/v1/cart/items/42");
    assert!(wp.analyze(mismatch).await.is_err());
    let mut input = request("/", "", "POST");
    input.content_type = "application/json";
    input.body = Bytes::from_static(br#"{"rest_route":"/shop/v1/cart/items/42"}"#);
    assert!(wp.analyze(input).await.unwrap().rest_route.is_none());
}
#[tokio::test]
async fn multipart_dispatch_fields_work_and_uploaded_filenames_are_not_post_values() {
    let wp = policy();
    let mut input = request("/", "_method=DELETE", "POST");
    input.content_type = "multipart/form-data; boundary=fixture";
    input.body=Bytes::from_static(b"--fixture\r\nContent-Disposition: form-data; name=\"rest_route\"\r\n\r\n/shop/v1/cart/items/42\r\n--fixture--\r\n");
    assert_eq!(
        wp.analyze(input).await.unwrap().rest_route.as_deref(),
        Some("/shop/v1/cart/items/42")
    );
    let mut input = request("/", "", "POST");
    input.content_type = "multipart/form-data; boundary=fixture";
    input.body=Bytes::from_static(b"--fixture\r\nContent-Disposition: form-data; name=\"rest_route\"; filename=\"fixture.txt\"\r\n\r\n/shop/v1/cart/items/42\r\n--fixture--\r\n");
    assert!(wp.analyze(input).await.unwrap().rest_route.is_none());
}
#[tokio::test]
async fn unqualified_business_fields_and_routes_are_not_assumed_forbidden() {
    let wp = policy();
    let mut input = request(
        "/unknown-form/",
        "action[]=one&action[]=two&_method[]=business-value",
        "POST",
    );
    input.content_type = "application/x-www-form-urlencoded";
    input.body = Bytes::from_static(b"action[]=one&action[]=two&_method[]=business-value");
    let context = wp.analyze(input).await.unwrap();
    assert_eq!(context.family, "unqualified");
    assert!(wp.check(&context, false).is_none());
    let context = wp
        .analyze(request("/wp-json/custom/v1/unknown", "", "PATCH"))
        .await
        .unwrap();
    assert!(wp.check(&context, false).is_none());
}
#[test]
fn unknown_modules_unknown_fields_and_weak_method_rules_fail_startup() {
    let mut modules = BTreeMap::new();
    modules.insert(
        "unexpected".into(),
        SourcedModule {
            profile_id: "x".into(),
            layer: Layer::Site,
            settings: json!({}),
        },
    );
    assert!(Wordpress::from_modules(&modules).is_err());
    for settings in [
        json!({"schema_version":2}),
        json!({"schema_version":1,"disable_admin_guard":true}),
        json!({"schema_version":1,"method_rules":[{"id":"bad","scope":"rest","pattern":"/x","methods":["GET"],"evidence":"fixture"}]}),
    ] {
        let modules = BTreeMap::from([
            (
                "wordpress".into(),
                SourcedModule {
                    profile_id: "wp".into(),
                    layer: Layer::Application,
                    settings: json!({"schema_version":1}),
                },
            ),
            (
                "wordpress-site".into(),
                SourcedModule {
                    profile_id: "site".into(),
                    layer: Layer::Site,
                    settings,
                },
            ),
        ]);
        assert!(Wordpress::from_modules(&modules).is_err());
    }
}
