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

fn login_policy() -> Wordpress {
    wordpress(json!({"schema_version":1,"login_consumers":[{
        "path":"/member-entry","request_order":"GP","evidence":"fictional-wp-signon-consumer"}]}))
}
fn login_request<'a>(query: &'a str, method: &'a str, body: &'static str) -> Request<'a> {
    let mut input = request("/member-entry/", query, method);
    input.content_type = "application/x-www-form-urlencoded";
    input.body = Bytes::from(body);
    input
}

#[tokio::test]
async fn login_scalar_requires_explicit_consumer_and_keeps_values_out_of_context() {
    let wp = login_policy();
    for body in ["pwd=literal", "%70wd=literal", "pwd=literal&action=login"] {
        let context = wp.analyze(login_request("", "POST", body)).await.unwrap();
        assert_eq!(context.confirmed_fields, ["pwd"]);
        assert_eq!(context.family, "member_login");
        assert_eq!(context.consumer_profile.as_deref(), Some("fictional-site"));
        let serialized = serde_json::to_string(&context).unwrap();
        assert!(!serialized.contains("literal"));
        assert!(!serialized.contains("confirmed_fields"));
    }
    let wp = policy();
    let context = wp
        .analyze(login_request("", "POST", "pwd=literal"))
        .await
        .unwrap();
    assert!(context.confirmed_fields.is_empty());
    let mut input = request("/wp-login.php", "", "POST");
    input.body = Bytes::from_static(b"pwd=literal");
    input.content_type = "application/x-www-form-urlencoded";
    assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
}

#[tokio::test]
async fn login_actions_get_overrides_methods_and_rest_cannot_borrow_password_binding() {
    let wp = login_policy();
    for query in [
        "action=logout",
        "action=rp",
        "key=",
        "checkemail=0",
        "rest_route=/fixture/v1/x",
        "rest_route=0",
        "action=custom",
    ] {
        assert!(
            wp.analyze(login_request(query, "POST", "pwd=literal"))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
    for body in [
        "pwd=literal&action=logout",
        "pwd=literal&rest_route=/fixture/v1/x",
        "pwd=",
        "pwd=0",
        "pwd=%30",
    ] {
        assert!(
            wp.analyze(login_request("", "POST", body))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
    for method in ["GET", "PUT", "PATCH", "DELETE", "HEAD"] {
        assert!(
            wp.analyze(login_request("", method, "pwd=literal"))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
    assert!(
        wp.analyze(login_request(
            "action=logout",
            "POST",
            "pwd=literal&action=login"
        ))
        .await
        .unwrap()
        .confirmed_fields
        .is_empty()
    );
    let mut input = login_request("", "POST", "{\"pwd\":\"literal\"}");
    input.content_type = "application/json";
    assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
    // GP excludes cookies; non-REST method hints do not change wp_signon POST.
    let headers = vec![
        ("Cookie".into(), "action=logout".into()),
        ("X-HTTP-Method-Override".into(), "DELETE".into()),
    ];
    let mut input = login_request("_method=DELETE", "POST", "pwd=literal");
    input.headers = &headers;
    assert_eq!(wp.analyze(input).await.unwrap().confirmed_fields, ["pwd"]);
}

#[tokio::test]
async fn php_password_arrays_and_alias_collisions_are_denied_and_single_aliases_unconfirmed() {
    let wp = login_policy();
    for body in [
        "pwd[]=literal",
        "pwd=literal&pwd=other",
        "pwd=literal&%70wd=other",
        "pwd=literal&+pwd=other",
        "pwd=literal&pwd%00suffix=other",
        "pwd[child]=literal",
        "pwd=literal&pwd[]%00suffix=other",
    ] {
        assert_eq!(
            wp.analyze(login_request("", "POST", body))
                .await
                .unwrap_err()
                .0,
            "wordpress_ambiguous_login_password"
        );
    }
    for body in [
        "+pwd=literal",
        "pwd%00suffix=literal",
        "%2570wd=literal",
        "pwd.=literal",
    ] {
        assert!(
            wp.analyze(login_request("", "POST", body))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
}

#[test]
fn login_consumers_require_canonical_unique_paths_gp_and_evidence() {
    for consumers in [
        json!([{"path":"/member-entry/","request_order":"GP","evidence":"fixture"}]),
        json!([{"path":"/member-entry","request_order":"GPC","evidence":"fixture"}]),
        json!([{"path":"/member-entry","request_order":"GP","evidence":""}]),
        json!([{"path":"/member-entry","request_order":"GP","evidence":"fixture"},
            {"path":"/member-entry","request_order":"GP","evidence":"fixture"}]),
    ] {
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
                    settings: json!({"schema_version":1,"login_consumers":consumers}),
                },
            ),
        ]);
        assert!(Wordpress::from_modules(&modules).is_err());
    }
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
    for query in [
        "%5Fmethod=DELETE",
        ".method=DELETE",
        "+_method=DELETE",
        "_method%00suffix=DELETE",
    ] {
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
        "rest_route=/x&rest_route%00suffix=/y",
        "_method=GET&_method%00suffix=DELETE",
        "_method[]%00suffix=DELETE",
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
async fn php_nul_name_aliases_resolve_query_and_post_dispatch_before_method_checks() {
    let wp = policy();
    let context = wp
        .analyze(request(
            "/index.php",
            "rest_route%00suffix=/shop/v1/cart/items/42",
            "PUT",
        ))
        .await
        .unwrap();
    assert_eq!(
        context.rest_route.as_deref(),
        Some("/shop/v1/cart/items/42")
    );
    assert_eq!(wp.check(&context, false).unwrap().status, 405);
    let context = wp
        .analyze(request(
            "/wp-admin/admin-ajax.php",
            "action%00suffix=fixture_lookup",
            "POST",
        ))
        .await
        .unwrap();
    assert_eq!(context.action.as_deref(), Some("fixture_lookup"));
    for body in [
        b"rest_route%00suffix=/shop/v1/cart/items/42".as_slice(),
        b"rest_route%00[ignored]=/shop/v1/cart/items/42".as_slice(),
    ] {
        let mut input = request("/index.php", "", "POST");
        input.content_type = "application/x-www-form-urlencoded";
        input.body = bytes::Bytes::copy_from_slice(body);
        let context = wp.analyze(input).await.unwrap();
        assert_eq!(
            context.rest_route.as_deref(),
            Some("/shop/v1/cart/items/42")
        );
    }
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
