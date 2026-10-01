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

fn form_settings() -> serde_json::Value {
    json!({"schema_version":1,"form_consumers":[{
        "id":"fixture.message","path":"/wp-admin/admin-ajax.php","action":"fixture_submit",
        "request_order":"GP","arg_separator":"&","max_input_vars":1000,"max_input_nesting_level":64,
        "form_field":"form[fields][1]","guards":[{"field":"form[id]","equals":"17"}],
        "evidence":"fictional-required-textarea-handler-and-schema"}]})
}
fn form_request(body: &str) -> Request<'_> {
    let mut input = request("/wp-admin/admin-ajax.php", "", "POST");
    input.content_type = "application/x-www-form-urlencoded";
    input.body = Bytes::copy_from_slice(body.as_bytes());
    input
}

#[tokio::test]
async fn ajax_form_consumer_confirms_only_original_qualified_leaf_without_values() {
    let wp = wordpress(form_settings());
    for body in [
        "action=fixture_submit&form[id]=17&form[fields][1]=literal",
        "%61ction=fixture_submit&%66orm%5Bid%5D=%31%37&form%5Bfields%5D%5B1%5D=literal",
        "form[fields][1]=literal&form[id]=17&action=fixture_submit",
        "action=fixture_submit&form[id]=17&form[fields][1]=literal&form[fields][2]=sibling",
        "action=fixture_submit&form[id]=17&form[fields][1]=literal&form[fields][01]=sibling",
        "action=fixture_submit&form[id]=17&form[fields][1]=literal%26form%5Bfields%5D%5B2%5D%3Dvalue",
    ] {
        let context = wp.analyze(form_request(body)).await.unwrap();
        assert_eq!(context.confirmed_fields, ["form[fields][1]"], "{body}");
        assert_eq!(context.family, "ajax");
        assert_eq!(context.consumer_profile.as_deref(), Some("fictional-site"));
        let record = serde_json::to_string(&context).unwrap();
        assert!(!record.contains("literal") && !record.contains("form[fields]"));
    }
    let default = wordpress(json!({"schema_version":1}));
    assert!(
        default
            .analyze(form_request(
                "action=fixture_submit&form[id]=17&form[fields][1]=literal"
            ))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
}

#[tokio::test]
async fn ajax_form_consumer_withholds_alias_tree_and_identity_ambiguity() {
    let wp = wordpress(form_settings());
    let prefix = "action=fixture_submit&form[id]=17&form[fields][1]=literal";
    for suffix in [
        "&form[fields][1]=second",
        "&%66orm[fields][1]=second",
        "&form[fields][1]",
        "&form=scalar",
        "&form[fields]=scalar",
        "&form[fields][1][child]=scalar",
        "&form[fields][1][]=scalar",
        "&form[fields][]=scalar",
        "&form[fields][1]ignored=scalar",
        "&+form[fields][1]=second",
        "&form%00tail[fields][1]=second",
        "&form[fields][1%00tail]=second",
        "&form[id]=18",
        "&form[id][child]=18",
        "&form[id]ignored=18",
        "&other[]=unsupported",
        "&unclosed[key=unsupported",
    ] {
        let context = wp
            .analyze(form_request(&format!("{prefix}{suffix}")))
            .await
            .unwrap();
        assert!(context.confirmed_fields.is_empty(), "{suffix}");
    }
    for body in [
        "action=other&form[id]=17&form[fields][1]=literal",
        "action=fixture_submit&form[id]=18&form[fields][1]=literal",
        "action=fixture_submit&form[id]=17tail&form[fields][1]=literal",
        "action=fixture_submit&form[fields][1]=literal",
        "action=fixture_submit&form[id]=17&form[fields][01]=literal",
        "action=fixture_submit&form[id]=17&form[fields][1]",
        "action=fixture_submit&form[id]=17&%2566orm[fields][1]=literal",
        "action=fixture_submit&form[id]=17&+form[fields][1]=literal",
        "action=fixture_submit&form[id]=17&form[fields][1]ignored=literal",
        "form[fields][1]=literal&form=scalar&action=fixture_submit&form[id]=17",
    ] {
        assert!(
            wp.analyze(form_request(body))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty(),
            "{body}"
        );
    }
}

#[tokio::test]
async fn ajax_form_consumer_cannot_borrow_other_dispatch_methods_media_or_query_action() {
    let wp = wordpress(form_settings());
    let body = "action=fixture_submit&form[id]=17&form[fields][1]=literal";
    for method in ["GET", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"] {
        let mut input = form_request(body);
        input.wire_method = method;
        assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
    }
    for media in ["application/json", "text/plain", "application/octet-stream"] {
        let mut input = form_request(body);
        input.content_type = media;
        assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
    }
    for path in [
        "/index.php",
        "/wp-admin/admin-post.php",
        "/wp-admin/admin-ajax.php/alternate",
        "/wp-json/fixture/v1/submit",
    ] {
        let mut input = form_request(body);
        input.path = path;
        assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
    }
    for query in [
        "action=fixture_submit",
        "action=other",
        "%61ction=fixture_submit",
    ] {
        let mut input = form_request(body);
        input.query = query;
        assert!(wp.analyze(input).await.unwrap().confirmed_fields.is_empty());
    }
    // Method hints do not change the actual AJAX POST dispatch in WordPress.
    let mut input = form_request(body);
    input.query = "_method=DELETE";
    let context = wp.analyze(input).await.unwrap();
    assert_eq!(context.effective_method, "POST");
    assert_eq!(context.confirmed_fields, ["form[fields][1]"]);
}

#[tokio::test]
async fn ajax_form_consumer_respects_php_input_count_and_nesting_contract() {
    let mut settings = form_settings();
    settings["form_consumers"][0]["max_input_vars"] = json!(3);
    settings["form_consumers"][0]["max_input_nesting_level"] = json!(2);
    let wp = wordpress(settings);
    let body = "action=fixture_submit&form[id]=17&form[fields][1]=literal";
    assert_eq!(
        wp.analyze(form_request(body))
            .await
            .unwrap()
            .confirmed_fields,
        ["form[fields][1]"]
    );
    for extra in ["&other=value", "&other[a][b][c]=value"] {
        assert!(
            wp.analyze(form_request(&format!("{body}{extra}")))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
    let wp = wordpress(form_settings());
    let long_key = format!("{body}&{}=unclassified", "a".repeat(193));
    assert!(
        wp.analyze(form_request(&long_key))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
}

#[test]
fn ajax_form_consumer_invalid_contracts_fail_startup() {
    let rejects = |settings: serde_json::Value| {
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
        assert!(Wordpress::from_modules(&modules).is_err());
    };
    for (key, value) in [
        ("request_order", json!("GPC")),
        ("arg_separator", json!("&;")),
        ("max_input_vars", json!(0)),
        ("max_input_vars", json!(10001)),
        ("max_input_nesting_level", json!(1)),
        ("max_input_nesting_level", json!(65)),
        ("path", json!("/other.php")),
        ("action", json!("")),
        ("evidence", json!(" ")),
        ("form_field", json!("action")),
        ("form_field", json!("form[]")),
        ("guards", json!([])),
        ("guards", json!([{"field":"form","equals":"17"}])),
        (
            "guards",
            json!([{"field":"action","equals":"fixture_submit"}]),
        ),
        (
            "guards",
            json!([{"field":"form[id]","equals":"17"},{"field":"form[id]","equals":"17"}]),
        ),
        ("guards", json!([{"field":"form[id]","equals":"17.0"}])),
        ("unknown", json!(true)),
    ] {
        let mut settings = form_settings();
        settings["form_consumers"][0][key] = value;
        rejects(settings);
    }
    let mut duplicate = form_settings();
    let consumer = duplicate["form_consumers"][0].clone();
    duplicate["form_consumers"]
        .as_array_mut()
        .unwrap()
        .push(consumer);
    rejects(duplicate);
}

fn multipart_settings() -> serde_json::Value {
    let mut settings = form_settings();
    settings["form_consumers"][0]["media_types"] =
        json!(["application/x-www-form-urlencoded", "multipart/form-data"]);
    settings
}
fn multipart_request(parts: &[(&str, Option<&str>, &[u8])]) -> Request<'static> {
    let mut input = request("/wp-admin/admin-ajax.php", "", "POST");
    input.content_type = "multipart/form-data; boundary=fixture-multipart";
    let mut body = Vec::new();
    for (name, file, value) in parts {
        body.extend_from_slice(
            format!("--fixture-multipart\r\nContent-Disposition: form-data; name=\"{name}\"")
                .as_bytes(),
        );
        if let Some(file) = file {
            body.extend_from_slice(format!("; filename=\"{file}\"").as_bytes());
        }
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--fixture-multipart--\r\n");
    input.body = Bytes::from(body);
    input
}
#[tokio::test]
async fn multipart_ajax_consumer_requires_explicit_media_and_literal_post_identity() {
    let parts = [
        ("action", None, b"fixture_submit".as_slice()),
        ("form[id]", None, b"17".as_slice()),
        ("form[fields][1]", None, b"literal".as_slice()),
    ];
    let default = wordpress(form_settings());
    assert!(
        default
            .analyze(multipart_request(&parts))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    let wp = wordpress(multipart_settings());
    let context = wp.analyze(multipart_request(&parts)).await.unwrap();
    assert_eq!(context.confirmed_fields, ["form[fields][1]"]);
    assert_eq!(context.consumer_profile.as_deref(), Some("fictional-site"));
    assert!(!serde_json::to_string(&context).unwrap().contains("literal"));
    for header in [
        "multipart/form-data; boundary=fixture-multipart; charset=utf-8",
        "multipart/form-data; boundary=fixture-multipart; boundary=fixture-multipart",
    ] {
        let mut ambiguous = multipart_request(&parts);
        ambiguous.content_type = header;
        assert!(
            wp.analyze(ambiguous)
                .await
                .unwrap()
                .confirmed_fields
                .is_empty()
        );
    }
    let mut changed = parts;
    changed[1].2 = b"%31%37";
    assert!(
        wp.analyze(multipart_request(&changed))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    changed = parts;
    changed[2].0 = "%66orm[fields][1]";
    assert!(
        wp.analyze(multipart_request(&changed))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    let mut settings = multipart_settings();
    settings["form_consumers"][0]["media_types"] = json!(["multipart/form-data"]);
    assert!(
        wordpress(settings)
            .analyze(form_request(
                "action=fixture_submit&form[id]=17&form[fields][1]=literal"
            ))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
}
#[tokio::test]
async fn multipart_ajax_files_tree_collisions_and_unsupported_headers_withhold_bindings() {
    let wp = wordpress(multipart_settings());
    let base = [
        ("action", None, b"fixture_submit".as_slice()),
        ("form[id]", None, b"17".as_slice()),
        ("form[fields][1]", None, b"literal".as_slice()),
    ];
    let mut file = base;
    file[2].1 = Some("file.txt");
    assert!(
        wp.analyze(multipart_request(&file))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    file = base;
    file[1].1 = Some("guard.txt");
    assert!(
        wp.analyze(multipart_request(&file))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    file = base;
    file[0].1 = Some("action.txt");
    assert!(
        wp.analyze(multipart_request(&file))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    for name in [
        "form",
        "form[fields]",
        "form[fields][1]",
        "form[fields][1][child]",
        "form[fields][1]ignored",
        " form[fields][1]",
        "form[fields][]",
        "form[id]",
    ] {
        let mut parts = base.to_vec();
        parts.push((name, None, b"other"));
        assert!(
            wp.analyze(multipart_request(&parts))
                .await
                .unwrap()
                .confirmed_fields
                .is_empty(),
            "{name}"
        );
    }
    let mut parts = base.to_vec();
    parts.push(("upload", Some("file.bin"), b"\xff"));
    assert_eq!(
        wp.analyze(multipart_request(&parts))
            .await
            .unwrap()
            .confirmed_fields,
        ["form[fields][1]"]
    );
    let mut unsupported = multipart_request(&base);
    unsupported.body = Bytes::from(
        String::from_utf8(unsupported.body.to_vec())
            .unwrap()
            .replace("\r\n\r\n", "\r\nX-Fixture: unsupported\r\n\r\n"),
    );
    assert!(
        wp.analyze(unsupported)
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    let mut binary = base;
    binary[2].2 = b"\xffliteral";
    assert!(
        wp.analyze(multipart_request(&binary))
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    let mut method = multipart_request(&base);
    method.wire_method = "PUT";
    assert!(
        wp.analyze(method)
            .await
            .unwrap()
            .confirmed_fields
            .is_empty()
    );
    let mut query = multipart_request(&base);
    query.query = "action=fixture_submit";
    assert!(wp.analyze(query).await.unwrap().confirmed_fields.is_empty());
}
#[test]
fn multipart_media_contract_is_bounded_explicit_and_fingerprinted() {
    use waf_core::profile::{Layer, Profile, SourcedModule, compose};
    let parse = |settings: serde_json::Value| {
        Wordpress::from_modules(&BTreeMap::from([
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
        ]))
    };
    for media in [
        json!([]),
        json!(["application/json"]),
        json!(["MULTIPART/FORM-DATA"]),
        json!(["multipart/form-data", "multipart/form-data"]),
        json!([
            "multipart/form-data",
            "application/x-www-form-urlencoded",
            "text/plain"
        ]),
    ] {
        let mut settings = form_settings();
        settings["form_consumers"][0]["media_types"] = media;
        assert!(parse(settings).is_err());
    }
    let mut profiles = [
        include_bytes!("../../../profiles/core/base.json").as_slice(),
        include_bytes!("../../../profiles/wordpress/base.json").as_slice(),
        include_bytes!("../../../profiles/sites/example.json").as_slice(),
    ]
    .into_iter()
    .map(|data| Profile::parse(data).unwrap())
    .collect::<Vec<_>>();
    profiles[2].modules.push(waf_core::profile::ModuleSpec {
        name: "wordpress-site".into(),
        settings: form_settings(),
    });
    let first = compose(profiles.clone(), "example-site").unwrap();
    profiles[2].modules.last_mut().unwrap().settings = multipart_settings();
    assert_ne!(
        first.fingerprint,
        compose(profiles, "example-site").unwrap().fingerprint
    );
}
