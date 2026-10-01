# Generic WordPress specialization

This crate implements WordPress dispatch semantics separately from `waf-core`. The application profile enables module `wordpress` with `{"schema_version":1}`. A site may add a distinct `wordpress-site` module with strict settings; module IDs cannot silently override one another. Module versions/settings/provenance contribute to the policy fingerprint. Unknown modules or malformed settings prevent proxy startup.

Site settings default to root installation, `wp-json` REST prefix, no extra PHP entry points and no method restrictions. An illustrative site module is:

```json
{
  "name": "wordpress-site",
  "settings": {
    "schema_version": 1,
    "base_path": "/",
    "rest_prefix": "wp-json",
    "rest_entry_paths": [],
    "method_rules": [
      {
        "id": "example.cart-item",
        "scope": "rest",
        "pattern": "^/shop/v1/cart/items/[0-9]+$",
        "methods": ["GET", "DELETE"],
        "evidence": "fictional-cart-workflow"
      }
    ]
  }
}
```

This is fictional, not a WooCommerce declaration or qualified installation policy. Method-rule scopes are `rest` (resolved REST route), `path` (canonical URL path) or `ajax` (action on admin-ajax). Rules require anchored bounded patterns, explicit methods and an evidence reference. All matching rules apply; overlaps intersect rather than silently override. Site rule denials retain site provenance. Unknown routes/actions remain unqualified and are not automatically forbidden.

## Dispatch behavior

REST identification handles the configured prefix, index.php path-info alternative, query-selected routes and POST form/multipart route selection. PHP key normalization is considered for dispatch parameters. Differing POST/query `rest_route` values are rejected as WordPress does. Duplicate/array dispatch parameters are rejected rather than allowing parser ambiguity. Uploaded files cannot become POST route strings; JSON/PUT bodies cannot populate PHP's $_POST. Custom PHP REST entry scripts must be declared by the site.

For REST, query `_method` wins over `X-HTTP-Method-Override`. The resulting method is uppercased and validated. Query splitting happens before decoding, once, so an encoded separator cannot create a parameter. Common-rule exceptions and method policies use this effective method while forwarding original bytes unchanged. REST HEAD may use a GET declaration; OPTIONS discovery is preserved. Wire-method overrides on non-REST routes are not assumed to change dispatch.

Administration paths require trusted ingress metadata in both proxy modes. Member login, admin-ajax and admin-post remain available for legitimate workflows and application authorization. The gateway does not infer user roles from client cookies or headers and does not validate WordPress nonces, account capabilities or object ownership. The backend must retain application authentication and deployer-side checks restricting administrative identities; trusted access does not grant an application role.

## Explicit login consumers

A site may declare login_consumers entries with a canonical path, request_order set explicitly to GP and an evidence reference. No consumer is enabled by default, including wp-login.php. The site analysis must verify the actual wp_signon handler/hooks, PHP request order and route mapping before declaring one. GP means POST action takes precedence and cookies cannot select it; conflicting action sources withhold confirmation.

On a declared consumer, the adapter confirms only a nonempty scalar POST form pwd when the resolved action is absent/login, no GET key/checkemail overrides exist and no query/form rest_route is present. Duplicate PHP-normalized pwd aliases and arrays are rejected on the login flow. Canonical or percent-encoded names decoding once to pwd can bind; single leading-space/NUL aliases stay unconfirmed because the shared scanner does not invent PHP normalization. JSON/multipart, other methods/actions and REST dispatch never borrow this confirmation. Non-REST method hints retain actual WordPress POST semantics. Confirmation retains the site profile identity, never the password or client-provided permission claims.

The gateway passes these confirmations to the shared origin-aware inspector after dispatch/access checks. A separate site form_field exception is still required; only that field's complete match hull can be excepted. Application authentication, staff restrictions, sibling/query/header inspection and parsing invariants remain required. This is an explicit consumer contract, not an automatic generic password exclusion. Actual site/browser/resource qualification remains deployer work.

## Evidence and limitations

Run `cargo test -p waf-wordpress --locked` for thirteen semantic tests and `cargo test -p waf-proxy --locked` for actual HTTP decisions/correlated neutral-backend checks. These do not qualify browser workflows, plugin-modified dispatch or PHP execution. Broader content-field bindings, nonce/role integration, plugin modules and deployment remain pending. Requalify site behavior after plugin/theme/core changes.

The semantics are based on primary [WordPress REST dispatch](https://developer.wordpress.org/reference/classes/wp_rest_server/serve_request/), [route loading](https://developer.wordpress.org/reference/functions/rest_api_loaded/) and [PHP form parsing](https://www.php.net/manual/en/function.parse-str.php). This is original Rust code; no WordPress PHP source was copied into this public crate.
