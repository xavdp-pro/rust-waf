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

## Explicit AJAX form consumers

Optional site `form_consumers` entries confirm a canonical content leaf only for an explicitly declared AJAX POST handler and scalar identity guards. No plugin or installed form is enabled by default. This fictional declaration requires separate actual handler/schema evidence:

```json
{
  "id": "example.message",
  "path": "/wp-admin/admin-ajax.php",
  "action": "example_submit",
  "request_order": "GP",
  "arg_separator": "&",
  "max_input_vars": 1000,
  "max_input_nesting_level": 64,
  "form_field": "form[fields][1]",
  "media_types": ["application/x-www-form-urlencoded"],
  "guards": [{"field": "form[id]", "equals": "17"}],
  "evidence": "fictional-required-textarea-handler-and-schema"
}
```

Place entries in the site module alongside login_consumers/method_rules. At most 32 declarations, eight identity guards per declaration, 64-byte/eight-segment field paths and bounded PHP input settings are accepted. IDs are unique; guards may not overlap each other, the selected leaf or action. Guard constants are nonsecret stable identifiers of at most 256 ASCII alphanumeric/underscore/hyphen bytes, never authentication tokens. Paths must match the configured installation's canonical admin-ajax endpoint. The deployer must verify actual **FPM** request order, input separator, variable/nesting limits, handler, form schema, field consumption and authorization; CLI defaults alone do not establish worker behavior. These assumptions and their file/configuration identities require requalification after drift.

Media defaults to URL-encoded only. A declaration may explicitly add multipart/form-data; other, duplicate or empty media lists are rejected. Multipart requires an unambiguous boundary and the strict borrowed physical layout described in [the origin contract](../../docs/form-field-origins.md). Uploaded files cannot select POST action, identity guards or content leaves. Guard values are literal UTF-8 for multipart, while URL-encoded names and values are decoded once. Unsupported framing, headers or content-type parameters withhold confirmation.

Confirmation requires wire POST, declared media, the exact original POST action and every guard, one assigned canonical selected leaf and no query-selected action. Original URL-encoded names are decoded once; MIME names remain literal. Duplicate selected/guard bindings, ancestor/descendant writes, oversized names, unsupported noncanonical keys and input count/depth beyond the declared limits withhold confirmation. Noncanonical keys include PHP aliases, NUL names, append arrays, ignored suffixes and malformed brackets, even on unrelated fields. This strict canonical-tree checkpoint can therefore withhold an exception on otherwise legitimate forms using unsupported array shapes; qualification must surface that limitation and further parser support must precede enabling such flows. Canonical disjoint siblings and leading-zero string indices remain distinct. Context/decision serialization omits content values and field selectors; confirmation retains the site profile identity.

The adapter does not validate application nonces, tokens, honeypots, timing, roles or ownership, and never claims that a complete application submission is authorized. WordPress retains those checks. A separate scoped site `form_field` exception is still required. Complete raw/decoded scanning, other fields, query/headers, dispatch/access checks, resource bounds and unchanged-byte forwarding remain in force. JSON, alternative handlers and additional plugin workflow qualification remain outstanding. Multipart source support does not qualify an actual installation.

## Evidence and limitations

Run `cargo test -p waf-wordpress --locked` for twenty-one semantic tests and `cargo test -p waf-proxy --locked` for actual HTTP decisions/correlated neutral-backend checks. Five new semantic cases cover explicit/absent consumers, decoded fields/identifiers, collisions, methods/media/dispatch, parser bounds and startup rejection. Two new protocol groups prove unchanged allowed bytes, correlated pre-backend negative denials and unapplied sibling-hit diagnostics. These do not qualify browser workflows, plugin-modified dispatch, PHP execution or artifact-specific resources. Broader content-field formats, nonce/role integration, plugin modules and deployment remain pending. Requalify site behavior after plugin/theme/core changes.

The semantics are based on primary [WordPress REST dispatch](https://developer.wordpress.org/reference/classes/wp_rest_server/serve_request/), [route loading](https://developer.wordpress.org/reference/functions/rest_api_loaded/) and [PHP form parsing](https://www.php.net/manual/en/function.parse-str.php). This is original Rust code; no WordPress PHP source was copied into this public crate.

## Scoped input constraints

Optional site `input_constraints` reject a selected scalar input without exempting a route, body, sibling field or core rule. No constraint is enabled by default. A fictional declaration is:

```json
{
  "id": "example.return-input",
  "path": "/wp-admin/admin-ajax.php",
  "actions": ["example_draft"],
  "methods": ["GET", "POST"],
  "request_order": "GP",
  "arg_separator": "&",
  "max_input_vars": 1000,
  "sources": [
    {"kind": "request_parameter", "name": "return_url"},
    {"kind": "header", "name": "Referer"},
    {"kind": "request_target"}
  ],
  "projection": "before_query",
  "reject_pattern": "FORBIDDEN",
  "evidence": "fictional-installed-scalar-consumer"
}
```

The exact canonical path and explicit **wire** methods delimit the consumer. Nonempty actions are supported only on the configured installation's canonical admin-ajax/admin-post endpoints, where the adapter resolves PHP action dispatch. An empty actions list applies to every action on that exact path; it is an explicit policy scope, not inferred plugin behavior. At most 32 constraints, 32 unique actions, four unique ordered sources and bounded nonempty patterns/evidence are accepted. Rule IDs share the existing method/consumer uniqueness namespace. Settings/provenance contribute to the effective fingerprint.

Optional `path_match` is `exact` by default. Explicit `prefix` matches a canonical path itself and descendants at a slash boundary; `/articles` never matches `/articles-other`. `/` covers the configured root installation. Prefix scopes must stay within the installation base and use an empty actions list; action resolution remains restricted to exact standard dispatcher endpoints. Paths remain canonical without a trailing slash except `/`.

Optional `when_parameter_present` applies the input predicate only if a declared normalized parameter name occurs in query bindings or form POST. This is a presence union, not PHP scalar fallback or plugin action-value resolution: empty/zero values, duplicate bindings, bracket-prefix bindings (including malformed array suffixes) and PHP name aliases count as present. This is a conservative syntactic trigger, not complete PHP array emulation. JSON and non-POST bodies do not populate form POST; uploaded files do not count. Names/counts and multipart physical/Multer agreement are still validated, while presence does not decode or retain parameter values. The existing scalar source contract remains strict and independent. These options never exempt core inspection, authentication, methods, siblings or complete-body validation, and infer no ban confidence. Site authors must qualify their actual dispatch/consumer semantics before using them; a prefix/presence declaration alone does not establish plugin protection.

`request_parameter` resolves one scalar using declared PHP GP order: POST first, otherwise GET. Only wire POST URL-encoded or multipart forms populate POST; JSON and other methods do not. Splitting precedes one URL decoding pass for form/query names and selected values. MIME names/values are literal. PHP leading-space/dot normalization is considered; duplicate selected aliases, arrays, decoded-name NUL ambiguity, non-UTF-8 selected values and NUL values are rejected. Each relevant source parser checks the declared variable count, including unrelated pairs; over-limit input is rejected instead of guessing which binding FPM retained. Decoded selected values are limited to 8192 UTF-8 bytes. Encoded form/query value representations are independently capped at 24576 wire bytes before decoding/allocation, then the decoded bound is enforced; literal MIME values, headers and targets retain the 8192-byte bound. This preserves the same selected-scalar budget across percent-encoded and literal media. Uploaded files never become POST values. Multipart requires strict physical layout and independent Multer agreement; unsupported metadata/framing denies the scoped input rather than guessing a fallback.

The ordered sources use PHP scalar truthiness (`""` and `"0"` are falsey). A present **POST** binding prevents interpreting the corresponding GET binding at all, including when POST is falsey; the next source is then chosen. A selected header is case-insensitive and must be unique; ambiguous later headers are irrelevant when an earlier source was selected. `request_target` is the original path plus literal query, must be last, and adds no hostname. `raw` inspects that selected value unchanged; `before_query` takes its literal prefix before the first question mark. Neither projection percent-decodes headers/targets, strips fragments, normalizes URL paths or emulates application URL hooks. The site must qualify its actual selected source and every later helper/filter before deriving a protection pattern.

Matches produce a pre-backend 403 with reason `wordpress_input_constraint`, policy/profile identity and no input values. Application access/method checks and complete core inspection of forwarded requests remain active; trusted access does not bypass a constraint. Parser ambiguities return 400. This is an explicit application input policy, not an automatically reliable attack classifier: these denials do not start bans, and existing ban/observe contracts are unchanged. Native authentication, nonces, roles and ownership remain mandatory in WordPress.

Five semantic tests and a neutral HTTP group exercise scalar scope, GP/falsey selection, source isolation, selected/header ambiguity, media/file handling, bounds/startup rejection, original-byte forwarding and correlated non-forwarding. A valid constraint cannot suppress an unrelated core match. Actual PHP/helper behavior, plugin virtual patches, artifact resources, Browser, independent effectiveness and matching performance remain separate qualification gates. GP and ampersand declarations are verified deployment prerequisites; other orders/separators fail startup. Unknown multipart binding is a request-wide fail-closed 400, because treating a potentially consumed POST field as absent would invent an unsafe fallback. Overlapping constraints intersect for forwarding; only the first denying policy is reported.


## Optional bounded input projection stages

A scoped input constraint and each source may declare optional `stages` arrays. Defaults are empty and preserve existing behavior. Selection uses the original value's PHP truthiness first. Only the selected source's stages run, followed by constraint stages, then the existing `projection` and rejection pattern. A truthy selected source transformed to an empty string does not restart fallback selection. Stages transform only a private inspection copy; the original HTTP bytes and complete core inspection remain unchanged.

Supported explicit stages:

- `replace`: a bounded Rust regular expression `pattern` and `replacement`. Global nonoverlapping matches, including empty-position matches, are replaced. Replacement capture syntax is only `${N}` (including `${0}`); unmatched optional groups contribute empty text, unknown groups and other dollar syntax fail startup. Ordinary dollar characters have no escape syntax in this version. Pattern bytes are capped at 2048, compiled program and DFA cache at 64 KiB each; replacement bytes at 1024 and tokens at 32. Optional `preserve_prefix_pattern` restricts replacement to the suffix after the first match starting at byte zero; the preserved prefix remains in the projected value and its size budget. Optional `skip_pattern` uses the same pattern bounds and matches the current full stage value before replacement. A matching condition skips only this replacement; omitted/null conditions leave replacement unconditional. Regex search semantics apply: use anchors when whole-value or prefix matching is intended.
- `remove_sequences`: recursively remove exact case-sensitive `sequences` until none remain. One to eight distinct words of the same 2–64 byte length are accepted; NUL and any nonempty prefix/suffix overlap (including self-overlap) fail startup. These restrictions make deletion order unambiguous. A streaming UTF-8 stack consumes each input character and removes matching suffixes; every removal shrinks the stack. Work is bounded by the 8192-byte input and the small declared word set, without a recursion-depth cutoff or intermediate expansion. An optional `skip_pattern` is evaluated once against the current complete stage input. A match preserves that input for this stage only; later stages, the constraint predicate, original-byte forwarding and complete core inspection still apply. Omitted/null means unconditional removal. Nonempty pattern bytes and compiled program/cache use the same 2048-byte/64-KiB bounds as `replace`; invalid patterns fail startup. Existing stage/value/privacy bounds remain active. This is an opt-in literal transformation, not a generic sanitizer or implicit URL decoding.
- `translate`: longest-key, one-pass literal mappings with no replacement rescanning; see the exact table/UTF-8/value bounds below.
- `trim`: remove the declared `characters` from both ends. The nonempty character set is at most 64 UTF-8 bytes.
- `before_query`: take the literal prefix before the first `?` at this point in the pipeline.
- `form_encode_segments`: split on literal `/`, preserving separators and empty segments. Encode each UTF-8 segment's bytes using form encoding (ASCII alphanumeric and `-_.` retained, space becomes `+`, other bytes become uppercase percent escapes). A bounded `skip_pattern` matches segments that stay unencoded. Required boolean `skip_if_decoding_changes` also preserves a segment containing `+` or a valid `%HH` escape. Required boolean `lowercase_when_escaped` lowercases ASCII in the resulting segment only when it contains such a form escape, including a skipped segment. Invalid escapes alone do not trigger the decoding-change condition. This is a declared transform, not a URL sanitizer or implicit percent-decoding.
- `empty_fallback`: replace only an empty intermediate value with the nonempty declared `value` (at most 256 bytes). Literal `0` is not empty.

All stages across the constraint and **all** its sources share a maximum of sixteen. Every intermediate result is capped at 8192 UTF-8 bytes; capture replacement appends are checked individually before allocation, and expansion fails with a request error rather than truncating or reverting to the original input. NUL literals in replacement, trim and fallback settings are rejected. Invalid stage kinds/settings, patterns and capture references fail startup. Unknown settings are rejected even on parameterless stages.

For example, this fictional source strips a transport prefix before a shared query projection:

```json
{
  "kind": "request_parameter",
  "name": "return_url",
  "stages": [{"kind": "replace", "pattern": "^item:", "replacement": ""}]
}
```

These are generic declarative primitives. No plugin, route, site prefix, filter, sanitizer or known vulnerability is automatically modeled. Deployers must verify transformation ordering, source-dependent behavior, hook effects, legitimate workflows and the actual sink before activating a policy. Configuration participates in existing versioned fingerprints; projected values remain absent from context/decision serialization. The capability grants no reliable ban confidence. Site policy, actual PHP equivalence, artifact-specific resources, deployment/rollback, Browser and final acceptance remain separate gates.

The optional `replace.skip_pattern` uses the same nonempty, at-most-2048-byte pattern and 64-KiB regex program/cache bounds as other projection patterns. It matches the complete current stage input once, before replacement. A match skips only that replacement; later stages and the selected-input predicate still apply, as do complete core inspection and original HTTP forwarding. Omitted/null conditions preserve unconditional replacement. The replacement pattern and capture template are validated even for an always-skipped stage; value/NUL and total-stage bounds are unchanged. Conditions are explicit policy data, not automatic trusted exceptions.

Optional `replace.preserve_prefix_pattern` uses the same bounded regex compiler. The first match preserves a prefix only when its start is byte zero; a missing or later-start match preserves no prefix. Replacement runs globally on the remaining suffix: its anchors/captures are relative to that suffix, and empty suffixes can still have zero-width replacements. The complete prefix stays in the projected value, counts toward the same 8192-byte output limit and remains visible to subsequent stages/predicates. `skip_pattern` is evaluated on the full current input before prefix selection. Omitted/null prefix settings retain whole-value replacement. This projection scope does not remove original HTTP bytes or grant a core-inspection exception.

## Optional parameter-value scope

An input constraint may select retained parameter values instead of syntactic root presence:

```json
"when_parameter_matches": {
  "name": "command_name",
  "binding": "php83_form_query_union",
  "pattern": "(?i)^apply_changes$",
  "stages": [{"kind": "trim", "characters": " "}]
}
```

This guard is mutually exclusive with `when_parameter_present`. It only selects whether the declared input predicate applies; it does not grant an exception, rewrite HTTP, bypass core inspection, alter authentication or increase detection confidence. Omission preserves existing behavior. Pattern/stage contracts are compiled before serving requests.

The explicitly named binding models a bounded subset of 64-bit PHP 8.3 form/query binding. Within each source, scalar duplicates and repeated array keys use last-write resolution; scalar/one-level-array replacements discard the earlier shape. Empty array indices append after the greatest numeric index, including the PHP 8.3 negative-first case. Canonical signed decimal keys become integers; leading zeros, plus signs, negative zero and integer overflow remain text keys. Root aliases normalize leading spaces, dots and spaces; inner keys preserve their spelling. Values from query and form POST are a union, rather than scalar POST precedence. Matching asks whether any retained value, after its declared stages, matches the regex. Map iteration order is not a plugin hook execution order.

Only POST URL-encoded and qualified multipart non-file fields populate the form source. JSON, files and bodies on other methods do not. Names decode once; selected URL-encoded values decode once. All source bindings and all retained value stages are validated even after a match. Selected nested arrays, malformed bracket syntax and NUL names/values fail closed as unqualified. This is not a full PHP parser or automatic WordPress `sanitize_title` implementation. Application filter changes, normalization, route-derived values and actual dispatcher behavior require independent site qualification.

Bounds per source: 128 retained array entries, 65,536 retained key/value bytes, selected keys at most 512 bytes and values at most 8,192 decoded bytes (24,576 URL-encoded wire bytes). Numeric keys count eight bytes toward storage. The existing `max_input_vars` bounds encountered query/form pairs; multipart files do not count as form variables. Append overflow fails closed. The guard permits at most 16 bounded projection stages, separate from the selected-input stage budget. Names are 1–96 ASCII alphanumeric/underscore/hyphen bytes, patterns are 1–2,048 bytes, and regex compilation uses 64 KiB size/DFA bounds. An empty-string-matching regex can select a present empty value; absent parameters have no values to match.

### Bounded one-pass literal translation

The optional `translate` stage accepts explicit literal mappings:

```json
{"kind":"translate","mappings":[{"from":"é","to":"e"},{"from":"l·l","to":"ll"}]}
```

At each original input position, the longest matching key wins. Replacement text is emitted once and is not rescanned by this stage; subsequent stages can process it. Configuration order does not affect the result. UTF-8 unmatched characters are preserved. Overlapping keys are supported; duplicate or empty keys are rejected at startup. Empty replacements delete the matching key. No regex, implicit case folding, Unicode normalization, application table or sanitizer is built into this primitive.

Contracts allow 1–512 unique mappings, keys of 1–16 UTF-8 bytes, replacement strings of 0–16 bytes, at most 4,096 total key bytes and 8,192 total key/replacement bytes. NUL is forbidden. A compiled byte trie searches at most sixteen bytes per input position using sorted edges; matches end at valid UTF-8 key boundaries. Input/output remain at most 8,192 bytes. Expansion fails before appending beyond the cap rather than truncating. This stage uses one slot in the existing sixteen-stage budget and is available in both input predicates and parameter-value guards. Application character mappings and their native-equivalence evidence belong in separately maintained profiles.
