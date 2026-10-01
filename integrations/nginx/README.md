# Nginx integration

Use native static/transport features and an isolated internal HTTP-to-FastCGI bridge. Generate and correlate request identifiers at trusted ingress; do not trust arbitrary client identity headers.

Read-only static resources may accept GET/HEAD only. Do not apply that policy blindly to unqualified dynamic workflows. Administration is restricted to explicit friend IPs, while admin-ajax/admin-post can support member-facing workflows.

The local temporary-list adapter remains to be selected and implemented against the actual available modules, with bounded cost and measurements. No reload per request, no upstream API call per attack, and no backend bypass on failure.
