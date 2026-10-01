# Ingress adapters

cloudflare-tunnel: visitor identity is validated HTTP metadata from trusted ingress. The origin packet filter does not see that visitor source inside the tunnel. Plan local HTTP rejection after reliable detection, without per-attack API calls.

direct: a packet filter can reject an actual observed network source. An expiring nftables adapter may supplement request validation. Never feed a packet firewall from an untrusted header.

Deployers own their domains, networks, and friend IPs. Both modes retain application authentication and explicit exceptions. No private network is required by the shared engine.
