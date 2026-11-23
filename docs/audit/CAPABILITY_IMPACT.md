<!-- coderabbit-ai-generated:v1 -->

# Capability impact audit

Baseline comparison: 27ddd80 (before hardening), 336f21b (transport/session repairs), d4d7b96 and 2758c9a (network hardening). Current branch feature/security-hardening-capability-expansion, clean at inspection. No knowledge-base directory or AGENTS.md found. Inventory reviewed: native HttpPolicy/Guardian/Context/ScanSession, ScopeEnforcer/Authorization/Config, EgressController/adapters, Conductor/CLI, installer registry and engine subprocess call sites. This is a boundary audit, not a claim every historical detector is fully implemented.

| Component | Previous capability | Current behavior | Security reason | Functional impact | Required action |
|---|---|---|---|---|---|
| DNS | OS resolution/connection pooling | Any denied answer rejects entire set | Rebinding protection | Mixed DNS loses usable addresses | Filter each candidate; consume exact validated records |
| Private IP | Explicit IP/CIDR scope | Still explicit grants; hostname alone insufficient | Private SSRF protection | Existing schema supports enterprise grants but documentation calls them lab-only | Document enterprise schema and test IPv4/IPv6/mixed grants |
| IPv6 | Literal and CIDR | Canonical strings; zones rejected | Ambiguous interfaces | Mapped IPv6 denial must cover both representations | Test mapped/CIDR deny precedence |
| Redirects | Scoped cross-origin allowed, credentials could leak | All cross-origin denied | Credential leakage | Legitimate SSO/API redirects blocked | Permit scoped read redirects with isolated headers/cookies; reject credential-bearing replay |
| Proxies | Explicit/environment proxies | All proxies rejected | Remote resolution bypass | Corporate gateways unavailable | Evaluate pinned HTTP/SOCKS tunnel adapters; retain explicit failure where final destination not enforced |
| Subprocess | Scoped command preflight with optional sandbox | All scan children blocked | Child-generated requests uncontrolled | Nuclei/sqlmap/dalfox/recon integrations unavailable | Per-tool mediation/isolation assessment; do not re-enable unrestricted traffic |
| Authentication | Caller-owned sessions | curl per-request session with caller cookies | Cross-user contamination | Cookie/Bearer flows tested; cross-origin login blocked | Restore safe redirect flows, preserve identity isolation |
| Pooling | Scan session reuse | DNS origin requests force-close | Pinning implementation shortcut | Extra TCP/TLS handshakes | Per-caller policy-owned pooled connector with policy-change invalidation |
| API testing | Custom methods/override headers | Override headers denied categorically | Method/path policy bypass | Legitimate override testing unavailable | Authorize both wire and effective methods/path |
| Native vulnerability engines | Guardian native requests | Native SQLi/XSS/SSTI/SSRF paths retained | Shared policy | Test coverage does not establish all detection quality | Preserve native fixtures and benchmark |
| Exploit validation | External tools plus native tests | External proof tools blocked | Uncontrolled egress/operations | Deep validation degraded | Document exact tool capability gaps, prohibited operations independent of target rules |
| Internal infrastructure | CIDR scope and external discovery tools | CIDR native HTTP works, discovery CLI blocked | Same subprocess gap | No verified general port/service scanner | Do not label blocked discovery supported |
| Dry-run | Installer-only semantics | Offline CLI plan | Zero side effects | Does not execute installer detection | Preserve no DNS/network/process behavior |
| Safety | Destructive/DoS names denied | Other prohibited category names missing | Incomplete policy vocabulary | Persistence/brute-force/resource-exhaustion names not immutable | Add permanent operation deny set |

External registry includes subfinder/httpx/katana/dnsx/naabu/nuclei/ffuf/alterx/gau/jsluice/x8/arjun/schemathesis/feroxbuster/amass/nmap/sqlmap/ghauri/dalfox/sstimap/jwt_tool/semgrep/git-dumper/kr/bbot/waymore/gowitness/dnstwist/interactsh-server. Some are offline analyzers, some raw TCP/DNS clients, some browser/HTTP scanners. HTTP proxy environment variables cannot constrain raw sockets or HTTPS methods/paths. A shared IP firewall alone cannot satisfy path/method authorization. Offline tools need enforced no-network execution; network tools need mandatory mediation and tool-specific prohibited-operation constraints. These adapters are not presently implemented; support must not be claimed.
