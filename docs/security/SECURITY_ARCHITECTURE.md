<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:b3dfc601def99b124dffeb225300372aa7b001b0ab6998bbff60a0db24ffa1dd -->

# Security boundaries — current checkpoint

Authorization and ScopeEnforcer decide native scope/RoE. HttpPolicy rechecks inside the concurrency slot. Path matching includes bounded decode/canonical variants; deny globs are case-normalized. Context/Conductor propagate dry-run and active-fuzz restrictions. Dry-run guarded requests/processes fail before sending; unguarded version/installer paths still need end-to-end audit.

EgressController currently validates subprocess inputs but does not enforce every child-generated request. This remains a critical boundary gap. Optional firejail is not proof of per-request HTTP restrictions. DNS rebinding, port allowlists, proxy and override-header enforcement are unresolved. No execution profile should be treated as exempt from these requirements.

Alternate transport forwards request kwargs and transfers cookies through the caller's jar. Each curl request owns a fresh session, preventing ambient cross-identity cookies. This intentionally trades connection reuse for isolation; performance has not been benchmarked. Response redirects are handled by HttpPolicy; cross-origin credential/body forwarding still needs repair. Timeout retries are disabled for state-changing methods because server execution may have succeeded before the response was lost.

Plan decisions use conditional SQL updates. Execution claim checks ready state and prerequisite hash atomically; a running plan cannot be overwritten by preparation. Approval expiry, explicit plan version storage, crash recovery of running claims and complete lifecycle transitions remain incomplete. No database migration was introduced.

Plugin additions must reuse authorization, request mutation/comparison and encrypted evidence. Existing interface is described in qbh/brain/strategy.py. Only IDOR/JWT Brain strategy modules exist; knowledge entries are not implementations.

## Provider control plane and native fallback enforcement

Certificate transparency and advisory sources remain query services, distinct from assessment targets. Previously DeepEnum._crtsh and CVE/library intelligence sent raw aiohttp traffic. The provider facade now uses the same HttpPolicy transport, validated DNS connector, TLS verification and scan rate/concurrency state. Its compile-time grants are exact method/origin/path tuples for crt.sh, CISA KEV, EPSS, OSV, GitHub advisories and NVD. OSV POST is a read-only advisory query, not target state modification. Target permissions are never expanded; enterprise private-IP grants are not copied to provider scope. Target deny rules and scan lifecycle/rules remain effective. No target cookies, credentials, rotating identity or ambient proxy settings are inherited. Provider audit records omit query content and request headers.

This repairs a documented distinction: providers are not scanning targets, but that does not exempt their network traffic from enforcement. Redirect destinations require an independent endpoint grant. Responses are size bounded by HttpPolicy and JSON nesting is limited to 64. Truncated or invalid data does not become advisory evidence.

Fingerprint and OpenAPI's fallback paths now call Context.request, including when Guardian is absent. A context without a policy-bearing request path fails closed. The explicitly configured loopback race fixture also requires normal target authorization and obeys dry-run; merely setting --race-fixture no longer circumvents request restrictions. This intentionally removes the earlier unchecked fixture exception, as required by centralized enforcement, while preserving authorized fixture execution.

Verification: real loopback provider queries and crt.sh/OSV parsing, no credentials inherited, shared budgets, exact endpoint/method restrictions, redirects, private DNS exclusion despite target private grants, cancellation/dry-run, parent operation restrictions, truncation and nested JSON. Native fallback and race tests prove allowed traffic and zero subsequent requests after denial. No live public provider availability is asserted by these fixtures.


<!-- /coderabbit-ai-generated:v1 -->