<!-- coderabbit-ai-generated:v1 -->

# Network policy remediation

## Implemented boundaries
Actual aiohttp requests validate scheme/host/path/method through Authorization, then validate options immediately inside the concurrency slot. Domain requests use a policy-owned connector with PolicyResolver: every DNS answer is checked, and those same address records feed the socket connector without a second DNS lookup. DNS caching is disabled on that connector. Non-public addresses require an explicit IP/CIDR scope entry; hostname authorization alone is insufficient. IPv4-mapped addresses are checked using their effective IPv4 address. Deny IP rules take precedence. Literal IP requests retain the caller connection pool after validation.

Default domain ports are 80/443. Configure `network_allowed_ports: [443, 8443]` to authorize additional domain ports; invalid/bool/out-of-range entries are errors. Explicitly scoped IPs are the laboratory opt-in and retain all ports for backward compatibility. Port isolation for a lab IP requires a dedicated target/network; do not use a broad CIDR scope for a lab. This exception is explicit, not a per-port laboratory ACL.

Proxy/proxy-auth options, ambient proxy sessions, mismatched Host and method/path override headers are rejected. curl ignores environment proxies. Domain traffic uses aiohttp because the current curl adapter does not provide equivalent DNS pinning; explicitly authorized literal IP curl traffic retains cookie/body isolation. DNS-over-HTTPS controlled independently by curl cannot occur for domain traffic through HttpPolicy. Domain connection pooling is sacrificed for connection-time policy ownership; literal IP pooling regression remains covered.

Cross-origin redirects are rejected, including same host with a different port or scheme, rather than forwarding auth/cookies/body. Same-origin redirects undergo authorization again and rate acquisition. A 303 discards JSON/form body when switching to GET. Broader redirect compatibility remains intentionally restricted.

## Subprocess containment and compatibility
EgressController no longer treats target preflight or optional firejail as proof of per-request HTTP enforcement. Every guarded scan subprocess is blocked with `per-request mediation unavailable`, including commands hiding their target in stdin, config files or code. Target preflight still records scope/DNS rejection reasons. No override flag permits unmediated scan children. This closes the launch route by containment; it does not implement a transparent HTTP mediation sandbox.

**Capability impact:** external scanner CLI integrations are unavailable in guarded scans until a mandatory per-request transport adapter is implemented. This intentionally departs from prior behavior where scoped commands were launched despite uncontrolled follow-up requests. The prior loopback-child-success test now asserts this new fail-closed contract. Existing out-of-scope/DNS tests retain their original denial assertions. Native engines remain operational. Installer operations explicitly requested outside a scan are separate provisioning actions, not proof of assessment egress control.

## Strict CLI dry-run
The CLI handles --dry-run before Conductor, authentication, resume, installer/version probes or OOB startup. It validates configuration and prints an offline stage/tool plan, then exits. Test instrumentation rejects DNS, aiohttp requests and child-process launch across full/recon/vuln/hunt/install. Existing Authorization request/process guards remain defense in depth. Dry-run no longer performs installer detection or executes an approved plan.

## Verification and scope of claims
New tests in test_network_boundary.py cover hidden-target subprocess launch, DNS rebinding simulations, private/mapped IPv6 addresses, port configuration, proxy/method overrides, CLI dry-run and cross-origin auth redirects. They initially failed before implementation. The first full modified suite exposed legacy child-admission, metrics and pooling regressions; target-rejection audit reasons, metrics and literal IP pooling were repaired. The one child-success expectation was migrated to the explicitly changed fail-closed contract, not claimed as preserved functionality.

These controls protect the repository's current guarded scan and HttpPolicy paths. They do not sandbox arbitrary third-party Python code or implement unrestricted external scanner support. Full OS-level mediation, exhaustive URL/parser equivalence, and explicit per-port lab-IP policy are not claimed. Other master-assignment phases remain open. <!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:729c97a64ca4396902d1ab501b5bae01c91f3c64ba24f1077808d3f760c424a0 -->

Final coverage run: **1320 passed, 1 skipped, 85.53%**, 73.65 seconds. Two subsequently added security tests also passed as part of the 20-case network suite. Full source checks passed (Ruff/compileall/diff). Local E2E passed seven cases. These are local results; CI outcome is separate.

<!-- /coderabbit-ai-generated:v1 -->
