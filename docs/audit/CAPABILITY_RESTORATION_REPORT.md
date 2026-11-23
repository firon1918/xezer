<!-- coderabbit-ai-generated:v1 -->

# Security and capability restoration report

## A. Security changes
PolicyResolver filters each DNS candidate independently; denied private answers no longer suppress authorized public or explicitly granted internal candidates. If no candidate is authorized the request fails closed. TCPConnector consumes those same records, with DNS caching disabled for new connections. Mapped IPv6 now checks deny rules for both original and effective addresses. Origin authorization and IP authorization remain separate: IP/CIDR grants never grant unrelated hostname access.

Method-override headers authorize the effective method in addition to the original request. Path-rewrite headers still fail with a distinct adapter-required reason. Immutable operation category gates now include DoS, DDoS, resource exhaustion, brute force, persistence, backdoors, destructive operations and unauthorized exfiltration. These are dispatch policy tests, not proof against arbitrary malicious plugin code. Global safety configuration can restate prohibitions but cannot turn them off; unknown safety settings fail validation.

## B. Capability impact
See CAPABILITY_IMPACT.md for pre-change comparison and EXTERNAL_TOOL_CAPABILITIES.md for each registered CLI tool. Restored: mixed public/private DNS candidates, authorized cross-origin read redirects, method overrides under effective-method authorization, and domain connection reuse. Retained: private enterprise IP/CIDR grants, literal IPv4/IPv6, JSON/form bodies and caller cookie sessions. No new vulnerability detector or RCE proof capability is claimed.

Cross-origin redirects use an anonymous caller with no inherited headers, cookies, auth or API keys. A 303 converts to GET and drops entity headers/body. Cross-origin replay of a non-read request body still requires a dedicated explicit replay/auth adapter. Same-origin cookies and headers remain usable. Redirect scope, destination DNS/IP/port checks and redirect count limits remain active.

Domain connectors are installed on the caller session, so cookies, session close and pool lifetime belong to that caller. The pool is bound to authorization identity and scope/port fingerprint. Policy changes require a new session rather than reusing a stale pool. Open sockets remain pinned to their original authorized peer even if DNS later changes; new connections revalidate answers. Shared externally-owned connectors are rejected with an explicit reason. The integration uses aiohttp connector ownership fields; dependency upgrades require regression testing. Native literal-IP pooling remains unchanged.

## C. Enterprise configuration / migration
Use existing scope syntax rather than a parallel infrastructure permission scheme:

```yaml
program: Enterprise assessment
scope:
  - domain: company.example
    in_scope:
      - company.example
      - '*.company.example'
      - 10.10.1.20
      - 10.20.0.0/16
      - fd00::/64
    out_of_scope:
      - 10.20.0.1
network_allowed_ports: [443, 8443]
global_safety_policy:
  prohibited_operations:
    dos: true
    ddos: true
    resource_exhaustion: true
    brute_force_attacks: true
    persistence: true
    destructive_operations: true
```

Private grants are explicit IP/CIDR entries. Hostname grants alone do not authorize private DNS destinations. The example infrastructure block from the task is not another accepted schema: it now errors with migration guidance instead of silently ignoring permissions. Legacy in_scope/out_of_scope entries remain supported. Ports default to 80/443 for hostnames; explicitly scoped IPs retain the prior all-port permission. IPv6 zone-qualified link-local addresses remain unsupported because interface authorization is not modeled.

## D. Verification
Deterministic tests in test_capability_preservation.py exercise mixed DNS, private IPv4/IPv6/CIDR and mapped deny precedence, immutable safety flags, effective-method restrictions, real domain keep-alive, allowed cross-origin redirect credential isolation, real IPv6 loopback, enterprise configuration and invalid settings. Existing denied method-override test now explicitly forbids state-changing actions; its security assertion is preserved. The previous cross-origin blanket-block test now denies an out-of-scope target, complemented by a real authorized redirect negative-credential control.

Initial new tests failed before implementation. First full run passed 1336 tests, one skipped, coverage 85.55%. <!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:c5bf6a2b305222cacd1f399f6b2885fad07b44d45c86c168933fed752c1bf5e3 -->

Final full suite: **1344 passed, 1 skipped, 85.70% coverage**, 75.66 seconds. Local E2E passed seven tests. Two consecutive benchmark executions preserved 53 endpoints, 53 parameter combinations, 236 executions and 36 tentative evidence records (not confirmed vulnerabilities). Ruff/compileall/diff checks passed.

<!-- /coderabbit-ai-generated:v1 --> The skip is the unavailable-curl test because curl_cffi is installed. Existing auth/native engine tests are regression evidence, not a comprehensive detection benchmark. No public target was scanned.

## E. Remaining risks / incomplete acceptance criteria
Proxy functionality remains blocked where destination pinning cannot be enforced; no tested HTTP CONNECT/SOCKS adapter was implemented. External CLI scanners remain blocked pending mandatory per-request mediation and filesystem/process isolation; the per-tool matrix describes missing functionality. This means the master task's broad scanner/proxy capability objective is not complete. Existing/planned XXE, RFI, WebSocket, RCE/shell proof, privilege escalation and business-logic detectors are not declared supported by this work.

Audit decisions are not yet uniformly persisted across every execution path. Arbitrary plugin-created sockets are not OS-sandboxed. Global category denial is not a complete semantic analysis of payloads. CNAME traversal relies on the OS resolver's final A/AAAA answers; full controlled CNAME infrastructure tests remain outstanding. TLS certificate/SNI and all proxy protocols require additional live integration tests. <!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:3da6248849932302ae560dcec2fa9311a99697e3068f0d4b98eb81d0bca81cef -->

Juice Shop startup was retried using the repository Compose procedure and task-local Docker daemon 29.1.3. It again failed with OCI cgroupv2 invalid-domain state; failed container/network were removed and task-owned daemon stopped. No successful vulnerability detection against Juice Shop is claimed.

<!-- /coderabbit-ai-generated:v1 -->

## F. Git
Current feature branch: feature/security-hardening-capability-expansion. Baseline: 2758c9a. Changes touch Authorization, Config, network policy, HttpPolicy, regression tests and audit documentation. No database migration or merge to main. Exact commit and push receipts are reported in the task response.

**Release recommendation: NOT RELEASE READY** for the full requested platform. Verified functionality improvements are usable within the documented native transport boundaries; unresolved integrations are not hidden by passing tests.
