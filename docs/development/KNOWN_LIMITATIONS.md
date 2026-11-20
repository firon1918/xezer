<!-- coderabbit-ai-generated:v1 -->

# Known limitations

**NOT RELEASE READY** until the remaining items below are closed. Status is
evidence-based: every "verified" claim names the regression tests that prove
it in this repository (full suite: 1434 passed, 7 skipped, real CLI gates
enabled, coverage 83.22% against the 70% floor; the skips are the explicit
privileged socket fixture and the curl_cffi presence check).

## Closed since the previous blocker report

- **Critical — child requests escaping native path/method enforcement.**
  All scanner child TCP egress now runs inside a scoped namespace
  (`qbh/scoped_child.py`) whose default route and iptables REDIRECT force
  every connection into the broker relay; each request is re-authorized at
  the broker (scope, path, method, rate, cooldown). Non-HTTP protocols fail
  closed; DNS is bridged through the scoped resolver. Verified by
  `tests/test_proxy_mediation.py`: mandatory mediation and direct-escape
  denial, HTTPS decryption and re-authorization, ffuf input/output
  preservation, namespace bypass refusal, origin-form POST body
  preservation, and a proxy-unaware raw-socket child whose restricted path
  and method requests are denied at the broker with zero target hits.
- **Connection-time DNS/IP/port validation.** `tests/test_dns_mediation.py`
  (scoped resolver, private-IP denial, dry-run, real DNSx under mediation)
  and `qbh/network_policy.py` per-answer validation with no second lookup.
- **Proxy policy.** `tests/test_proxy_mediation.py` covers numeric CONNECT
  targets, SNI-keyed TLS, proxy credentials, cookie/body preservation and
  connection pooling through both http and socks5 proxies.
- **Method overrides.** `tests/test_capability_preservation.py::test_method_override_uses_effective_authorization`;
  override headers are re-authorized in `qbh/network_policy.py`.
- **Cross-origin credentials.** `tests/test_auth_state.py` origin/path/
  secure/expiry cookie filtering and mutated-context export refusal.
- **Strict end-to-end dry-run.** DNS broker, socket guard, process egress,
  provider policy and installer dry-run tests never start network or
  process IO (`test_dns_mediation.py`, `test_socket_namespace.py`,
  `test_network_boundary.py`, `test_proxy_mediation.py`,
  `test_provider_policy.py`, `test_security_boundaries.py`,
  `test_installer.py`).
- **Approval expiry/integrity and duplicate execution.**
  `tests/test_brain_planner.py::test_decision_replay_rejected` and
  `test_execution_claim_is_single_use_and_version_bound` (CAS decision,
  single-use version-bound claim, re-authorization after queueing).
- **Session transport variants.** `tests/test_auth_variants.py` verifies
  RFC 6238 TOTP (appendix B vectors), bounded refresh-token rotation, CSRF
  double-submit headers, wrong-OTP rejection, stale-cookie fail-closed
  export, refresh-before-relogin on reload, and negative config validation;
  no tokens appear in the database dump.
- **Active vulnerability plugins and OWASP detection benchmark.**
  `qbh/brain/strategies/{sqli,ssti,lfi_path_traversal,xss}.py` add bounded
  GET-only probes with per-class `has_confirmation` gates (paired controls,
  distinct literals/products, repetition, negative controls); the planner
  applies each plugin's own gate and downgrades forged confirmations.
  `tests/test_injection_strategies.py` (25 tests) proves planted positives,
  hardened negatives, error-text-only and flag-only rejection, dry-run and
  authorization enforcement. `tests/benchmarks/owasp_detection.py` +
  `tests/test_owasp_benchmark.py` measure the full brain lifecycle on
  loopback fixtures: 6/6 expected detections, 0 hardened false positives.
  XSS remains candidate-only pending independent browser execution evidence;
  LFI requires an operator-designated synthetic canary (`lfi_canary_file`).
- **Namespace lab fallback verified end-to-end.** The pinned Juice Shop
  image (`bkimminich/juice-shop@sha256:2765a26d…`) was extracted with
  `tests/labs/prepare-namespace.sh` and served by
  `tests/labs/namespace_lab.py` (bubblewrap, empty network namespace,
  Unix-socket ingress, loopback-only listener). `tests/labs/verify_juice_shop.py`
  passed every check against it: readiness, native query-predicate bypass
  (0 control rows vs 46 injected rows), native forbidden-path denial,
  mediated curl allow/deny with `mediation_blocked` audit, and mediated
  ffuf result-file integrity. The lab was stopped afterwards; no vulnerable
  service remains running or publicly exposed. The lab shell scripts were
  also repaired (CRLF→LF, `.gitattributes` keeps them LF) and the verify
  script accepts `--port` so it never collides with unrelated local services.

## Remaining release blockers

- Docker Compose startup of the same image still fails in this sandbox due
  to cgroups restrictions; the verified namespace fallback above is the
  supported local lab path. VulnHub provisioning and additional targets
  remain untested.
- Full remote CI matrix results are outstanding: the local equivalents all
  pass (ruff, compileall, benchmark stability with unchanged baseline,
  pytest 1434 passed / 7 skipped at 83.22% coverage against the 70% floor,
  report-mode and smoke gates), but pushing to the remote is currently
  denied by the stored GitHub credential (403), so no remote run exists
  for the latest commits. Local performance references: OWASP benchmark
  planner time 1.465 s planted / 0.628 s hardened; full suite 272–304 s.

## Remaining audit items (non-blocking)

- HAR freshness semantics and recursive parser/graph limits still need a
  dedicated audit; source maps and deferred applicability already have
  regression coverage (`tests/test_js_intelligence.py`,
  `tests/test_eligibility_states.py`, `tests/test_integrated_verification.py`).