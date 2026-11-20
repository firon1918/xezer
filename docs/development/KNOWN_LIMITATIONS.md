<!-- coderabbit-ai-generated:v1 -->

# Known limitations

**NOT RELEASE READY** until the remaining items below are closed. Status is
evidence-based: every "verified" claim names the regression tests that prove
it in this repository (full suite: 1407 passed, 7 skipped, real CLI gates
enabled; the skips are the explicit privileged socket fixture and the
curl_cffi presence check).

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

## Remaining release blockers

- No new active vulnerability plugins beyond the IDOR strategy and the
  passive JWT implementation-weakness strategy; no comprehensive OWASP
  detection benchmark with planted-vulnerability positive and hardened
  negative fixtures yet.
- Juice Shop compose/image preparation succeeded but container startup
  failed due to sandbox cgroups; the namespace lab fallback exists
  (`tests/labs/`) but is not yet verified end-to-end. VulnHub provisioning
  and additional targets are untested. No vulnerable services remain
  running or publicly exposed.
- Full remote CI matrix results and performance measurements are
  outstanding.

## Remaining audit items (non-blocking)

- HAR freshness semantics and recursive parser/graph limits still need a
  dedicated audit; source maps and deferred applicability already have
  regression coverage (`tests/test_js_intelligence.py`,
  `tests/test_eligibility_states.py`, `tests/test_integrated_verification.py`).