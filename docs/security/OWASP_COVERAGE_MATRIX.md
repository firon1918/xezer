<!-- coderabbit-ai-generated:v1 -->

# OWASP coverage — inventory plus loopback detection benchmark

Official references checked in this continuation: [Top 10:2025](https://owasp.org/Top10/2025/) and [API Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). [Top 10:2021](https://owasp.org/Top10/2021/) and [WSTG](https://owasp.org/www-project-web-security-testing-guide/) require detailed per-test mapping. The 2025 publication includes Mishandling of Exceptional Conditions as A10. Category membership never implies complete coverage.

| Vulnerability / category | Module | Type | Preconditions / evidence | Target / result | Limitations |
|---|---|---|---|---|---|
| Access control A01:2021/2025; API BOLA | brain/strategies/idor.py | Active | Two verified subjects, owner policy, protected object, negative control | Loopback benchmark / PASS (confirmed planted, inconclusive hardened) | Not broad BFLA or privilege escalation; CWE-639/862 |
| Path traversal / LFI A01:2021/2025 | brain/strategies/lfi_path_traversal.py | Active | Operator-designated synthetic canary file (`lfi_canary_file`), exact-content disclosure, missing-file negative control, repetition | Loopback benchmark / PASS (confirmed planted, inconclusive hardened) | No canary → deferred, never guessed; depth ≤ 4; CWE-22 |
| JWT authentication A07:2021/2025 | brain/strategies/jwt_implementation_weakness.py | Passive | Captured token structure | Loopback benchmark / PARTIAL (candidate only) | Token weakness candidate is not server acceptance; CWE-347 |
| Injection A03:2021, A05:2025 — SQLi | brain/strategies/sqli.py | Active | Boolean differential with distinct literals, repeated rounds, negative control | Loopback benchmark / PASS (confirmed planted, inconclusive hardened) | GET parameters only, ≤ 2 parameters; no time-based/blind inference; CWE-89 |
| Injection A03:2021, A05:2025 — SSTI | brain/strategies/ssti.py | Active | Two distinct arithmetic products across `{{}}`/`${}`/`<%=%>` syntaxes, negative control, repetition | Loopback benchmark / PASS (confirmed planted, inconclusive hardened) | Expression evaluation only, no RCE claim; CWE-1336 |
| Injection A03:2021, A05:2025 — XSS | brain/strategies/xss.py | Active | Unescaped marker reflection with context classification | Loopback benchmark / PASS (candidate planted, completed hardened) | Capped at candidate: confirmation requires independent browser execution evidence (`browser_execution_verified`); CWE-79 |
| Legacy injection engines | engines/sqli.py, ssti.py, xss.py | Active | Authorized input, tool evidence | Juice Shop / NOT TESTED | Dalfox R/V and sqlmap signals stay candidates pending validation |
| SSRF A10:2021 | engines/ssrf.py | Active | Controlled callback correlation | Lab / NOT TESTED | No arbitrary metadata/internal targets; CWE-918 |
| Misconfiguration A05:2021, A02:2025 | legacy content/fingerprint engines | Mixed | Response/configuration observations | Lab / NOT TESTED | No comprehensive coverage or exploitability claim |
| API security beyond BOLA | API discovery/fuzz legacy engines | Mixed | Scope, schema/parameters, auth context | Lab / NOT TESTED | No verified mass assignment/rate-limit/business-logic support |
| Supply chain A06:2021, A03:2025 | library_cve/cve_intel | Passive/enrichment | Library identification plus applicable advisory | Lab / NOT TESTED | Version match alone is not exploitability |
| Crypto, integrity, logging, insecure design, exceptional conditions | No verified comprehensive detector | — | Context-specific controls required | NOT TESTED | NOT IMPLEMENTED as comprehensive categories |
| Advanced smuggling/cache/WebSocket/prototype pollution | No audited shared strategy | — | Explicit controlled profile and impact evidence | NOT TESTED | NOT IMPLEMENTED/NOT VERIFIED |

## Loopback detection benchmark (measured)

`tests/benchmarks/owasp_detection.py` runs the full brain lifecycle against
planted-vulnerability and hardened loopback (127.0.0.1) fixtures;
`tests/test_owasp_benchmark.py` gates it in CI. Latest measured run:

- Score: **6/6 expected detections, 0 hardened false positives**.
- Planted: sqli/ssti/lfi/idor **confirmed**, xss/jwt **candidate**
  (4 confirmed + 3 candidate findings, 63 fixture requests, 1.465 s planner time).
- Hardened: every active case **inconclusive/completed**, 0 findings
  (59 fixture requests, 0.628 s planner time). JWT is a client-token
  observation and is excluded from the hardened false-positive count by design.
- Confirmation is never a flag or HTTP status alone: each confirmed class
  passes its `has_confirmation` gate (paired controls, distinct literals or
  products, repetition, negative controls). A forged `confirmed` result
  without gate evidence is downgraded to `inconclusive` by the planner
  (`tests/test_injection_strategies.py`).

Full CWE and WSTG mappings, per-class positive/negative cases beyond the
benchmark fixtures and remaining requested vulnerability classes are
outstanding. No coverage percentage is claimed.
