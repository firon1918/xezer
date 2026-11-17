<!-- coderabbit-ai-generated:v1 -->

# OWASP coverage — initial inventory, not a benchmark

Official references checked in this continuation: [Top 10:2025](https://owasp.org/Top10/2025/) and [API Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). [Top 10:2021](https://owasp.org/Top10/2021/) and [WSTG](https://owasp.org/www-project-web-security-testing-guide/) require detailed per-test mapping. The 2025 publication includes Mishandling of Exceptional Conditions as A10. Category membership never implies complete coverage.

| Vulnerability / category | Module | Type | Preconditions / evidence | Target / result | Limitations |
|---|---|---|---|---|---|
| Access control A01:2021/2025; API BOLA | brain/strategies/idor.py | Active | Two verified subjects, owner policy, protected object, negative control | Synthetic loopback / PASS in existing E2E | Not broad BFLA or privilege escalation; CWE-639/862 |
| JWT authentication A07:2021/2025 | brain/strategies/jwt_implementation_weakness.py | Passive | Captured token structure | Unit fixtures / PARTIAL | Token weakness candidate is not server acceptance; CWE-347 |
| Injection A03:2021, A05:2025 | engines/sqli.py, ssti.py, xss.py | Active | Authorized input, differential evidence | Juice Shop / NOT TESTED | Legacy implementations require impact/false-positive audit; CWE-89/79/1336 |
| SSRF A10:2021 | engines/ssrf.py | Active | Controlled callback correlation | Lab / NOT TESTED | No arbitrary metadata/internal targets; CWE-918 |
| Misconfiguration A05:2021, A02:2025 | legacy content/fingerprint engines | Mixed | Response/configuration observations | Lab / NOT TESTED | No comprehensive coverage or exploitability claim |
| API security beyond BOLA | API discovery/fuzz legacy engines | Mixed | Scope, schema/parameters, auth context | Lab / NOT TESTED | No verified mass assignment/rate-limit/business-logic support |
| Supply chain A06:2021, A03:2025 | library_cve/cve_intel | Passive/enrichment | Library identification plus applicable advisory | Lab / NOT TESTED | Version match alone is not exploitability |
| Crypto, integrity, logging, insecure design, exceptional conditions | No verified comprehensive detector | — | Context-specific controls required | NOT TESTED | NOT IMPLEMENTED as comprehensive categories |
| Advanced smuggling/cache/WebSocket/prototype pollution | No audited shared strategy | — | Explicit controlled profile and impact evidence | NOT TESTED | NOT IMPLEMENTED/NOT VERIFIED |

Full CWE and WSTG mappings, per-class positive/negative cases and remaining requested vulnerability classes are outstanding. No coverage percentage is claimed.
