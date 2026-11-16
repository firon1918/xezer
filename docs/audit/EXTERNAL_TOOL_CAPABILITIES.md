<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:d99f6b511f1b5a6945c4d5b47f93cb108478efaa4857668d3b473f88ecc507d1 -->

<!-- coderabbit-ai-generated-section:v1:279922d8eb8ae1783ae8669ad9927a17d89b3be13758af11261cefcde81eefe4 -->

# External integration audit

Registry and engine-source inventory at this feature branch. Every row is an assessment of the integration boundary, not a claim that the third-party binary has been fully audited. No unsafe child was re-enabled. Target preflight cannot authorize generated paths/methods. Tools remain installed/configurable but guarded execution is blocked; do not count them as supported scanners.

| Tool | Source references | Egress considerations | Current execution | Required secure adapter |
|---|---|---|---|---|
| subfinder | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| dnsx | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| httpx | qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| naabu | qbh/engines/recon.py; qbh/socket_tools.py via EgressController/run_process | TCP discovery with validated numeric target list | PARTIAL: v2.7.0 real IPv4/IPv6 JSON output verified | Exact recon top-ports pipeline, non-connect modes and resource limits still pending; v2.3.4 has a reproduced timeout-unit defect |
| katana | qbh/engines/offensive.py, qbh/engines/param_enum.py, qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| nuclei | qbh/engines/vuln.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| ffuf | qbh/engines/content.py, qbh/engines/ferox.py, qbh/engines/offensive.py, qbh/engines/param_enum.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| alterx | qbh/engines/deep_enum.py | Offline analysis (must prevent telemetry/helper egress) | BLOCKED | No-network filesystem/process sandbox required; network namespace alone leaves host Unix sockets reachable |
| gau | qbh/engines/deepen.py, qbh/engines/offensive.py, qbh/engines/param_enum.py, qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| jsluice | installer registry / indirect integration; runtime path not verified | Offline analysis (must prevent telemetry/helper egress) | BLOCKED | No-network filesystem/process sandbox required; network namespace alone leaves host Unix sockets reachable |
| x8 | qbh/engines/param_enum.py, qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| arjun | qbh/engines/param_enum.py, qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| schemathesis | qbh/engines/api_fuzz.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| feroxbuster | qbh/engines/ferox.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| amass | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| nmap | qbh/socket_tools.py via EgressController/run_process; installer registry | TCP connection discovery; pinned hosts file | PARTIAL: real IPv4/IPv6 connect scans verified | NSE/service probes and application-restriction gateway still pending; not certified for all Nmap modes |
| sqlmap | qbh/engines/sqli.py, qbh/engines/wafdetect.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| ghauri | qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| dalfox | qbh/engines/xss.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| sstimap | qbh/engines/ssti.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| jwt_tool | qbh/engines/jwt.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| semgrep | qbh/engines/sourcecode.py | Offline analysis (must prevent telemetry/helper egress) | BLOCKED | No-network filesystem/process sandbox required; network namespace alone leaves host Unix sockets reachable |
| git-dumper | qbh/engines/sourcecode.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| kr | qbh/engines/api_enum.py, qbh/engines/deepen.py, qbh/engines/fingerprint.py, qbh/engines/race.py, qbh/engines/sqli.py, qbh/engines/validation.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| bbot | qbh/engines/deepen.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| waymore | qbh/engines/deepen.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| gowitness | qbh/engines/deepen.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| dnstwist | qbh/engines/deepen.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| interactsh-server | installer registry / indirect integration; runtime path not verified | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |

A local `unshare --user --map-root-user --net true` capability check succeeded. That alone is not sufficient containment: host Unix sockets/files and helper subprocesses require filesystem/process isolation. No verified complete mediation wrapper was implemented in this turn. Proxy-based and tool-specific sandbox prototypes must demonstrate both permitted requests and denied hidden targets before support is claimed.

## Subsequent mediation checkpoint

The BLOCKED column above is the pre-change baseline, not the current certification matrix. curl and ffuf now have real allow/deny execution tests; sqlmap executes through mediation but missed the tested Juice Shop injection. nuclei, dalfox and feroxbuster have unverified proxy presets. Other rows still require restoration work. See [current evidence and remaining work](MEDIATION_PROGRESS.md). No version-only invocation counts as a scanner integration test.


<!-- /coderabbit-ai-generated:v1 -->
## Direct socket orchestration evidence

The previous blanket child refusal is now replaced for Nmap/Naabu TCP discovery by `socket_tools.run_socket_tool`, reached through both `EgressController.run` and guarded `adapters.base.run_process`. Every destination is scope checked; hostname resolution occurs once, private answers need an explicit IP/CIDR grant, and only approved candidates enter namespace routes/firewall. Nmap uses system resolution with a private hosts file. Naabu uses the exact validated IP list because its DNS client bypasses hosts. Per-destination port ranges preserve explicit literal-IP grants and configured hostname port limits. Direct DNS cannot expand routes. Tests prove real allowed and denied traffic, parsed Naabu JSON, one DNS lookup, and unchanged namespace/firewall configuration from the child. These are local synthetic IPv4/IPv6 fixtures, not proof of external routed deployment readiness.

Optional real-test prerequisites: Linux sudo/iproute2/iptables/ip6tables/bubblewrap/Nmap; Go-built Naabu v2.7.0 (`GOBIN=<chosen-bin-dir> GOMAXPROCS=2 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.7.0`) with libpcap development files. Run `XEZER_PRIVILEGED_TESTS=1 XEZER_NAABU_BIN=<absolute-naabu-path> .venv/bin/python -m pytest -q tests/test_socket_namespace.py`. Missing binaries are failures in this selected test, not mocked successes. Ordinary tests do not automatically grant privileged host firewall access.

Raw socket execution currently refuses HTTP request restrictions because L3/L4 rules cannot enforce paths and methods. An application-aware gateway is still needed for that configuration. NSE/service probes remain explicitly unsupported in the socket adapter while classification and mediation are implemented. No integration was deleted, and these limitations must not be counted as full restoration. Two concurrent namespace executions per controller, process timeout, cancellation/deadline monitoring and namespace process termination are implemented; dedicated adversarial resource/cleanup tests and output-volume limits remain pending.


<!-- /coderabbit-ai-generated:v1 -->