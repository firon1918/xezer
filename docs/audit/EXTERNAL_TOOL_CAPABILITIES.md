<!-- coderabbit-ai-generated:v1 -->

# External integration audit

Registry and engine-source inventory at this feature branch. Every row is an assessment of the integration boundary, not a claim that the third-party binary has been fully audited. No unsafe child was re-enabled. Target preflight cannot authorize generated paths/methods. Tools remain installed/configurable but guarded execution is blocked; do not count them as supported scanners.

| Tool | Source references | Egress considerations | Current execution | Required secure adapter |
|---|---|---|---|---|
| subfinder | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| dnsx | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| httpx | qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| naabu | qbh/engines/recon.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
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
| nmap | installer registry / indirect integration; runtime path not verified | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
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
