<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:d6ff560f9d9fc10d1a7664b26687b7a44d77daa691b27af736e9ce97c9950cda -->

<!-- coderabbit-ai-generated-section:v1:62894de9d67af329223a6bff92dc7f2bbadc060657fe1636d4d48fdc3e1d2e88 -->

<!-- coderabbit-ai-generated-section:v1:7929bbfcfbb28d0c693c689ba27d0941086efaee1a9c6ce1185b03ba57080cd7 -->

<!-- coderabbit-ai-generated-section:v1:d99f6b511f1b5a6945c4d5b47f93cb108478efaa4857668d3b473f88ecc507d1 -->

<!-- coderabbit-ai-generated-section:v1:279922d8eb8ae1783ae8669ad9927a17d89b3be13758af11261cefcde81eefe4 -->

# External integration audit

Registry and engine-source inventory at this feature branch. Every row is an assessment of the integration boundary, not a claim that the third-party binary has been fully audited. No unsafe child was re-enabled. Target preflight cannot authorize generated paths/methods. Statuses distinguish real tested paths from unverified or blocked paths. Partial integration is not certification of every optional mode.

| Tool | Source references | Egress considerations | Current execution | Required secure adapter |
|---|---|---|---|---|
| subfinder | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| dnsx | qbh/engines/deep_enum.py; qbh/dns_mediation.py | Private UDP/TCP DNS bridge to scoped Unix broker | PARTIAL: v1.3.1 real A/AAAA, denied-name and private-address tests pass | AXFR, ANY, iterative trace and complete DeepEnum orchestration remain unverified/unsupported paths |
| httpx | qbh/engines/recon.py; mandatory HTTP broker and offline identity check | HTTP(S) target probing, optional DNS/protocol side channels | PARTIAL: v1.12.0 real HTTP, allow/deny, recon parser and SQLite persistence pass | Hostname/DNS, optional protocol modes and full recon stages still pending |
| naabu | qbh/engines/recon.py; qbh/socket_tools.py via EgressController/run_process | TCP discovery with validated numeric target list | PARTIAL: v2.7.0 real IPv4/IPv6 JSON output verified | Exact recon top-ports pipeline, non-connect modes and resource limits still pending; v2.3.4 has a reproduced timeout-unit defect |
| katana | qbh/engines/offensive.py, qbh/engines/param_enum.py, qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | PARTIAL: v1.8.0 real crawl, policy denial and ReconEngine database ingestion pass | Headless/browser, authenticated crawl and optional modes still require real tests |
| nuclei | qbh/engines/vuln.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | NOT TESTED: mediation preset present | Run actual templates and implement required non-HTTP protocol adapters |
| ffuf | qbh/engines/content.py, qbh/engines/ferox.py, qbh/engines/offensive.py, qbh/engines/param_enum.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | PARTIAL: real authorized/denied HTTP and Juice Shop requests verified | Complete all engine-specific workflows and finding validation |
| alterx | qbh/engines/deep_enum.py; offline_tools.py | Local permutation generation; optional updater | PARTIAL: v0.1.0 actual permutation output passes in networkless sandbox | Downstream DNSx resolution/pipeline still pending; updater remains a provisioning operation |
| gau | qbh/engines/deepen.py, qbh/engines/offensive.py, qbh/engines/param_enum.py, qbh/engines/recon.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| jsluice | installer registry; offline_tools.py | Local parsing or remote JavaScript fetch | PARTIAL: pinned 0ddfab153e06 real local and remote URL extraction passes | Remote input prefetched through policy, genuine parser runs offline; downstream graph wiring still pending |
| x8 | qbh/engines/param_enum.py, qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| arjun | qbh/engines/param_enum.py, qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| schemathesis | qbh/engines/api_fuzz.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| feroxbuster | qbh/engines/ferox.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | NOT TESTED: mediation preset present | Run actual binary and verify engine output ingestion |
| amass | qbh/engines/deep_enum.py | DNS/raw sockets or multiple protocols | BLOCKED | Protocol-aware isolated adapter required; HTTP proxy cannot constrain raw sockets |
| nmap | qbh/socket_tools.py via EgressController/run_process; installer registry | TCP connection discovery; pinned hosts file | PARTIAL: real IPv4/IPv6 connect scans verified | NSE/service probes and application-restriction gateway still pending; not certified for all Nmap modes |
| sqlmap | qbh/engines/sqli.py, qbh/engines/wafdetect.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | PARTIAL: real mediated requests executed; prior Juice Shop detection missed | Investigate missed SQLi and verify positive/negative detection; exit zero is not detection evidence |
| ghauri | qbh/engines/sqli.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | BLOCKED | Mandatory HTTP mediation plus isolated execution required; optional proxy flag is insufficient |
| dalfox | qbh/engines/xss.py | HTTP/HTTPS, redirects, generated requests; verify tool-specific side channels | PARTIAL: v2.13.0 real positive/negative reflection and structured evidence pass | Independent browser execution verification remains pending; DOM observations are candidates |
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

## Offline and HTTPx integration evidence

Version-command signatures from the existing installer registry now run in a filesystem and network namespace with no host network or broker socket. They are provisioning identity checks, not scanner success evidence. Actual AlterX permutation generation and JSluice parsing are tested separately. HTTPx v1.12.0 runs through explicit proxy mediation; the real ReconEngine._httpx path validates the binary, probes a synthetic server, parses output and persists host/title data to SQLite. No subprocess mocking is used in these selected real tests.

A real recon regression exposed synthetic 403 responses from the broker on upstream TLS errors. Those looked like target findings and suppressed HTTP fallback. Broker failures now close the exchange and retain audit evidence without synthesizing a target HTTP response. Policy denials still send no target request. Existing real curl/ffuf and HTTPS tests passed after this correction. JSluice uses Go proxy behavior that bypasses loopback; remote inputs are therefore fetched by the shared policy first and passed as staged local files to the original JSluice binary. This is an explicit fetch/parse adapter, not a substitute parser.

Additional real gate: `XEZER_CLI_TESTS=1 XEZER_TOOL_BIN=<binary-directory> .venv/bin/python -m pytest -q tests/test_additional_cli.py`. Tested builds: HTTPx v1.12.0, AlterX v0.1.0, JSluice v0.0.0-20240110145140-0ddfab153e06. Full library/provider/DNS browser modes and all other listed tools remain unverified until their real tests exist.


<!-- /coderabbit-ai-generated:v1 -->

## Katana and Dalfox restored execution paths

Katana v1.8.0 now receives its explicit proxy argument inside the existing network/filesystem namespace. The kernel denies direct egress; all actual HTTP exchanges go through RequestBroker and HttpPolicy. The real ReconEngine._crawl fixture discovered authorized links, stored them in SQLite, and sent no requests to the restricted path or foreign redirect. Failed/timeout executions now create warnings instead of silently appearing as an empty successful crawl. Browser modes have not been verified by this test.

Dalfox v2.13.0 executed a bounded custom-payload fixture through the real adapter. Unsafe HTML reflection produced structured evidence; escaped HTML produced no findings. An actual denied-path test observed zero target requests; an invalid-option test preserved the nonzero exit and error output. These are request and detector tests, not successful JavaScript execution claims. The test-only custom payload and skip-headless options do not alter production scanner defaults.

A failing regression proved that the previous XSSEngine regular expression interpreted “not vulnerable” as a confirmed XSS finding. The old implementation also selected only reflected PoCs (`--only-poc r`) while claiming confirmation. It now collects JSONL R and V observations, preserves evidence, rejects malformed/foreign records and failed executions, and does not infer confirmation from prose. Dalfox's pinned implementation can emit V for a static DOM selector match, so that label alone is insufficient execution proof. Observations remain candidates until independent verification. This changes an incorrect confirmation behavior, while retaining detected signals and actual scanner execution. Production output includes requests/responses and worker concurrency follows the scan configuration.

Reproduce selected real gates with XEZER_CLI_TESTS=1 and XEZER_TOOL_BIN containing the pinned binaries. Build commands verified here: GOBIN=<bin> GOMAXPROCS=2 go install github.com/projectdiscovery/katana/cmd/katana@v1.8.0 and github.com/hahwul/dalfox/v2@v2.13.0. Shared test command and exact observed results are recorded in the task validation record; headless XSS, full default Dalfox workflow, and unrelated scanner integrations remain outstanding.


<!-- /coderabbit-ai-generated:v1 -->
## DNSx controlled resolver integration

EgressController routes actual DNSx executions into the existing filesystem/user/network namespace. The child has only its own loopback and a mounted Unix DNS broker socket. Explicit resolver arguments select a local UDP/TCP bridge; ignoring those arguments cannot create host network access. The parent parses bounded DNS messages, requires one IN question, authorizes its normalized name, checks lifecycle/dry-run and operation rules, and resolves it with dnspython using the deployment's configured resolver. A resolver is trusted control-plane infrastructure, not an assessment-scope grant. DNS-derived addresses never expand target scope. Subsequent HTTP/socket connections still need their own pinned transport authorization.

The broker shares scan rate/concurrency state, caps concurrent handlers at16, accepts at most4096 request bytes, limits a process to1000 authorized questions, bounds resolver and exchange time, cancels handlers and removes sockets on teardown. Mixed A/AAAA address sets retain permitted addresses and filter private addresses lacking explicit grants. Explicit enterprise private-IP grants remain effective. This does not yet establish complete CPU/disk/output resource limiting for all scanners.

Real DNSx1.3.1 executed through this adapter against a synthetic UDP resolver: A/AAAA output parsed correctly, foreign names never reached the upstream resolver, private addresses were filtered, and dry-run sent no DNS queries. Separate actual socket execution inside the same namespace could not contact the host resolver directly. Broker tests cover explicit private grants, cancellation, mixed-address filtering and CNAME records. No public assessment target was used. Version discovery passed in the offline namespace separately.

Current limitations: single-query UDP/TCP lookup support does not implement AXFR/IXFR streaming or ANY; these return REFUSED explicitly. Iterative trace/direct authoritative-server modes cannot bypass the namespace and need a dedicated authorized adapter before being represented as working. Full DeepEnum source orchestration and DNSx wildcard/reverse/PTR modes remain unverified. No entire scanner integration was removed. Source files: qbh/dns_mediation.py, qbh/dns_child.py; real gate: XEZER_CLI_TESTS=1 XEZER_TOOL_BIN=<bin> python -m pytest tests/test_dns_mediation.py. Build pinned binary with GOBIN=<bin> GOMAXPROCS=2 go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1.


<!-- /coderabbit-ai-generated:v1 -->