<!-- coderabbit-ai-generated:v1 -->

# Proxy, subprocess mediation and lab engineering checkpoint

## Status
The latest all-core-scanners acceptance criteria are **not complete**. This checkpoint implements working HTTP mediation and proxy adapters; it does not certify every registry integration or raw-socket scanner. No scanner integration or dependency has been removed. NOT RELEASE READY for the complete scanner-restoration objective.

## Architecture implemented
Explicit HTTP CONNECT, HTTPS CONNECT and SOCKS5 proxy adapters resolve target names locally, validate individual candidate IPs and send numeric addresses to the proxy. TLS validates the original target hostname/SNI. Proxy credentials stay on the proxy handshake. Caller-owned connection pools retain session isolation. Changing the proxy/policy requires a new session. Environment proxies remain rejected. The explicitly configured proxy is trusted infrastructure: XEzer cannot prove that a malicious proxy actually routes to the requested IP. HTTPS target certificate validation remains enabled.

Guarded `run_process` and `EgressController.run` enter a mandatory bubblewrap filesystem, user, PID, IPC and network namespace. The child has no host network, home, proc filesystem or Docker socket. A single Unix socket reaches an HTTP broker. A private loopback relay exposes it to proxy-compatible tools. HTTPS is terminated using an ephemeral CA whose private key is not mounted into the child. Every decrypted request goes through HttpPolicy, with scan rate/concurrency budgets shared. Direct sockets cannot escape the namespace. Missing isolation/dependencies never trigger an unrestricted retry.

The broker preserves binary request/response bodies, multiple Set-Cookie headers, scanner stdout/stderr, exit codes and explicitly staged output files. Request/response bodies are capped; 32 pending connections, 8 processing slots, 1,000 requests per execution, 60-second exchanges and at most 128 certificate names bound broker resources. Scanner output file collection is capped at 32 MB. These are explicit limits, not proof of complete process resource containment.

## Executed evidence
- Real curl: HTTP and HTTPS requests, denied paths, redirect cookie handling, binary response preservation.
- Real ffuf 2.1.0-dev: wordlist ingestion, actual authorized requests, denied path never reaches server, JSON output consumed and checked.
- Real sqlmap 1.10.4: executed through broker against Juice Shop; first run mediated 17 requests, later explicit-prefix run 9. Both exited 0 but did **not** detect injection. This is a missed detection, not a successful vulnerability finding. An intervening attempt while the lab was stopped received broker 403 and is not counted as a passing scan.
- Native HTTP CONNECT and SOCKS5 fixtures: numeric destinations, bodies, cookies, pooled connection reuse and denied methods/paths.
- Native HTTP/HTTPS proxy fixtures: target TLS verification, original SNI, explicit proxy authentication, encrypted proxy connection.
- Namespace escape fixture: direct loopback and external-address connections fail; host home, Docker socket and host proc paths are absent.
- Dry-run instrumentation: no broker listener, subprocess or DNS resolution.

## Juice Shop
Pinned image v19.0.0 now runs through `tests/labs/namespace_lab.py`, bypassing the unsupported Docker cgroup runtime without granting host network access. Compose remains the default on a normal Docker host. `prepare-namespace.sh` reproducibly exports the same pinned image without starting a container; use a new rootfs directory. The fallback uses a writable disposable app copy, private network namespace and Unix ingress. Host listener binds only 127.0.0.1:3000. It is registered as a TCP lab service, without a public Preview.

`python -m tests.labs.verify_juice_shop` verifies readiness, native authorized/denied traffic, mediated curl and ffuf output, and a non-destructive query-predicate bypass: control returned 0 rows, injected query returned 46. This verifies lab behavior and transport evidence, not a newly implemented autonomous SQLi detector. External-service-dependent Juice Shop challenges cannot work without egress. The fallback does not enforce Compose memory/pid cgroup limits. Stop the foreground launcher with Ctrl-C; its finally block kills the isolated process group. Delete only the dedicated disposable state directory to reset fixtures.

## Installation and use
Install `pip install -r requirements-mediation.txt`, Linux bubblewrap, and the actual tool binaries. Tests require curl and ffuf. CI installs bubblewrap/ffuf and enables unprivileged user namespaces on its disposable runner. Never relax these host settings automatically on a customer deployment. Proxy connections use existing explicit proxy arguments/configuration; no target scope is added by configuring a proxy. The internal broker CA is temporary and is never installed into system trust.

```
DOCKER_HOST=unix:///tmp/xezer-docker.sock tests/labs/prepare-namespace.sh "$RUNTIME_ROOT/juice-shop-rootfs-new"
.venv/bin/python tests/labs/namespace_lab.py --rootfs "$RUNTIME_ROOT/juice-shop-rootfs-new" --state "$RUNTIME_ROOT/juice-shop-state-new"
.venv/bin/python -m tests.labs.verify_juice_shop
```

## Remaining engineering work, not completed claims
All tools in EXTERNAL_TOOL_CAPABILITIES.md remain inventoried. curl/ffuf have real regression coverage; sqlmap has real execution evidence and a missed detection. nuclei/dalfox/feroxbuster proxy presets are unverified, not certified integrations. No HTTP-only selector is imposed on nuclei to disguise lost protocol coverage.

Other tools still need actual execution-environment adapters and per-binary integration tests: subfinder, dnsx, httpx, naabu, katana, alterx, gau, jsluice, x8, arjun, schemathesis, amass, nmap, ghauri, sstimap, jwt_tool, semgrep, git-dumper, kr, bbot, waymore, gowitness, dnstwist and interactsh-server. Mixed-protocol tools need controlled DNS and a privileged destination firewall/gateway in addition to HTTP mediation. A network-namespace creation probe succeeded; lack of implementation must not be mislabeled as an environmental impossibility. API/provider discovery destinations require explicit separate authorization; target DNS must not grant them implicitly.

Unresolved compatibility: transparent mediation for proxy-unaware tools, raw TCP/UDP protocols, browser/WebSocket upgrades, certificate-pinning clients, arbitrary installation layouts/template directories and persistent scanner output directories. HTTP broker connections close after one response; native proxy pools are verified, CLI keep-alive is not preserved yet. Full process resource accounting and complete per-tool dry-run descriptions also remain outstanding. These prevent claiming full restoration.

## Changed components
qbh/proxy_transport.py, qbh/http_policy.py, qbh/mediation.py, qbh/mediation_child.py, qbh/egress.py, qbh/adapters/base.py, qbh/context.py; optional/dev requirements; CI sandbox prerequisites; real transport/CLI tests; lab extraction/start/verification scripts and documentation. No database migration. Existing configurations retain scope; proxy-denial tests were intentionally changed to assert target-policy enforcement through the newly authorized adapter, with real allow/deny tests added.
