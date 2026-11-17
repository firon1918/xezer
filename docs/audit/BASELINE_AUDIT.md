<!-- coderabbit-ai-generated:v1 -->

# Baseline audit — initial discovery

Baseline: origin/main 27ddd80aee9a6d4332f3d1b2e4ab7a0dc1472916. Branch: feature/security-hardening-capability-expansion. No user changes present. This is an initial architecture and boundary inventory, not a completed line-by-line audit of the approximately 20,000 lines of Python.

## Architecture
CLI main.py creates Conductor/Context. Authorization owns scope and RoE; Guardian calls HttpPolicy. Native HTTP uses aiohttp or ImpersonatingTransport. External engines use adapters.base.run_process with a ContextVar EgressController. HAR importer persists encrypted occurrences in SQLite schema 12; RequestGraph and ContextBuilder feed BrainPlanner. TaskLedger/Scheduler govern bounded execution; store persists plans/events/results. Vault encrypts authentication and evidence. Reporting includes JSON/Markdown exports and offline CLI inspection.

## Capabilities
15 knowledge definitions are data, not 15 executable strategies. Brain discovery currently loads IDOR and JWT strategies only. Separate legacy engines include SQLi, XSS, SSTI, SSRF, API discovery/fuzzing and source analysis; their presence is not verification of security impact. Existing tests cover native HTTP, CLI, scope, authentication, HAR, graph, planner, differential analysis, retries, durable recovery and loopback E2E. CI declares Python 3.10–3.14, Ruff, coverage >=70%, repeated benchmark, smoke and gitleaks. Baseline suite is running; no result assumed.

## Confirmed code-level risks requiring reproduction
- EgressController validates command targets, not requests made by a child. Its optional sandbox can silently fall back to no isolation.
- authorize_request checks raw and once-decoded paths only; nested encoding and dot segments can defeat deny patterns. Restriction hosts use case-sensitive fnmatch.
- CLI approval calls execute_ready without a selected-plan filter. Decision rows are not guarded against replay.
- dry_run is used by installer but is not enforced by Authorization or transport.
- Context.active_fuzz reads CLI override, but BrainPlanner asks Authorization directly, losing the override.
- HttpPolicy alternative transport drops request bodies and uses a shared cookie session.
- Scope IPv6 normalization returns the original representation; zones and alternative representations require explicit treatment.
- Authorization occurs before concurrency acquisition, leaving a cancellation/policy-change window.

## Contract changes required by this assignment
README explicitly says scan dry-run has no offline guarantee and state-changing tests are allowed unless forbidden. The new assignment intentionally replaces the former dry-run contract with zero network transmission. CLI implicit bulk approval will be removed in favor of explicit plan IDs. These are compatibility changes, not reasons to weaken regression checks.

## Remaining audit and test gaps
DNS pinning at connection time, port restrictions, proxy policy, method overrides, atomic approval/version/expiry, parser resource budgets, evidence freshness, probe refinement, source maps and relative JS bases still require detailed review and reproduction. Native guarantees cannot currently be extended to all subprocesses. No vulnerable application has been installed or benchmarked in this task. No capability is lab-verified here yet.

## Implementation order
1. Reproduce boundary defects and establish baseline.
2. Central request canonicalization, strict dry-run and active-fuzz propagation, then subprocess containment and DNS/IP/port enforcement.
3. Plan isolation and concurrency, authentication/session transport integrity, evidence/parser correctness.
4. Expand verified detection using shared primitives only after P0 closes.
5. Isolated Juice Shop and VulnHub infrastructure assessment, positive/negative E2E, performance and independent review.
