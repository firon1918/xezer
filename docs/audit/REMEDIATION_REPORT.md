<!-- coderabbit-ai-generated:v1 -->

# Remediation checkpoint — incomplete assignment

## A. Executive summary
Initial architecture/boundary audit and first security repairs on baseline 27ddd80aee9a6d4332f3d1b2e4ab7a0dc1472916. This is a checkpoint, not completion of the master engineering assignment. P0 remains open; new vulnerability plugins and vulnerable labs have not been added.

## B. Previous findings
| Issue | Root cause and affected files | Change / regression | Status |
|---|---|---|---|
| Subprocess restriction bypass | egress.py checks input targets, not generated requests | dry-run blocks guarded process launch even without targets; tests/test_security_boundaries.py | Critical bypass outside dry-run unresolved |
| Method authorization | authorization.py method syntax and normalization | rejects malformed method tokens; existing method/RoE tests retained | Partial; override headers and explicit consent pending |
| Probe bypass | urlintel.py, HttpPolicy | shared authorization remains; no dedicated new probe repair | Pending investigation |
| Case-sensitive restrictions | authorization.py fnmatch on unnormalized host patterns | normalizes exact/wildcard domain patterns including trailing dots; canonical path tests | <!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:474bacaa1127decbbee122dd9f04abe9b5914f6c17922a653264106060a24d3b -->

Verified covered cases including existing deny globs; broader server-specific normalization remains unverified

<!-- /coderabbit-ai-generated:v1 --> |
| Dry-run | Context/Conductor did not pass flag to Authorization | central request/process guards, offline auth registration; zero transport invocation test | Partial; full CLI socket instrumentation and unguarded installer/version probes pending |
| Approval isolation | main.py called execute_ready for every plan | explicit PLAN_ID, rejects missing plan and repeated decision, execute_ready filter; two-plan regression | Verified selection/replay cases; version/expiry and execution races pending |
| Planner/Vault retries | store/planner recovery and task ledger | no retry integrity overhaul | Pending |
| Source maps | brain/js_intelligence.py | no changes | Pending |
| IPv6 normalization | scope.py returned original spelling | standard-library canonical address; rejects zone IDs | Partial; mapped IPv6/IP network enforcement pending |
| Probe state/retry | urlintel.py and persistence | no changes | Pending |
| Forbidden paths | raw plus one decode insufficient | bounded decoding, dot-segment/separator/backslash/NFC variants, malformed encoding rejection | Verified listed regression paths; not proof for every server parser |
| --no-active-fuzz | Context property differed from planner Authorization | CLI false reaches central policy in Context/Conductor | Unit-verified propagation; full active-traffic CLI test pending |
| curl_cffi body/session loss | HttpPolicy drops kwargs; shared transport session | no changes | High unresolved |
| Auth failure isolation | auth_state.py | existing exception handling observed, no expanded audit | Pending |
| HAR freshness | importer/graph/context | no changes | Pending |
| Applicability refinement | eligibility/probe/planner | no changes | Pending |
| Relative JS fetch resolution | JS intelligence | no changes | Pending |

## C. Additional findings
Authorization was checked before concurrency-slot acquisition. HttpPolicy now checks again inside the slot, before the transport invocation. A cancelled authorization test proves no transport invocation. This does not solve DNS rebinding, proxy routing, ports or method-override semantics.

## D. Architecture
Existing Authorization, ScopeEnforcer, HttpPolicy, Context, BrainPlanner and SQLite store retained. No new framework, dependency or schema. Decision writes use a conditional SQL update and event in the same transaction. Failed automatic plans may still be rejected to prevent reconsideration; completed plans cannot be approved again. Execution claiming itself is not yet atomic.

## E. Detection coverage
No new detection classes. 15 knowledge definitions and two Brain strategies observed; legacy engines need independent positive/negative verification. No claim of comprehensive OWASP coverage. Official OWASP mapping and detailed capability matrix remain unimplemented.

## F. Lab results
No Juice Shop, VulnHub or additional vulnerable application installed or tested. Docker CLI is present; daemon has not been evaluated. /dev/kvm is absent and qemu-system-x86_64 was not found; this does not prove software-emulated VMs are impossible. No lab services or public previews started. Lab provisioning and infrastructure verification remain outstanding.

## G. Validation
Baseline suite: 1283 passed, 85.33% coverage (Python 3.14.4). New boundary tests failed before the repair. Plan-isolation/replay tests also failed before the repair. First full modified run: 1299 passed, two failed. One failure was the intentionally removed implicit bulk-approval CLI; E2E now explicitly approves each IDOR plan and preserves vulnerable/secure outcome assertions. Another exposed a compatibility regression rejecting failed automatic plans; fixed without changing that original test. <!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:7bf574b40e9578f97a4fa87913df58d88e9c8fd62546151f304cd6612b14e7c1 -->

Final full run: **1301 passed, coverage 85.36%**. A subsequent deny-glob compatibility repair passed **111 affected tests**, with unaffected full-suite results reused. Ruff, compileall and diff whitespace checks passed. Final repository collects 1302 tests; a single full run of that final count was not performed.

<!-- /coderabbit-ai-generated:v1 --> Local E2E: seven passed after the CLI migration. No remote CI run or multi-Python matrix result claimed.

## H. Git / migration
Branch feature/security-hardening-capability-expansion from latest fetched origin/main. No database migration. CLI callers must supply --approve PLAN_ID; --approve/--reject require --test-plan. Repeated decisions now fail. Zone-qualified IPv6 and ambiguous URL authorities are rejected. No merge authorized or performed.

## I. Remaining risks
Critical: external child traffic still lacks mandatory per-request policy enforcement. High: connection-time DNS/IP/port restrictions, curl_cffi session/body integrity, execution claiming and plan version/expiry, method overrides and full dry-run boundary validation. Medium: parser resource bounds, evidence freshness, configuration validation, source-map and JS/probe correctness remain to be investigated; these are audit obligations, not all confirmed vulnerabilities. Low: documentation/capability mappings and performance measurement incomplete. Full code audit and new detection work remain outstanding.

## J. Release recommendation
**NOT RELEASE READY**. Central outbound policy acceptance criterion is not met and the lab/detection benchmark has not been executed. Passing regression tests do not establish completion of the master assignment.
