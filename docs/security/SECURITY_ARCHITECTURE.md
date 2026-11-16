<!-- coderabbit-ai-generated:v1 -->

# Security boundaries — current checkpoint

Authorization and ScopeEnforcer decide native scope/RoE. HttpPolicy rechecks inside the concurrency slot. Path matching includes bounded decode/canonical variants; deny globs are case-normalized. Context/Conductor propagate dry-run and active-fuzz restrictions. Dry-run guarded requests/processes fail before sending; unguarded version/installer paths still need end-to-end audit.

EgressController currently validates subprocess inputs but does not enforce every child-generated request. This remains a critical boundary gap. Optional firejail is not proof of per-request HTTP restrictions. DNS rebinding, port allowlists, proxy and override-header enforcement are unresolved. No execution profile should be treated as exempt from these requirements.

Alternate transport forwards request kwargs and transfers cookies through the caller's jar. Each curl request owns a fresh session, preventing ambient cross-identity cookies. This intentionally trades connection reuse for isolation; performance has not been benchmarked. Response redirects are handled by HttpPolicy; cross-origin credential/body forwarding still needs repair. Timeout retries are disabled for state-changing methods because server execution may have succeeded before the response was lost.

Plan decisions use conditional SQL updates. Execution claim checks ready state and prerequisite hash atomically; a running plan cannot be overwritten by preparation. Approval expiry, explicit plan version storage, crash recovery of running claims and complete lifecycle transitions remain incomplete. No database migration was introduced.

Plugin additions must reuse authorization, request mutation/comparison and encrypted evidence. Existing interface is described in qbh/brain/strategy.py. Only IDOR/JWT Brain strategy modules exist; knowledge entries are not implementations.
