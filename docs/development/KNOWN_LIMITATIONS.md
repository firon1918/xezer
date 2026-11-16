<!-- coderabbit-ai-generated:v1 -->

# Known limitations — release blocker

**NOT RELEASE READY**. The master assignment is incomplete.

Critical: subprocess child requests can escape native path/method enforcement. High: connection-time DNS/IP/port validation, proxy policy, method overrides, cross-origin credentials, strict end-to-end dry-run and full approval expiry/integrity remain unresolved. These prevent any claim of a fully centralized outbound boundary.

Authentication body/cookie isolation and duplicate execution claims have regression coverage. Refresh/CSRF/MFA, all session transport variants and stale-session behavior are not comprehensively verified. Source maps, HAR freshness, deferred applicability, recursive parsers and graph limits still require audit.

No new vulnerability plugins or comprehensive OWASP detection benchmark have been implemented. Juice Shop compose/image preparation succeeded but container startup failed due to sandbox cgroups. VulnHub provisioning and additional targets are untested. No vulnerable services remain running or publicly exposed. Full remote CI results and performance measurements are outstanding.
