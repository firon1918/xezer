<!-- coderabbit-ai-generated:v1 -->

# Verification strategy

Run `.venv/bin/python -m pytest --cov=qbh --cov-report=term-missing --cov-fail-under=70`, `.venv/bin/python -m pytest tests/e2e -q`, compileall and the README Ruff command. Install requirements-dev.txt to exercise real curl_cffi loopback tests; the optional runtime transport remains optional for users. Tests use synthetic identities and isolated SQLite databases.

New cases live in test_security_boundaries.py, test_transport_sessions.py and test_brain_planner.py. Reproduce failures before implementation; preserve the original secure/vulnerable IDOR controls. CLI approval now needs an explicit existing PLAN_ID. Decision replay and execution claiming are separate checks.

Outstanding gates: subprocess-generated requests, connection-time DNS/port policy, method overrides, redirected credentials, complete dry-run socket instrumentation, plan expiry, parser depth/size, HAR freshness and full lab detection benchmark. Performance and CI multi-Python checks remain required; passing unit tests does not close those obligations.
