#!/usr/bin/env bash
# CodeRabbit-generated lab teardown, including disposable lab state.
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f compose.yaml down --volumes --remove-orphans
