#!/usr/bin/env bash
# CodeRabbit-generated lab startup.
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f compose.yaml up -d --wait --wait-timeout 180
