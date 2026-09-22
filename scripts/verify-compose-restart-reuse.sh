#!/usr/bin/env bash
set -euo pipefail

run_id="${SIH_RESTART_REUSE_RUN_ID:-$(date +%s)}"
export SIH_RESTART_REUSE_RUN_ID="$run_id"

docker compose up -d --wait postgres
docker compose run --rm backend alembic -c /app/database/alembic.ini upgrade head
docker compose up -d --wait backend worker
docker compose run --rm -v "$PWD/backend:/workspace" backend python /workspace/scripts/compose_restart_reuse.py prepare
docker compose restart backend worker
docker compose up -d --wait backend
docker compose run --rm -v "$PWD/backend:/workspace" backend python /workspace/scripts/compose_restart_reuse.py verify
