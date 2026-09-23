#!/usr/bin/env bash
set -euo pipefail

# Preserve container mount targets when invoked from Git Bash on Windows.
export MSYS_NO_PATHCONV=1

run_id="${SIH_RESTART_REUSE_RUN_ID:-$(date +%s)}"
export SIH_RESTART_REUSE_RUN_ID="$run_id"

docker compose up -d --wait postgres
docker compose run --rm -v "$PWD/database:/app/database" backend alembic -c /app/database/alembic.ini upgrade head
docker compose up -d --wait --build backend worker
docker compose run --rm -e SIH_RESTART_REUSE_RUN_ID="$SIH_RESTART_REUSE_RUN_ID" -v "$PWD/backend:/app/backend" backend python /app/backend/scripts/compose_restart_reuse.py prepare
docker compose restart backend worker
docker compose up -d --wait backend
echo "services restarted"
docker compose run --rm -e SIH_RESTART_REUSE_RUN_ID="$SIH_RESTART_REUSE_RUN_ID" -v "$PWD/backend:/app/backend" backend python /app/backend/scripts/compose_restart_reuse.py verify
