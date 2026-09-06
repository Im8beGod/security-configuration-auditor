# Project Tests

Backend tests live primarily under:

backend/tests/

This top-level directory is reserved for future repository-wide, deployment,
and end-to-end testing.

The backend suite contains deterministic unit tests plus opt-in PostgreSQL
integration tests for authentication, persistence constraints, durable-job
concurrency, and worker lifecycle behavior. CI enables all PostgreSQL
integration tests after migrating an empty PostgreSQL 17 service to Alembic
head `20260906_0004`.

From `backend/`, normal tests run with:

    python -m pytest -v

The frontend is verified from `frontend/` with:

    npm ci
    npm run build
    npm run lint
