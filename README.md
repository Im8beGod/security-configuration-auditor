# SIH 26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

Smart India Hackathon Problem Statement 26155.

## Purpose

A centralized, AI-augmented, vendor-agnostic network security compliance
auditor for heterogeneous network-device configuration evidence.

The system will normalize vendor-specific configuration meaning, resolve
effective security state, deterministically evaluate compliance requirements,
preserve evidence and provenance, provide remediation guidance, and generate
auditable reports.

## Architecture

The SIH prototype uses a modular monolith with one background worker system.

Technology baseline:

- React + TypeScript
- Python + FastAPI
- PostgreSQL 17 + JSONB
- SQLAlchemy 2.x + Alembic
- protected filesystem `ArtifactStorage`
- Docker
- Docker Compose

Trusted future processing pipeline:

Raw Configuration
→ Structural IR
→ Semantic Interpretation
→ Canonical Security Facts
→ Effective Security State
→ Deterministic Compliance
→ Findings
→ Reports

AI assists interpretation and adaptation but does not make trusted final
compliance decisions.

## Repository Structure

- backend/ — FastAPI application and domain modules
- frontend/ — React + TypeScript application
- worker/ — background worker deployment boundary
- database/ — migration and initialization structure
- storage/ — runtime artifacts and reports
- docs/ — architecture, contracts and development documentation
- tests/ — future repository-wide tests
- scripts/ — development automation
- .github/ — GitHub Actions workflows

## Prerequisites

- Python 3.13+
- Node.js
- npm
- Git
- Docker Desktop
- Docker Compose
- GitHub CLI

## Backend

From the backend directory:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python -m pytest -v
    uvicorn app.main:app --reload

Health endpoint:

    http://localhost:8000/health

## Frontend

From the frontend directory:

    npm ci
    npm run build
    npm run lint
    npm run dev

Development URL:

    http://localhost:5173

## Docker

Create the local environment file once, then replace the development-only
password and JWT placeholders with values used only on your workstation:

    Copy-Item .env.example .env

Validate, build, and start the four-service development environment:

    docker compose config --quiet
    docker compose build
    docker compose up -d

Apply migrations explicitly after PostgreSQL is healthy. Neither the backend nor
the worker runs migrations automatically:

    docker compose run --rm backend alembic -c database/alembic.ini upgrade head

Inspect service state and logs:

    docker compose ps
    docker compose logs backend worker frontend postgres

Stop containers without deleting the persistent database volume:

    docker compose down

The browser frontend is available at `http://localhost:5173` and calls
`http://localhost:8000/api/v1`. PostgreSQL uses `postgres:5432` inside
Compose and host port `5433`. Backend and worker share the protected
`./storage` bind mount. This Compose configuration is for local development,
not production deployment.

## Environment

Use `.env.example` as the environment template.

Real `.env` files, secrets, uploaded artifacts and generated reports must
never be committed.

## Current Status

- Step 1 — Implementation Contracts: COMPLETE / FROZEN
- Step 2 — Repository Setup: COMPLETE / FROZEN
- Step 3 — Basic Platform Skeleton: IN PROGRESS

The current Step 3 skeleton provides Organization/User persistence,
HttpOnly-cookie authentication, backend RBAC roles (`analyst`,
`mapping_admin`, and `admin`), an explicit bootstrap-admin command,
PostgreSQL-backed durable jobs, and a persistent worker. There is no public
registration. The production worker currently handles only the
`SYSTEM_NOOP` job type (persisted as `system_noop`); all real job types
remain queued.

The four local Compose services are `frontend`, `backend`, `worker`, and
`postgres`. Current Alembic head is `20260906_0004`.

The skeleton does **not** yet implement upload/device/audit workflows, vendor
parsing, EffectiveState resolution, compliance evaluation, findings,
remediation, reports/PDF generation, AI learning workflows, or real dashboard
data.
