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

### Step 4A Artifact ingestion

Authenticated clients can upload one evidence file with
`POST /api/v1/artifacts/upload`, upload multiple files with
`POST /api/v1/artifacts/bulk-upload`, and retrieve tenant-owned metadata with
`GET /api/v1/artifacts/{artifact_id}`. Multipart fields are named `file` for the
single endpoint and `files` for bulk.

The initial validator accepts UTF-8 text, JSON, and XML. JSON and XML must be
well-formed; XML DTD/entity declarations and binary input are rejected. Unknown
vendor syntax in valid text is accepted and conservatively classified. This stage
does not identify vendors, resolve profiles, interpret semantics, or evaluate
compliance. Bulk responses report each filename's success or controlled failure,
so one rejected file does not roll back successful siblings.

Defaults are 10 MiB per file (`ARTIFACT_MAX_UPLOAD_BYTES=10485760`) and 20 files
per bulk request (`ARTIFACT_MAX_BULK_FILES=20`).

### Step 4B Device and Snapshot workflow

A Device is a persistent logical asset identity, not a container for historical
configuration, software, or vendor truth. Authenticated organization-scoped APIs
support creating, listing, retrieving, and patching Device identity metadata:

- `POST /api/v1/devices`
- `GET /api/v1/devices`
- `GET|PATCH /api/v1/devices/{device_id}`

A Snapshot is the complete supplied Artifact evidence set for one Device at one
point. Draft Snapshots can be created and inspected through:

- `POST|GET /api/v1/devices/{device_id}/snapshots`
- `GET|PATCH /api/v1/snapshots/{snapshot_id}`
- `POST|DELETE /api/v1/snapshots/{snapshot_id}/artifacts/{artifact_id}`
- `POST /api/v1/snapshots/{snapshot_id}/finalize`

Membership edits are atomic and draft-only. `artifact_count` is recomputed from
membership, and `snapshot_hash` is SHA-256 over the direct concatenation of the
lexicographically sorted, fixed-length member Artifact SHA-256 values. The empty
draft uses SHA-256 of empty bytes. Finalization requires at least one safely
validated Artifact and moves the Snapshot from `draft` to `ready`; ready, locked,
and archived Snapshots are read-only. Unknown evidence remains eligible when it
was safely ingested. Tenant IDs, creator IDs, lifecycle status, counts, and hashes
are backend-authoritative.

Step 4B performs no vendor interpretation. Step 4C activates Audit creation and
the transition that locks a Snapshot when its first Audit is submitted.

### Step 4C Audit submission

The implemented backend workflow now reaches durable Audit submission:

```text
Upload -> Device -> Snapshot -> Audit -> queued PostgreSQL Job
```

Authenticated clients create an initial revision with `POST /api/v1/audits`, list
or inspect Audits with `GET /api/v1/audits` and `GET /api/v1/audits/{audit_id}`,
and submit a draft with `POST /api/v1/audits/{audit_id}/run`. Audit creation binds
revision 1 to exactly one ready Snapshot but does not lock it. Starting the Audit
atomically locks that Snapshot, moves the Audit to `queued`, and creates one
durable `audit` Job. New evidence after this point requires a new Snapshot.

Audit responses include a safe associated Job summary when one exists. Job status
is also available from `GET /api/v1/jobs/{job_id}` for the owning tenant. Internal
payloads and unowned/system Jobs are not exposed.

The current production worker intentionally supports only `system_noop`; it does
not claim `audit` Jobs. Consequently, a submitted Audit and its Job truthfully
remain queued with zero attempts until Step 5 provides real identification and
parsing. Queued does not mean evaluated, and Step 4C creates no profiles,
compliance verdicts, findings, or placeholder PASS/FAIL/UNKNOWN results.

### Step 4D Browser workflow

The authenticated React application exposes the complete implemented workflow at
`/uploads`, `/devices`, `/snapshots/:snapshotId`, `/audits`, and
`/audits/:auditId`. Server state is managed with TanStack Query, detail routes
refetch canonical state after refresh, and queued Job status is polled without
simulating progress. The browser clearly distinguishes editable drafts, ready
Snapshots, locked evidence, draft Audits, and queued submissions.

Step 4D adds no audit processor or compliance UI. Queued Audit Jobs remain queued
until Step 5 supplies real vendor identification and parsing.

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
- Step 3 — Basic Platform Skeleton: COMPLETE / FROZEN
- Step 4A — Secure Upload + Artifact Ingestion: IMPLEMENTED
- Step 4B — Device + Snapshot Workflow: IMPLEMENTED
- Step 4C — Audit Creation + Durable Job Orchestration: IMPLEMENTED
- Step 4D — End-User Frontend Workflow: IMPLEMENTED

The current Step 3 skeleton provides Organization/User persistence,
HttpOnly-cookie authentication, backend RBAC roles (`analyst`,
`mapping_admin`, and `admin`), an explicit bootstrap-admin command,
PostgreSQL-backed durable jobs, and a persistent worker. There is no public
registration. The production worker currently handles only the
`SYSTEM_NOOP` job type (persisted as `system_noop`); all real job types
remain queued.

The four local Compose services are `frontend`, `backend`, `worker`, and
`postgres`. Current Alembic head is `20260906_0004`.

Step 4 implements authenticated Artifact ingestion, Device identity, immutable
Snapshot evidence grouping, Audit creation, durable Job submission, and the
browser workflow connecting them. Starting an Audit locks its Snapshot; new
evidence requires a new Snapshot. A queued Audit is only durable pending work,
not an evaluated result.

The application does **not** yet implement real Audit processing, vendor/profile
identification, Cisco parsing, semantic interpretation, Effective State,
compliance evaluation, Findings, remediation, or reports/PDF generation.
