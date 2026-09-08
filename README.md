# AI-Driven Multi-Vendor Network Security Compliance Auditor

SIH 26155 is a bounded, evidence-first auditor for Cisco IOS XE 17.x and
Fortinet FortiOS 7.x configuration evidence. It preserves supplied evidence,
normalizes vendor meaning into shared security semantics, and produces
deterministic, reviewable compliance results.

## Product Flow

```text
Configuration
-> vendor/profile detection
-> structural parsing
-> canonical SecurityFacts
-> EffectiveState
-> deterministic compliance
-> Findings/Evidence
-> remediation/reporting
```

Supported vendor readers are `indentation_cli.v1` for Cisco IOS XE and
`fortios_cli.v1` for FortiOS. Both feed the same canonical facts, effective
state, compliance engine, findings model, and report format.

## Capabilities

- Single-file and multi-file evidence upload
- True multi-device batch auditing through `POST /api/v1/audits/batch`
- Cisco IOS XE 17.x and FortiOS 7.x profile-aware processing
- PASS, FAIL, and UNKNOWN verdicts with severity, evidence, and provenance
- Findings mapped to selected NIST SP 800-53 Rev. 5 controls
- Supervised Review Center for unresolved syntax and low-code mappings
- Persistent immutable Knowledge Packs and validated publication workflow
- Historical re-evaluation using the same evidence and a new immutable revision
- Per-device PDF reports with identity and hardware details
- Reviewed Cisco remediation preview catalog for SSH v2, remote logging, and NTP

Snapshots, Artifacts, and Audit revisions are immutable at their respective
lifecycle boundaries. Batch submission is stateless and returns per-device
accepted or rejected results without introducing a persistent Batch model.

## AI and Compliance Boundaries

An AI suggestion interface exists for optional mapping assistance. Suggestions
are advisory, the production AI provider is not currently configured, and the
deterministic manual workflow works without AI. AI never determines PASS,
FAIL, or UNKNOWN.

Findings are **mapped to selected NIST SP 800-53 Rev. 5 controls**. This is a
traceability mapping, not a claim of NIST compliance, certification, or full
coverage. CIS, DISA STIG, and ISO mapping packs are not currently implemented.

Reviewed Cisco procedures currently cover:

- SSH v2
- Remote logging host
- NTP server

FortiOS remediation is deliberately unavailable pending publication of a
reviewed procedure catalog. No remediation command is executed by the system.

## Repository Layout

- `backend/` - FastAPI application, domain services, worker handlers, and tests
- `frontend/` - React and TypeScript application
- `database/` - Alembic configuration and migrations
- `storage/` - local development artifact and report mounts
- `docs/` - architecture, demo, presentation, and development notes
- `docker-compose.yml` - local backend, worker, frontend, and PostgreSQL stack

## Setup

Prerequisites: Python 3.13+, Node.js/npm, Docker Desktop, Docker Compose, and
Git.

```powershell
Copy-Item .env.example .env
# Replace development-only password and JWT values in .env.
docker compose config --quiet
docker compose up -d --build
docker compose run --rm backend alembic -c database/alembic.ini upgrade head
```

The frontend is available at `http://localhost:5173`; the API is available at
`http://localhost:8000`, with health check `GET /health`. PostgreSQL is
available to Compose services as `postgres:5432` and from the host as port
`5433` by default.

## Backend Development

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest tests/unit -q
uvicorn app.main:app --reload
```

## Frontend Development

```powershell
cd frontend
npm ci
npm run build
npm run lint
npm run dev
```

## Migrations and Verification

The current Alembic head is `20260908_0011`. Apply migrations explicitly; the
backend and worker do not migrate the database automatically.

```powershell
alembic -c database/alembic.ini heads
alembic -c database/alembic.ini current
python -m compileall backend/app backend/tests
git diff --check
```

Focused backend tests cover profile resolution, both vendor readers, the
deterministic compliance path, Review Center publication, remediation preview,
reporting, re-evaluation, and the multi-device batch boundary. PostgreSQL
integration tests are opt-in and document their required environment flags in
the test files.

## Demo Quick Start

1. Start the Compose stack and apply migration head as shown above.
2. Sign in with a bootstrapped administrator account.
3. Upload Cisco and FortiOS configuration evidence and create one Snapshot per
   device.
4. Submit the two snapshots through the batch audit endpoint or the existing
   audit workflow.
5. Review PASS/FAIL/UNKNOWN findings, evidence, selected NIST mappings, and
   the reviewed Cisco remediation preview.
6. Open Review Center for unresolved syntax, publish only after validation and
   administrator approval, then explicitly re-evaluate to create a new
   immutable revision.
7. Generate the per-device PDF report and show identity, hardware, findings,
   and evidence.

See [the demo script](docs/demo/DEMO_SCRIPT.md) and [the five-slide content](docs/presentation/SIH_5_SLIDE_CONTENT.md).

## Security Notes

All API reads and writes are organization-scoped. Evidence and report storage
is protected, internal job payloads are not exposed through the public API, and
real `.env` files, secrets, uploaded artifacts, reports, caches, and database
dumps must never be committed.
