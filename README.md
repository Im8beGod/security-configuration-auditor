# L.O.G.O.S. — Network Security Compliance Auditor

L.O.G.O.S. is an evidence-first platform for reviewing bounded network-device
configuration evidence. It normalizes supplied configurations into traceable,
deterministic compliance findings with persisted evidence, reviewed
remediation guidance, and PDF reporting.

This repository is the SIH26155 project context for the L.O.G.O.S. evaluator
demo. SIH26155 is not the product name.

## What L.O.G.O.S. does

~~~text
Evidence upload -> Device -> immutable Snapshot -> profile detection
-> structural parsing -> semantic interpretation -> SecurityFacts
-> EffectiveState -> deterministic compliance -> Findings + Evidence
-> reviewed remediation guidance -> PDF report -> Fleet Dashboard
~~~

PASS, FAIL, and UNKNOWN verdicts come from the deterministic compliance engine
using persisted evidence and effective state. AI does not decide a verdict,
approve a mapping, or publish knowledge. Evidence, finalized Snapshots, Audit
revisions, and published Knowledge Pack versions are immutable at their
lifecycle boundaries.

## Prerequisites

For the evaluator flow, install:

- Windows 10/11 with PowerShell
- Git
- Docker Desktop with Docker Compose v2 enabled

The evaluator flow runs the backend, worker, PostgreSQL, and frontend in
containers. Node.js and Python are only needed for optional native development
outside Docker.

## Fresh-machine setup (Windows PowerShell)

Run these steps from PowerShell. Replace the example identity values with the
credentials you want to use for the demo.

### 1. Clone the repository

~~~powershell
git clone https://github.com/Im8beGod/security-configuration-auditor.git
Set-Location security-configuration-auditor
~~~

### 2. Create the environment file

~~~powershell
Copy-Item .env.example .env
notepad .env
~~~

At minimum, replace these values in .env:

- POSTGRES_PASSWORD: a strong local PostgreSQL password. It is used when the
  PostgreSQL data volume is initialized and is shared by the Compose services.
- JWT_SECRET: a long, random signing secret for login tokens. Never commit
  .env or reuse this value outside the local deployment.

Keep the local defaults for POSTGRES_HOST=postgres, POSTGRES_PORT=5432,
BACKEND_PORT=8000, FRONTEND_PORT=5173, and VITE_API_BASE_URL unless your
machine already uses those host ports.

### 3. Validate the Compose file

~~~powershell
docker compose config --quiet
~~~

No output and exit code 0 means the rendered Compose configuration is valid.

### 4. Start PostgreSQL

~~~powershell
docker compose up -d postgres
docker compose ps postgres
~~~

Wait until the postgres service reports healthy.

### 5. Apply all database migrations

The backend and worker do not migrate automatically. Run the repository's
Alembic configuration through the backend image:

~~~powershell
docker compose run --rm backend alembic -c database/alembic.ini upgrade head
~~~

### 6. Create the first administrator

The command prompts for the password twice without echoing it:

~~~powershell
docker compose run --rm backend python -m app.cli.bootstrap_admin --organization-name "L.O.G.O.S. Demo" --organization-slug logos-demo --email admin@example.com
~~~

Use the same email and password at the login screen. The organization slug and
email must be unique in the database.

### 7. Start all services

~~~powershell
docker compose up -d --build
docker compose ps
~~~

Compose starts PostgreSQL, the FastAPI backend, the durable worker, and the
React frontend. The backend and frontend services have health checks.

### 8. Verify backend and frontend health

~~~powershell
(Invoke-WebRequest -UseBasicParsing http://localhost:8000/health).Content
(Invoke-WebRequest -UseBasicParsing http://localhost:5173/).StatusCode
~~~

The backend response should contain {"status":"healthy"} and the frontend
request should return HTTP status 200.

### 9. Open and sign in

Open http://localhost:5173 and sign in with the administrator created above.

## Database reset and credential changes

To remove the PostgreSQL volume and rebuild the local stack from an empty
database:

~~~powershell
docker compose down -v --remove-orphans
docker compose up -d postgres
docker compose run --rm backend alembic -c database/alembic.ini upgrade head
docker compose run --rm backend python -m app.cli.bootstrap_admin --organization-name "L.O.G.O.S. Demo" --organization-slug logos-demo --email admin@example.com
docker compose up -d --build
~~~

The -v flag permanently removes the Compose PostgreSQL volume and its data.
Changing POSTGRES_PASSWORD after that volume has already been initialized
does not change the password stored inside PostgreSQL. Either restore the
original value in .env, reconcile the database password manually, or use the
reset above for a clean local deployment.

## Quick evaluator demo

After signing in:

1. Open **Upload / Evidence** and upload the files in demo/configurations/.
2. Create a Device and an evidence Snapshot for each supplied vendor sample.
3. Finalize the Snapshot, open **Audits**, select at least two ready Snapshots,
   and choose the applicable framework or Assessment Pack.
4. Run the audits, then review the dashboard posture, findings, persisted
   evidence, reviewed remediation preview, and PDF report.
5. Optionally upload unknown-vendor.cfg, open the Mapping Review area, create
   a bounded mapping, validate it against evidence, approve it, publish it, and
   re-evaluate the same evidence.

The supplied samples are safe local text fixtures. Do not upload production
secrets or live credentials.

## Supported scope

### Vendors and readers

- Cisco IOS XE 17.x
- Fortinet FortiOS 7.x
- Juniper Junos 18.x XML onboarding
- Arista EOS 4.x
- Generic CLI ingestion for administrator-supervised training

Coverage is profile- and version-bounded. This is not universal support for
every vendor, platform, or release.

### Assessment frameworks

- NIST SP 800-53 Rev. 5
- DISA Network Device Management SRG
- CIS Cisco IOS XE 17.x Benchmark v2.2.1
- ISO/IEC 27001:2022 technical alignment derived through NIST OLIR

These are scoped technical subsets or alignment packs. L.O.G.O.S. does not
provide NIST, DISA, STIG, CIS, or ISO certification, CIS-CAT equivalence, full
framework coverage, universal compliance, or ISO conformity assessment.

## Optional local Ollama assistance

Ollama is optional and disabled by default. Auditing and the evaluator demo do
not require it. When enabled, it provides advisory mapping suggestions only;
there is no cloud fallback, automatic approval, or verdict authority.

Set these values in .env only when a local Ollama service and the configured
model are available:

~~~dotenv
AI_MAPPING_SUGGESTIONS_ENABLED=true
AI_MAPPING_PROVIDER=ollama
AI_OLLAMA_BASE_URL=http://host.docker.internal:11434
AI_OLLAMA_MODEL=qwen2.5-coder:7b-instruct-q4_K_M
~~~

## Remediation safety boundary

Remediation is reviewed guidance and preview only. L.O.G.O.S. never executes
device commands and never autonomously modifies device configurations.

## Technology and repository structure

FastAPI and Python, PostgreSQL with Alembic, a PostgreSQL-backed worker,
React/TypeScript, Docker Compose, and local artifact/report storage.

- backend/ — FastAPI application, domain services, tests, and fixtures
- frontend/ — React and TypeScript application
- database/ — Alembic configuration and migrations
- worker/ — PostgreSQL durable-job worker runtime
- demo/configurations/ — safe evaluator configuration samples
- docs/ — architecture and demonstration material
- storage/ — local artifact and report mounts

## Migration and verification commands

The current Alembic head is 20260924_0027:

~~~powershell
docker compose run --rm backend alembic -c database/alembic.ini heads
docker compose run --rm backend alembic -c database/alembic.ini current
docker compose run --rm backend alembic -c database/alembic.ini check
git diff --check
~~~

Real .env files, secrets, uploaded artifacts, reports, caches, database
dumps, and runtime storage must never be committed.
