# SIH 26155

## AI-Driven Multi-Vendor Network Security Compliance Auditor

SIH 26155 is an evidence-first competition prototype for reviewing bounded
network-device configuration evidence. It turns supplied configurations into
traceable, deterministic findings—not an automated device-management system.

## Problem

Configuration reviews are often vendor-specific, difficult to reproduce, and
hard to connect to evidence. This prototype preserves the submitted evidence,
normalizes its security meaning, and makes each result reviewable.

## What the prototype does

```text
Evidence upload -> Device -> immutable Snapshot -> profile detection
-> structural parsing -> semantic interpretation -> SecurityFacts
-> EffectiveState -> deterministic compliance -> Findings + Evidence
-> reviewed remediation guidance -> PDF report -> Fleet Dashboard
```

The advanced extension uses a declarative `ProfileManifest`, a generic XML
structural reader, low-code mappings, executable validation, human approval,
and immutable Knowledge Packs so future audits can reuse reviewed knowledge.

## Architecture and trust boundary

PASS, FAIL, and UNKNOWN verdicts are produced by the deterministic compliance
engine from persisted evidence and effective state. AI does not decide a
verdict, approve a mapping, or publish knowledge. Evidence, finalized
Snapshots, Audit revisions, and published Knowledge Pack versions are
immutable at their lifecycle boundaries.

## Prototype-supported vendors

- Cisco IOS XE 17.x
- Fortinet FortiOS 7.x
- Juniper Junos 18.x XML onboarding

Coverage is intentionally profile- and version-bounded; this is not universal
support for every vendor or release.

## Assessment frameworks

Implemented AssessmentPacks provide scoped technical prototype coverage for:

- NIST SP 800-53 Rev. 5
- DISA Network Device Management SRG
- CIS Cisco IOS XE 17.x Benchmark v2.2.1
- ISO/IEC 27001:2022 technical alignment derived through NIST OLIR

NIST, DISA, and CIS packs are scoped technical subsets. ISO material is
technical alignment only.

## Key features

- Single- and multi-file evidence upload with device and immutable Snapshot records
- Profile-aware multi-vendor normalization into shared SecurityFacts and EffectiveState
- Deterministic PASS, FAIL, and UNKNOWN findings with persisted evidence and provenance
- Reviewed, preview-only remediation guidance across Cisco, FortiOS, and Junos
- PDF reporting and a fleet dashboard
- Low-code mapping, validation, approval, immutable Knowledge Packs, and historical re-evaluation

## AI safety boundary

Optional local Ollama integration provides mapping suggestions only. There is
no cloud fallback, no automatic approval, and auditing continues without AI.

## Remediation safety boundary

Remediation is reviewed guidance and preview only. The system never executes
device commands and never autonomously modifies device configurations.

## Technology stack

FastAPI and Python, PostgreSQL with Alembic, a PostgreSQL-backed worker,
React/TypeScript, Docker Compose, and local artifact/report storage.

## Quick start

Prerequisites: Python 3.13+, Node.js/npm, Docker Desktop, Docker Compose, and Git.

```powershell
Copy-Item .env.example .env
# Replace development-only placeholders in .env.
docker compose config --quiet
docker compose up -d --build
docker compose run --rm backend alembic -c database/alembic.ini upgrade head
```

The frontend is available at `http://localhost:5173`; the API is at
`http://localhost:8000` (`GET /health`).

## 3-5 minute demo

1. Sign in and open the Fleet Dashboard.
2. Upload the approved Cisco IOS XE development fixture at
   `backend/tests/fixtures/cisco_ios_xe/representative.cfg`; create or confirm
   its Device and Snapshot.
3. Select an applicable AssessmentPack and run the audit.
4. Open a FAIL or UNKNOWN finding to show persisted evidence, then open the
   reviewed remediation preview.
5. Generate the PDF report and return to the Fleet Dashboard.

Use [the demo runbook](docs/demo-runbook.md) for judge narration.

## Repository structure

- `backend/` — FastAPI application, domain services, tests, and fixtures
- `frontend/` — React and TypeScript application
- `database/` — Alembic configuration and migrations
- `worker/` — PostgreSQL durable-job worker runtime
- `docs/` — architecture and demonstration material
- `storage/` — local development artifact and report mounts

## Known limitations

- Framework coverage is a prototype subset, not certification.
- There is no public/cloud production deployment in this repository.
- Vendor and version coverage is intentionally bounded.
- Local AI assistance is optional and advisory only.
- The persistent PostgreSQL worker provides durable jobs, transactional
  claiming with `FOR UPDATE SKIP LOCKED`, explicit handlers, bounded failure
  metadata, graceful shutdown, and no automatic retries. A hard worker/process
  failure after a job enters PROCESSING can require manual operational recovery.

## Prototype and non-certification disclaimer

This prototype does not provide NIST, DISA, STIG, CIS, or ISO certification;
does not provide CIS-CAT equivalence; and does not claim full framework
coverage, universal compliance, or ISO conformity assessment.

## Migration and verification

The final Alembic head is `20260909_0018`. The backend and worker never apply
migrations automatically.

```powershell
docker compose run --rm backend alembic -c database/alembic.ini heads
docker compose run --rm backend alembic -c database/alembic.ini current
docker compose run --rm backend alembic -c database/alembic.ini check
git diff --check
```

Real `.env` files, secrets, uploaded artifacts, reports, caches, database
dumps, and runtime storage must never be committed.
