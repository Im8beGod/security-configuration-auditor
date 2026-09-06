# Database

The project uses PostgreSQL with JSONB support. Alembic is the authoritative
schema-evolution mechanism; the application must not create or migrate schema
automatically during startup.

From the repository root, with the backend virtual environment active, run:

```powershell
alembic -c database/alembic.ini upgrade head
```

Migration scripts live in `database/migrations/`. New schema changes must be
implemented as explicit Alembic revisions. The baseline revision is
intentionally empty because it predates all application ORM models.
The current migration head is `20260906_0004`.

The first application tables are `organizations` and `users`. Every user
belongs to exactly one organization. User email addresses are globally unique
for the planned email/password login model, and only password hashes are
stored. Persisted roles are `analyst`, `mapping_admin`, and `admin`.

`Device` stores logical identity only; historical OS, profile, and configuration
truth belongs to evidence processing. `Snapshot` is the complete evidence
boundary for one device at one point in time. An `Artifact` may remain
unassigned until it is grouped into a Snapshot. Each `Audit` evaluates exactly
one Snapshot, and `(snapshot_id, revision_number)` is unique.

These models are persistence skeletons only. Snapshot locking, artifact
grouping, audit execution, and other workflows begin in later implementation
steps.

Durable job coordination uses the PostgreSQL `jobs` table. Queue consumers must
claim the oldest queued row and transition it within one caller-owned transaction
using `FOR UPDATE SKIP LOCKED`; `attempt_count` increments once per claim.
There are no automatic retries. A persistent worker consumes only explicitly
registered types; its sole production handler is currently `SYSTEM_NOOP`
(persisted as `system_noop`), while unsupported real job types remain queued.
Redis, RabbitMQ, Kafka, Celery, and
other broker services are intentionally absent. Job payloads are untrusted
structured input and must never be dynamically executed or used for secrets.

Directories:

- migrations/ — Alembic environment and explicit migration revisions
- init/ — safe database initialization resources if required

No production domain schema exists at the Step 3.4 baseline.
