# Database

The project uses PostgreSQL with JSONB support. Alembic is the authoritative
schema-evolution mechanism; application startup must not create or migrate
schema automatically.

From the repository root, use the containerized toolchain:

```powershell
docker compose run --rm backend alembic -c database/alembic.ini upgrade head
docker compose run --rm backend alembic -c database/alembic.ini current
```

Migration scripts live in `database/migrations/`. The final migration head is
`20260909_0018`.

`Device` stores logical identity. An immutable `Snapshot` is the complete
evidence boundary for one device at one point in time; an `Artifact` can remain
unassigned until grouped into a Snapshot. Each `Audit` evaluates one Snapshot,
and `(snapshot_id, revision_number)` is unique. SecurityFacts, EffectiveState,
findings, evidence, reports, and Knowledge Pack provenance preserve the
reviewable audit trail.

Durable job coordination uses the PostgreSQL `jobs` table. Consumers claim the
oldest eligible queued row inside a short caller-owned transaction using
`FOR UPDATE SKIP LOCKED`; `attempt_count` increments once per claim. Registered
handlers cover audit execution, re-evaluation, mapping validation, PDF
generation, and the side-effect-free system no-op. Unsupported types remain
queued. There are no automatic retries, broker services, schedulers, or dynamic
payload execution.

The worker handles graceful shutdown, but it is not high-availability queue
infrastructure: a hard worker/process failure after a job enters PROCESSING can
require manual operational recovery.

## Deferred technical debt

`alembic check` currently reports two known pre-B12 metadata differences:

- the `profile_manifest_versions.organization_id` index
- the `profile_resolution_decisions.snapshot_id` foreign-key delete metadata
  difference (`RESTRICT` in the migration versus `CASCADE` in model metadata)

They are intentionally deferred for this prototype; no migration beyond
`20260909_0018` is created for them. CI permits only these documented
differences and continues to fail for an unexpected migration-drift report.

Directories:

- `migrations/` — Alembic environment and explicit migration revisions
- `init/` — safe database initialization resources when required
