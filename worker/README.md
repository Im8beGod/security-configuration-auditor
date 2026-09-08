# SIH 26155 Worker

This directory represents the deployment boundary for the background worker.

The worker will eventually execute long-running tasks such as:

- audits
- re-evaluations
- mapping validation
- PDF generation
- bulk report generation

Business/domain logic must remain inside the backend domain modules.

The worker must call those services rather than duplicate parsing, interpretation,
effective-state, compliance, findings, or reporting logic.

The worker is now a persistent runtime backed by the PostgreSQL durable `jobs`
queue. Each polling iteration uses a fresh Session and short claim transaction.
Claims are filtered to explicitly registered handler types before row locking, so
unsupported jobs remain queued. Idle and recoverable database-failure paths wait
for `WORKER_POLL_INTERVAL_SECONDS` rather than busy-spinning.

The process handles Docker SIGTERM and Ctrl+C cleanly. It never runs migrations.
The production runtime registers the side-effect-free `SYSTEM_NOOP` handler,
the mapping-validation, PDF-generation, and re-evaluation handlers, and the
real `AuditJobHandler` adapter around the domain pipeline. The runtime constructs
the audit handler with the configured session factory and artifact storage;
business logic remains in the backend domain modules.

The worker still has no automatic retry mechanism, scheduler, broker, or
dynamic payload execution. A successfully claimed Job is completed only after
its registered handler returns successfully; handler failures are recorded as
controlled job failures.
