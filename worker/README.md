# SIH 26155 Worker

The worker is a persistent PostgreSQL-backed runtime for long-running audit,
re-evaluation, mapping-validation, PDF-generation, and bulk-report work.
Business and domain logic remains in the backend modules; handlers invoke those
services rather than duplicating parsing, interpretation, compliance, findings,
or reporting logic.

Each polling iteration uses a fresh Session and a short claim transaction.
Claims are restricted to registered handler types before row locking, so
unsupported jobs remain queued. The worker registers the side-effect-free
system no-op, audit execution, re-evaluation, mapping validation, and PDF
generation handlers. Idle and recoverable database-failure paths respect
`WORKER_POLL_INTERVAL_SECONDS` rather than busy-spinning.

The process handles Docker SIGTERM and Ctrl+C gracefully and never runs
migrations. It has no automatic retry mechanism, scheduler, broker, or dynamic
payload execution. Handler failures are recorded as controlled job failures.

This is a prototype worker, not production-grade high availability. A hard
worker/process failure after a job enters PROCESSING can require manual
operational recovery.
