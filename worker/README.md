# SIH 26155 Worker

The worker is a persistent PostgreSQL-backed runtime for long-running audit,
re-evaluation, mapping-validation, PDF-generation, and bulk-report work.
Business and domain logic remains in the backend modules; handlers invoke those
services rather than duplicating parsing, interpretation, compliance, findings,
or reporting logic.

Each polling iteration uses a fresh Session and a short PostgreSQL claim
transaction with `FOR UPDATE SKIP LOCKED`. Claims are restricted to registered
handler types before row locking, so unsupported jobs remain queued. A claim
receives a lease owner and periodic heartbeat; expired PROCESSING jobs are
deterministically marked FAILED before new claims. The worker registers the
side-effect-free system no-op, audit execution, re-evaluation, mapping
validation, and PDF generation handlers. Idle and recoverable database-failure
paths respect `WORKER_POLL_INTERVAL_SECONDS` rather than busy-spinning.

The process handles Docker SIGTERM and Ctrl+C gracefully: it stops claiming
new work while an active handler and its heartbeat finish normally. It never
runs migrations and has no automatic retry, requeue, handler replay,
scheduler, broker, or dynamic payload execution. Handler failures and expired
leases are recorded as controlled job failures.

This is a prototype worker, not production-grade high availability or
exactly-once execution. A hard crash is recovered through lease expiry, but
the interrupted handler is not automatically replayed.
