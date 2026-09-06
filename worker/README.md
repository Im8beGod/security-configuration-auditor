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
The only registered production handler is `SYSTEM_NOOP` (persisted as
`system_noop`), a side-effect-free infrastructure check that ignores its payload.
Step 5 also provides a real, thin `AuditJobHandler` adapter around the domain
pipeline, but deliberately does not register it. The current worker contract
automatically completes every successfully handled Job, while Step 5 must leave
the canonical Audit nonterminal at `interpreting`; the Job has no stage-target or
resumable-checkpoint contract that could represent that boundary truthfully.

Audit Jobs therefore remain queued and unclaimed until a later pipeline batch can
complete the canonical Audit lifecycle without fabricating compliance. There is
no automatic retry mechanism, scheduler, broker, or dynamic payload execution.
