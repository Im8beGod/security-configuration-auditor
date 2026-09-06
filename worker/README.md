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

No real background-job implementation exists in Step 2.
