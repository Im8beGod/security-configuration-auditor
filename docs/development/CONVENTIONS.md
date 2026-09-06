# Development Conventions

## Architecture

SIH 26155 uses a modular monolith with one background worker boundary.

Module boundaries must remain explicit.

Do not mix parsing, semantic interpretation, effective-state resolution,
compliance evaluation, findings, remediation, or reporting responsibilities.

## Backend

- Python uses snake_case.
- FastAPI handles request/API responsibilities.
- Domain logic belongs in domain modules.
- Worker code must reuse backend/domain services rather than duplicate logic.
- Database models, domain models, and API models should remain separate where practical.

## Frontend

- React uses TypeScript.
- Features belong under src/features.
- Shared reusable code belongs under src/shared.
- Backend/domain business logic must not be placed in the frontend.

## Security

- Uploaded network evidence is untrusted input.
- Secrets and real environment files must never be committed.
- Runtime artifacts and generated reports must not be committed.
- Raw evidence must eventually be preserved immutably.

## Frozen Principles

- One Audit evaluates one Snapshot.
- Historical audits and reports are immutable.
- SecurityFact and EffectiveState remain separate.
- Compliance evaluates EffectiveState.
- Finding is the canonical stored compliance result.
- UNKNOWN must never silently become PASS.
- Interpretation mappings and remediation procedures are separate.
- AI cannot self-publish mappings or determine trusted final compliance verdicts.

## Implementation Discipline

Implement only the current implementation step.

Avoid premature infrastructure such as:

- microservice proliferation
- Kubernetes
- Kafka
- arbitrary user Python
- autonomous remediation
- unnecessary databases
