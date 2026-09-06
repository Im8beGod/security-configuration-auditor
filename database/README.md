# Database

The project uses PostgreSQL with JSONB support.

Step 2 establishes database infrastructure only.

Domain tables for Artifact, Device, Snapshot, Audit, SecurityFact,
EffectiveState, Finding, Mapping, Report, and later supporting entities
will be implemented in later steps according to the frozen contracts.

Directories:

- migrations/ — future database migrations
- init/ — safe database initialization resources if required

No production domain schema is implemented in Step 2.
