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

## Authentication (Step 3.7)

- Authentication uses email/password, Argon2id hashes, and short-lived HS256
  access JWTs in an HttpOnly cookie. Tokens and hashes never appear in API bodies.
- Each authenticated request reloads the User and active Organization. Persisted
  roles (`analyst`, `mapping_admin`, `admin`) are authoritative; role dependencies
  use explicit allowed sets. Frontend visibility is not authorization.
- Future queries must derive tenant identity from the authenticated User, not a
  client-supplied organization ID. Product mutations must preserve CSRF protection.
  SameSite=Lax is the current default; cross-site workflows need deliberate CSRF
  design before enabling them.
- Cookie name, Secure, SameSite, and path are environment-driven. Production
  HTTPS requires AUTH_COOKIE_SECURE=true. SameSite=None requires Secure.
- Login passwords are accepted intact up to 1024 characters and never truncated.
- Logout clears the cookie; copied access tokens expire naturally. There are no
  refresh tokens or server-side revocation records in Step 3.7.
- No public registration exists. Initial identities require the explicit command
  below; it never executes during import, startup, Docker startup, or migrations.

From `backend/`, with its virtual environment active and the usual environment
variables exported (including POSTGRES_PASSWORD and JWT_SECRET):

```powershell
python -m app.cli.bootstrap_admin --organization-name "Example Organization" --organization-slug example-org --email admin@example.invalid
```

The command prompts twice for a hidden password. It creates the Organization and
Admin in one transaction, rejects duplicate email/slug, and never overwrites or
elevates an existing identity. It requires a terminal supporting hidden input.
On the host, set POSTGRES_HOST=localhost and POSTGRES_PORT=5433; containers use
postgres:5432. Settings do not automatically load a .env file for host commands.

Normal `python -m pytest -v` tests do not require PostgreSQL. With development DB
settings exported, opt in to the real-DB check using SIH_AUTH_POSTGRES_TEST=1 and
`python -m pytest -v tests/integration/test_auth_postgres.py`. It requires head
20260906_0004 and rolls back all temporary identities in an outer transaction.

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
