# Production VM Deployment

The production topology is isolated in `deploy/compose.production.yml`. Caddy
serves the built React SPA, proxies `/api/v1/*` and `/health` to the backend,
and is the only public service. The API, worker, and PostgreSQL remain on the
private Compose network; PostgreSQL has no host port mapping.

## First release

On the Linux VM, copy `deploy/production.env.example` to a protected file such
as `/etc/sih26155/production.env`, set a real DNS `DOMAIN`, generate strong
`POSTGRES_PASSWORD` and 32+-character `JWT_SECRET` values, and restrict the
file to the deployment operator. Do not commit the populated file. Public TLS
requires the DNS name to point at the VM with ports 80 and 443 reachable;
Ollama is optional and core auditing runs with AI suggestions disabled.

From the repository root:

```sh
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml build
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml up -d postgres
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml run --rm migrate
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml up -d backend worker frontend
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml ps
```

The `migrate` command is an explicit one-time release step that runs
`alembic upgrade head`; backend and worker never migrate on startup. Confirm
the revision is `20260909_0020` with:

```sh
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml run --rm migrate \
  alembic -c /app/database/alembic.ini current
```

Caddy obtains and renews the certificate after DNS is ready. The browser API
base is built as `/api/v1`, so it never embeds a visitor-localhost URL. Verify
`https://DOMAIN/health`, the SPA response, and that `docker compose ... ps`
shows PostgreSQL and backend healthy with the worker running.

## Backup and restore

Create a database dump and a storage archive before upgrades:

```sh
mkdir -p backups
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml exec -T postgres \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  > backups/security_auditor-$(date +%Y%m%d-%H%M%S).dump
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml exec -T backend \
  tar czf - -C /app/storage . > backups/storage-$(date +%Y%m%d-%H%M%S).tgz
```

For a local restore, stop API/worker first, restore the database into the
PostgreSQL service, and restore the matching storage archive into the shared
storage volume:

```sh
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml stop backend worker frontend
cat backups/security_auditor.dump | docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml exec -T postgres \
  sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists'
cat backups/storage.tgz | docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml run --rm -T backend \
  tar xzf - -C /app/storage
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml run --rm migrate
docker compose --env-file /etc/sih26155/production.env \
  -f deploy/compose.production.yml up -d backend worker frontend
```

The named `postgres_data`, `app_storage`, `caddy_data`, and `caddy_config`
volumes survive container recreation. PostgreSQL has no host port mapping;
only Caddy publishes 80 and 443.

## Upgrades and shutdown

Before an upgrade, take the database and shared-storage backups above. Build
the new images, start PostgreSQL, run the explicit `migrate` step, then
recreate backend, worker, and frontend. Stop the deployment with `docker
compose ... stop`; use `down` only when removing containers while retaining
named volumes. Do not use `down -v` unless deliberately discarding the
database, artifacts, reports, and Caddy state.

The worker uses `FOR UPDATE SKIP LOCKED` claims, lease ownership, and
heartbeats. An expired PROCESSING job fails deterministically; jobs are never
automatically retried, requeued, or replayed. Remediation remains reviewed
guidance/preview only—this deployment never sends commands to network devices.

This procedure validates a production-like local Compose deployment, not a
public deployment or HA/exactly-once execution guarantee.
