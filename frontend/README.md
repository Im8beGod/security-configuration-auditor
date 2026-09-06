# SIH 26155 Frontend

The React application uses centralized React Router and TanStack Query providers.
Authenticated routes share an application shell with primary navigation, current
user identity, and logout. Dashboard, Devices, Audits, Findings, and Reports are
available to all authenticated roles. Training navigation and its frontend route
guard are limited to `mapping_admin` and `admin`; backend authorization remains
authoritative.

Browser API requests use `VITE_API_BASE_URL`, which defaults locally to
`http://localhost:8000/api/v1`. The shared native-fetch client always includes
credentials so the browser can manage the backend's HttpOnly authentication cookie.
Tokens and query data are not persisted in browser storage.

On startup and refresh, `/auth/me` rehydrates the session through the HttpOnly
cookie. Login updates the current-user query, while logout clears authenticated
query data and returns to `/login`.

## Step 4D Workflow

The authenticated browser workflow now supports:

```text
Upload evidence -> Device -> draft Snapshot -> finalize -> Audit -> run -> Job status
```

`/uploads` handles bulk uploads and mixed per-file results. `/devices` and
`/devices/:deviceId` manage logical assets and draft Snapshots, while
`/snapshots/:snapshotId` provides refresh-safe Artifact membership and lifecycle
actions. `/audits` and `/audits/:auditId` expose draft submission and poll queued
Job status every five seconds while active.

Draft Snapshot membership is editable. A ready Snapshot can create an Audit, and
running that Audit locks the Snapshot; new evidence then requires a new Snapshot.
The current worker intentionally leaves `audit` Jobs queued until Step 5 provides
real processing. The frontend does not simulate progress or display vendor,
compliance, finding, remediation, or report results.
