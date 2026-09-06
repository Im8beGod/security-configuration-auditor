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
