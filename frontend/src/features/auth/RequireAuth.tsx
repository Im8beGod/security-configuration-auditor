import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { useCurrentUser } from './authState'

export function RequireAuth() {
  const currentUser = useCurrentUser()
  const location = useLocation()

  if (currentUser.isPending) {
    return (
      <main className="state-panel state-panel-loading" aria-live="polite">
        <span className="eyebrow">Secure workspace</span>
        <p>Checking your session…</p>
      </main>
    )
  }
  if (currentUser.isError) {
    return (
      <main className="state-panel state-panel-error">
        <span className="eyebrow">Authentication boundary</span>
        <h1>Session unavailable</h1>
        <p>We could not verify your session. Please try again.</p>
        <button className="button-primary" type="button" onClick={() => void currentUser.refetch()}>
          Try again
        </button>
      </main>
    )
  }
  if (currentUser.data === null) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <Outlet context={currentUser.data} />
}
