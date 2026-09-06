import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { useCurrentUser } from './authState'

export function RequireAuth() {
  const currentUser = useCurrentUser()
  const location = useLocation()

  if (currentUser.isPending) {
    return (
      <main aria-live="polite">
        <p>Checking your session…</p>
      </main>
    )
  }
  if (currentUser.isError) {
    return (
      <main>
        <h1>Session unavailable</h1>
        <p>We could not verify your session. Please try again.</p>
        <button type="button" onClick={() => void currentUser.refetch()}>
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
