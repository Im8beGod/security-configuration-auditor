import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'

import { ApiError } from '../../shared/api/client'
import { useCurrentUser } from './authState'
import { useLoginMutation } from './useAuthMutations'

function intendedPath(state: unknown): string {
  if (typeof state !== 'object' || state === null || !('from' in state)) {
    return '/dashboard'
  }
  const from = state.from
  if (
    typeof from !== 'object' ||
    from === null ||
    !('pathname' in from) ||
    typeof from.pathname !== 'string' ||
    !from.pathname.startsWith('/') ||
    from.pathname.startsWith('//')
  ) {
    return '/dashboard'
  }
  const search = 'search' in from && typeof from.search === 'string' ? from.search : ''
  const hash = 'hash' in from && typeof from.hash === 'string' ? from.hash : ''
  return `${from.pathname}${search}${hash}`
}

export function LoginPage() {
  const currentUser = useCurrentUser()
  const login = useLoginMutation()
  const location = useLocation()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)
  const destination = intendedPath(location.state)

  if (currentUser.isPending) {
    return (
      <main aria-live="polite">
        <p>Checking your session…</p>
      </main>
    )
  }
  if (currentUser.data) {
    return <Navigate to={destination} replace />
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalizedEmail = email.trim()
    if (!normalizedEmail || !password) {
      setValidationError('Email and password are required.')
      return
    }
    setValidationError(null)
    login.mutate(
      { email: normalizedEmail, password },
      {
        onSuccess: () => navigate(destination, { replace: true }),
        onError: () => setPassword(''),
      },
    )
  }

  const requestError = login.isError
    ? login.error instanceof ApiError && login.error.status === 401
      ? 'Invalid email or password.'
      : 'Unable to sign in. Please try again.'
    : null
  const error = validationError ?? requestError

  return (
    <main className="login-page">
      <h1>Sign in</h1>
      <p>Use your SIH 26155 account to continue.</p>
      <form onSubmit={submit} noValidate>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          aria-describedby={error ? 'login-error' : undefined}
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-describedby={error ? 'login-error' : undefined}
        />

        {error && (
          <p id="login-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={login.isPending}>
          {login.isPending ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
