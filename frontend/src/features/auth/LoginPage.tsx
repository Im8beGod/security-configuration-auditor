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
      <main className="login-page login-loading" aria-live="polite">
        <span className="eyebrow">Secure workspace</span>
        <p>Checking your session...</p>
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
      <section className="login-intro" aria-labelledby="login-title">
        <span className="brand-note">SIH 26155 · Security operations</span>
        <span className="eyebrow">Evidence to assurance</span>
        <h1 id="login-title">Make every configuration decision defensible.</h1>
        <p>
          Normalize network evidence, surface real findings, and keep every remediation step
          reviewable from one controlled workspace.
        </p>
        <div className="login-flow" aria-label="Platform workflow">
          <span><b>01</b> Evidence</span>
          <i aria-hidden="true">→</i>
          <span><b>02</b> Normalize</span>
          <i aria-hidden="true">→</i>
          <span><b>03</b> Assure</span>
        </div>
      </section>
      <section className="login-card" aria-labelledby="welcome-title">
        <div className="login-card-head">
          <span className="eyebrow">Protected workspace</span>
          <h2 id="welcome-title">Welcome back</h2>
          <p>Sign in to continue to your organization&apos;s audit console.</p>
        </div>
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
            {login.isPending ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
        <p className="login-foot">Access is tenant-scoped and protected by your organization&apos;s policies.</p>
      </section>
    </main>
  )
}
