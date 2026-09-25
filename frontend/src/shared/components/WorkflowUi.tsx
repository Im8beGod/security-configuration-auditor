import { errorMessage } from '../workflowFormat'

export function StatusBadge({ value }: { value: string }) {
  return <span className={`status-badge status-${value}`}>{value.replaceAll('_', ' ')}</span>
}

export function QueryState({ pending, error, empty, children }: {
  pending: boolean
  error: unknown
  empty?: string
  children: React.ReactNode
}) {
  if (pending) return <p className="quiet-state state-message state-loading" aria-live="polite">Loading current data...</p>
  if (error) return <p className="error-message state-message state-error" role="alert">{errorMessage(error)}</p>
  if (empty) return <p className="quiet-state state-message state-empty">{empty}</p>
  return children
}
