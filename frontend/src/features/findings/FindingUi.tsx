import type { JsonValue, FindingSeverity, FindingVerdict } from '../../shared/types/findings'
import { readable } from './findingFormat'

export function VerdictBadge({ value }: { value: FindingVerdict | string }) { return <span className={`finding-badge verdict-${value}`}>{readable(value)}</span> }
export function SeverityBadge({ value }: { value: FindingSeverity | string }) { return <span className={`finding-badge severity-${value}`}>{readable(value)}</span> }
export function StructuredValue({ value, empty = 'Not available' }: { value: JsonValue | null | undefined; empty?: string }) {
  if (value === null || value === undefined) return <span className="muted-value">{empty}</span>
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return <code>{String(value)}</code>
  return <pre className="structured-value">{JSON.stringify(value, null, 2)}</pre>
}
export function ScopeSummary({ scope }: { scope: Record<string, JsonValue> | null }) {
  if (!scope) return <span className="muted-value">Not established</span>
  const type = typeof scope.type === 'string' ? readable(scope.type) : 'Scope'
  const key = typeof scope.key === 'string' ? scope.key : null
  return <span>{type}{key ? ` · ${key}` : ''}</span>
}
