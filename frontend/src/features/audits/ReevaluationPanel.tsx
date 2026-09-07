import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useOutletContext } from 'react-router-dom'
import { useState } from 'react'

import { getReevaluationEligibility, listAuditRevisions, reevaluateAudit, workflowKeys } from '../../shared/api/workflow'
import type { Audit, ReevaluationEligibility } from '../../shared/types/workflow'
import type { AuthUser } from '../../shared/types/auth'
import { errorMessage, formatDate, shortId } from '../../shared/workflowFormat'
import { StatusBadge } from '../../shared/components/WorkflowUi'
import { canAccessTraining } from '../auth/roles'

function reasonLabel(reason: string | null): string {
  return (reason ?? 'unavailable').replaceAll('_', ' ')
}

function Confirmation({ audit, target, pending, onCancel, onConfirm }: {
  audit: Audit
  target: NonNullable<ReevaluationEligibility['candidates']>[number]
  pending: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  return <aside className="boundary-note" aria-live="polite">
    <strong>Confirm new Audit revision</strong>
    <p>Source Audit revision {audit.revision_number} ({shortId(audit.audit_id)}) will remain unchanged.</p>
    <p>Target Knowledge Pack version {target.version} ({shortId(target.knowledge_pack_version_id)}) will be pinned.</p>
    <p>The same immutable Snapshot and evidence will be reused. A NEW Audit revision will be created.</p>
    <div className="button-row">
      <button className="button-primary" disabled={pending} onClick={onConfirm}>{pending ? 'Creating revision...' : 'Confirm re-evaluation'}</button>
      <button className="button-secondary" disabled={pending} onClick={onCancel}>Cancel</button>
    </div>
  </aside>
}

export function ReevaluationPanel({ audit }: { audit: Audit }) {
  const user = useOutletContext<AuthUser>()
  const client = useQueryClient()
  const [confirmTarget, setConfirmTarget] = useState<ReevaluationEligibility['candidates'][number] | null>(null)
  const eligible = useQuery({ queryKey: workflowKeys.reevaluation(audit.audit_id), queryFn: () => getReevaluationEligibility(audit.audit_id) })
  const revisions = useQuery({ queryKey: workflowKeys.revisions(audit.audit_id), queryFn: () => listAuditRevisions(audit.audit_id) })
  const create = useMutation({
    mutationFn: (pack: string) => reevaluateAudit(audit.audit_id, pack),
    onSuccess: next => {
      setConfirmTarget(null)
      void client.invalidateQueries({ queryKey: workflowKeys.revisions(audit.audit_id) })
      void client.invalidateQueries({ queryKey: workflowKeys.audit(next.audit_id) })
    },
  })
  const target = eligible.data?.candidates[0]

  return <section className="panel">
    <div className="section-title"><div><span className="eyebrow">Immutable revision history</span><h2>Re-evaluate historical evidence</h2></div></div>
    <p className="quiet-state">The original audit, snapshot, and evidence will not change. A new revision uses the exact same immutable evidence with the selected trusted Knowledge Pack.</p>
    {revisions.data && <ol className="revision-list">{revisions.data.map(item => <li key={item.audit_id}><Link to={`/audits/${item.audit_id}`}>Revision {item.revision_number}</Link><span>{item.reevaluation_reason.replaceAll('_', ' ')}</span><StatusBadge value={item.status}/><small>{String(item.version_refs.knowledge_pack_version_id ?? 'pack pending')}</small></li>)}</ol>}
    {canAccessTraining(user.role) && target && !confirmTarget && <div className="next-action"><div><strong>Knowledge Pack version {target.version}</strong><span>Published {formatDate(target.published_at)} · potentially re-evaluable.</span></div><button className="button-primary" onClick={() => setConfirmTarget(target)}>Review and re-evaluate</button></div>}
    {canAccessTraining(user.role) && confirmTarget && <Confirmation audit={audit} target={confirmTarget} pending={create.isPending} onCancel={() => setConfirmTarget(null)} onConfirm={() => create.mutate(confirmTarget.knowledge_pack_version_id)} />}
    {eligible.data && !eligible.data.eligible && <p className="quiet-state">Re-evaluation unavailable: {reasonLabel(eligible.data.reason)}</p>}
    {create.data && <p className="boundary-note">Revision {create.data.revision_number} was queued. <Link to={`/audits/${create.data.audit_id}`}>View new audit {shortId(create.data.audit_id)}</Link></p>}
    {(eligible.error || revisions.error || create.error) && <p className="error-message" role="alert">{errorMessage(eligible.error ?? revisions.error ?? create.error)}</p>}
  </section>
}
