import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useOutletContext } from 'react-router-dom'
import { getReevaluationEligibility, listAuditRevisions, reevaluateAudit, workflowKeys } from '../../shared/api/workflow'
import type { Audit } from '../../shared/types/workflow'
import type { AuthUser } from '../../shared/types/auth'
import { errorMessage, formatDate, shortId } from '../../shared/workflowFormat'
import { StatusBadge } from '../../shared/components/WorkflowUi'
import { canAccessTraining } from '../auth/roles'

export function ReevaluationPanel({ audit }: { audit: Audit }) {
  const user = useOutletContext<AuthUser>(); const client = useQueryClient()
  const eligible = useQuery({ queryKey: workflowKeys.reevaluation(audit.audit_id), queryFn: () => getReevaluationEligibility(audit.audit_id) })
  const revisions = useQuery({ queryKey: workflowKeys.revisions(audit.audit_id), queryFn: () => listAuditRevisions(audit.audit_id) })
  const create = useMutation({ mutationFn: (pack: string) => reevaluateAudit(audit.audit_id, pack), onSuccess: next => { void client.invalidateQueries({ queryKey: workflowKeys.revisions(audit.audit_id) }); void client.invalidateQueries({ queryKey: workflowKeys.audit(next.audit_id) }) } })
  const target = eligible.data?.candidates[0]
  return <section className="panel"><div className="section-title"><div><span className="eyebrow">Immutable revision history</span><h2>Re-evaluate historical evidence</h2></div></div><p className="quiet-state">The original audit, snapshot, and evidence will not change. A new revision uses the exact same immutable evidence with the selected trusted Knowledge Pack.</p>{revisions.data && <ol className="revision-list">{revisions.data.map(item => <li key={item.audit_id}><Link to={`/audits/${item.audit_id}`}>Revision {item.revision_number}</Link><span>{item.reevaluation_reason.replaceAll('_', ' ')}</span><StatusBadge value={item.status}/><small>{String(item.version_refs.knowledge_pack_version_id ?? 'pack pending')}</small></li>)}</ol>}{canAccessTraining(user.role) && target && <div className="next-action"><div><strong>Knowledge Pack version {target.version}</strong><span>Published {formatDate(target.published_at)} · creates a new audit revision.</span></div><button className="button-primary" disabled={create.isPending} onClick={() => window.confirm('Create a new immutable audit revision using the same snapshot and evidence?') && create.mutate(target.knowledge_pack_version_id)}>{create.isPending ? 'Creating revision...' : 'Re-evaluate'}</button></div>}{eligible.data && !eligible.data.eligible && <p className="quiet-state">Re-evaluation unavailable: {eligible.data.reason?.replaceAll('_', ' ')}</p>}{create.data && <p className="boundary-note">Revision {create.data.revision_number} was queued. <Link to={`/audits/${create.data.audit_id}`}>View new audit {shortId(create.data.audit_id)}</Link></p>}{(eligible.error || revisions.error || create.error) && <p className="error-message" role="alert">{errorMessage(eligible.error ?? revisions.error ?? create.error)}</p>}</section>
}
