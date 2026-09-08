import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { getAudit, getDevice, getJob, getSnapshot, runAudit, workflowKeys } from '../../shared/api/workflow'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import { errorMessage, formatDate, shortId } from '../../shared/workflowFormat'
import { AuditReportPanel } from '../reports/AuditReportPanel'
import { ReevaluationPanel } from './ReevaluationPanel'

const activeJob = (status?: string) => status === 'queued' || status === 'processing'

export function AuditDetailPage() {
  const { auditId = '' } = useParams()
  const queryClient = useQueryClient()
  const audit = useQuery({ queryKey: workflowKeys.audit(auditId), queryFn: () => getAudit(auditId), enabled: Boolean(auditId), refetchInterval: query => activeJob(query.state.data?.job?.status) ? 5000 : false })
  const device = useQuery({ queryKey: workflowKeys.device(audit.data?.device_id ?? ''), queryFn: () => getDevice(audit.data!.device_id), enabled: Boolean(audit.data?.device_id) })
  const snapshot = useQuery({ queryKey: workflowKeys.snapshot(audit.data?.snapshot_id ?? ''), queryFn: () => getSnapshot(audit.data!.snapshot_id), enabled: Boolean(audit.data?.snapshot_id) })
  const job = useQuery({ queryKey: workflowKeys.job(audit.data?.job?.job_id ?? ''), queryFn: () => getJob(audit.data!.job!.job_id), enabled: Boolean(audit.data?.job?.job_id), refetchInterval: query => activeJob(query.state.data?.status) ? 5000 : false })
  const run = useMutation({ mutationFn: () => runAudit(auditId), onSuccess: updated => queryClient.setQueryData(workflowKeys.audit(auditId), updated) })
  const currentJob = job.data ?? audit.data?.job

  return <section className="page-stack"><Link className="back-link" to="/audits">Back to audits</Link><QueryState pending={audit.isPending} error={audit.error}>{audit.data && <>
    <header className="page-heading heading-actions"><div><span className="eyebrow">Audit revision {audit.data.revision_number}</span><h1>Audit {shortId(audit.data.audit_id)}</h1><p>{device.data?.display_name ?? `Device ${shortId(audit.data.device_id)}`} - Snapshot {snapshot.data?.label ?? shortId(audit.data.snapshot_id)}</p></div><StatusBadge value={audit.data.status} /></header>
    <div className="stat-strip"><div><span>Audit state</span><strong>{audit.data.status.replaceAll('_', ' ')}</strong></div><div><span>Processing stage</span><strong>{audit.data.processing_stage?.replaceAll('_', ' ') ?? 'Not started'}</strong></div><div><span>Created</span><strong>{formatDate(audit.data.created_at)}</strong></div></div>
    <section className="panel"><h2>Revision provenance</h2><dl className="detail-grid"><div><dt>Revision</dt><dd>{audit.data.revision_number}</dd></div><div><dt>Reason</dt><dd>{audit.data.reevaluation_reason.replaceAll('_', ' ')}</dd></div><div><dt>Previous Audit</dt><dd>{audit.data.previous_audit_id ? <Link to={`/audits/${audit.data.previous_audit_id}`}>{shortId(audit.data.previous_audit_id)}</Link> : 'Initial Audit'}</dd></div><div><dt>Pinned Assessment Pack</dt><dd>{audit.data.assessment ? `${audit.data.assessment.family ?? ''} ${audit.data.assessment.name ?? ''} v${audit.data.assessment.version ?? ''}` : 'Legacy technical baseline'}</dd></div><div><dt>Pinned Knowledge Pack</dt><dd>{String(audit.data.version_refs.knowledge_pack_version_id ?? 'Not pinned')}</dd></div></dl><p className="boundary-note">This revision reuses the same immutable Snapshot and evidence. The historical source Audit remains unchanged.</p></section>
    {Object.keys(audit.data.coverage).length > 0 && <section className="panel"><h2>Transparent assessment coverage</h2><dl className="detail-grid"><div><dt>Selected obligations</dt><dd>{String(audit.data.coverage.selected_obligation_count ?? 'Not provided')}</dd></div><div><dt>Applicable</dt><dd>{String(audit.data.coverage.applicable ?? 'Not provided')}</dd></div><div><dt>Not applicable</dt><dd>{String(audit.data.coverage.not_applicable ?? 'Not provided')}</dd></div><div><dt>Applicability unknown</dt><dd>{String(audit.data.coverage.applicability_unknown ?? 'Not provided')}</dd></div><div><dt>Automatic implemented</dt><dd>{String(audit.data.coverage.automatic_implemented ?? 'Not provided')}</dd></div><div><dt>Manual</dt><dd>{String(audit.data.coverage.manual ?? 'Not provided')}</dd></div><div><dt>Unimplemented</dt><dd>{String(audit.data.coverage.unimplemented ?? 'Not provided')}</dd></div></dl></section>}
    <div className="next-action"><div><strong>Persisted findings</strong><span>Review canonical findings for this audit.</span></div><Link className="button-primary" to={`/findings?audit=${audit.data.audit_id}`}>View findings</Link></div>
    {audit.data.status === 'draft' && <div className="next-action"><div><strong>Ready to submit</strong><span>Running locks the Snapshot and places this Audit in the durable queue.</span></div><button className="button-primary" disabled={run.isPending} onClick={() => window.confirm('Run this Audit?') && run.mutate()}>{run.isPending ? 'Submitting...' : 'Run Audit'}</button></div>}
    {run.isError && <p className="error-message" role="alert">{errorMessage(run.error)}</p>}
    {currentJob && <section className="panel queue-panel"><div className="section-title"><div><span className="eyebrow">Durable job</span><h2>Processing status</h2></div><StatusBadge value={currentJob.status} /></div><div className="progress-track"><span style={{ width: `${currentJob.progress}%` }} /></div><dl className="detail-grid"><div><dt>Progress</dt><dd>{currentJob.progress}%</dd></div><div><dt>Attempts</dt><dd>{currentJob.attempt_count}</dd></div><div><dt>Stage</dt><dd>{currentJob.stage ?? 'Waiting'}</dd></div><div><dt>Started</dt><dd>{formatDate(currentJob.started_at)}</dd></div></dl>{currentJob.error_message && <p className="error-message">{currentJob.error_message}</p>}</section>}
    <AuditReportPanel auditId={audit.data.audit_id} auditStatus={audit.data.status} /><ReevaluationPanel audit={audit.data} />
    <section className="panel"><h2>Audit provenance</h2><dl className="detail-grid"><div><dt>Snapshot state</dt><dd>{snapshot.data ? <StatusBadge value={snapshot.data.status} /> : 'Loading'}</dd></div><div><dt>Frameworks</dt><dd>{audit.data.selected_frameworks.join(', ') || 'None selected'}</dd></div><div><dt>Started</dt><dd>{formatDate(audit.data.started_at)}</dd></div><div><dt>Completed</dt><dd>{formatDate(audit.data.completed_at)}</dd></div></dl></section>
  </>}</QueryState></section>
}
