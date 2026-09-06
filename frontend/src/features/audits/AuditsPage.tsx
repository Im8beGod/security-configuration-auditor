import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { listAudits, listDevices, workflowKeys } from '../../shared/api/workflow'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import { formatDate, shortId } from '../../shared/workflowFormat'

export function AuditsPage() {
  const audits = useQuery({ queryKey: workflowKeys.audits, queryFn: listAudits })
  const devices = useQuery({ queryKey: workflowKeys.devices, queryFn: listDevices })
  const names = new Map(devices.data?.map((device) => [device.device_id, device.display_name]))
  return <section className="page-stack"><header className="page-heading"><div><span className="eyebrow">Steps 5–7</span><h1>Audits</h1></div><p>Submission and queue status only. Compliance evaluation is not active yet.</p></header><QueryState pending={audits.isPending} error={audits.error} empty={audits.data?.length === 0 ? 'No audits have been created yet.' : undefined}><div className="table-panel"><table><thead><tr><th>Audit</th><th>Device</th><th>Revision</th><th>Audit state</th><th>Job state</th><th>Created</th></tr></thead><tbody>{audits.data?.map((audit) => <tr key={audit.audit_id}><td><Link to={`/audits/${audit.audit_id}`}>Audit {shortId(audit.audit_id)}</Link></td><td>{names.get(audit.device_id) ?? `Device ${shortId(audit.device_id)}`}</td><td>{audit.revision_number}</td><td><StatusBadge value={audit.status} /></td><td>{audit.job ? <StatusBadge value={audit.job.status} /> : 'Not submitted'}</td><td>{formatDate(audit.created_at)}</td></tr>)}</tbody></table></div></QueryState></section>
}
