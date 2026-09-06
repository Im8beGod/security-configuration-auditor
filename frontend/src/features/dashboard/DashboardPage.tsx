import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { listArtifacts, listAudits, listDevices, workflowKeys } from '../../shared/api/workflow'
import { StatusBadge } from '../../shared/components/WorkflowUi'

export function DashboardPage() {
  const artifacts = useQuery({ queryKey: workflowKeys.artifacts(), queryFn: () => listArtifacts() })
  const devices = useQuery({ queryKey: workflowKeys.devices, queryFn: listDevices })
  const audits = useQuery({ queryKey: workflowKeys.audits, queryFn: listAudits })
  return <section className="page-stack"><header className="hero-panel"><div><span className="eyebrow">Evidence workspace</span><h1>Build an audit-ready evidence set.</h1><p>Move from uploaded network evidence to a durable queued Audit without inventing results.</p><div className="button-row"><Link className="button-primary" to="/uploads">Upload evidence</Link><Link className="button-secondary" to="/devices">View Devices</Link></div></div><div className="workflow-map" aria-label="Current workflow"><span>Upload</span><i>→</i><span>Device</span><i>→</i><span>Snapshot</span><i>→</i><span>Audit queue</span></div></header><div className="metric-grid"><article><span>Evidence files</span><strong>{artifacts.data?.length ?? '—'}</strong><small>Safely persisted uploads</small></article><article><span>Devices</span><strong>{devices.data?.length ?? '—'}</strong><small>Logical asset identities</small></article><article><span>Audits</span><strong>{audits.data?.length ?? '—'}</strong><small>Draft and queued submissions</small></article></div><section className="panel"><div className="section-title"><div><span className="eyebrow">Current boundary</span><h2>Submission, not evaluation</h2></div><StatusBadge value="queued" /></div><p>Running an Audit locks its Snapshot and creates a durable PostgreSQL Job. Audit processing, vendor interpretation, and compliance results begin in later steps.</p></section></section>
}
