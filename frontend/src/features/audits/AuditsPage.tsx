import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { createBatchAudits, listAssessmentPacks, listAudits, listDevices, listSnapshots, workflowKeys } from '../../shared/api/workflow'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import { errorMessage, formatDate, shortId } from '../../shared/workflowFormat'
import type { BatchAuditResponse, Device, Snapshot } from '../../shared/types/workflow'

type ReadySnapshot = { device: Device; snapshot: Snapshot }

export function AuditsPage() {
  const queryClient = useQueryClient()
  const audits = useQuery({ queryKey: workflowKeys.audits, queryFn: listAudits })
  const devices = useQuery({ queryKey: workflowKeys.devices, queryFn: listDevices })
  const assessmentPacks = useQuery({ queryKey: workflowKeys.assessmentPacks, queryFn: () => listAssessmentPacks() })
  const snapshotQueries = useQueries({
    queries: (devices.data ?? []).map((device) => ({
      queryKey: workflowKeys.snapshots(device.device_id),
      queryFn: () => listSnapshots(device.device_id),
    })),
  })
  const [selectedSnapshots, setSelectedSnapshots] = useState<string[]>([])
  const [batchResults, setBatchResults] = useState<BatchAuditResponse | null>(null)
  const [packBySnapshot, setPackBySnapshot] = useState<Record<string, string>>({})
  const readySnapshots: ReadySnapshot[] = snapshotQueries.flatMap((query, index) => {
    const device = devices.data?.[index]
    return device ? (query.data ?? []).filter((snapshot) => snapshot.status === 'ready').map((snapshot) => ({ device, snapshot })) : []
  })
  const snapshotById = new Map(readySnapshots.map((item) => [item.snapshot.snapshot_id, item]))
  const batch = useMutation({
    mutationFn: () => createBatchAudits(selectedSnapshots.flatMap((snapshotId) => {
      const item = snapshotById.get(snapshotId)
      return item ? [{ device_id: item.device.device_id, snapshot_id: item.snapshot.snapshot_id, ...(packBySnapshot[snapshotId] ? { assessment_pack_version_id: packBySnapshot[snapshotId] } : {}) }] : []
    })),
    onSuccess: (result) => {
      setBatchResults(result)
      setSelectedSnapshots([])
      setPackBySnapshot({})
      void queryClient.invalidateQueries({ queryKey: workflowKeys.audits })
    },
  })
  const names = new Map(devices.data?.map((device) => [device.device_id, device.display_name]))
  const snapshotsPending = snapshotQueries.some((query) => query.isPending)
  const snapshotsError = snapshotQueries.find((query) => query.error)?.error

  function toggleSnapshot(snapshotId: string, checked: boolean) {
    setSelectedSnapshots((current) => checked ? [...current, snapshotId] : current.filter((id) => id !== snapshotId))
  }

  return <section className="page-stack">
    <header className="page-heading"><div><span className="eyebrow">Steps 5-7</span><h1>Audits</h1></div><p>Submit ready Cisco and FortiOS snapshots together. Each item keeps its own audit and job result.</p></header>
    <section className="panel">
      <div className="section-title"><div><span className="eyebrow">Batch submission</span><h2>Select ready snapshots</h2></div><span>{selectedSnapshots.length} selected</span></div>
      {snapshotsError ? <p className="error-message" role="alert">{errorMessage(snapshotsError)}</p> : snapshotsPending ? <p className="quiet-state" aria-live="polite">Loading ready snapshots...</p> : readySnapshots.length === 0 ? <p className="quiet-state">No ready snapshots are available. Finalize evidence from a device first.</p> : <div className="selection-list">{readySnapshots.map(({ device, snapshot }) => <label key={snapshot.snapshot_id}><input type="checkbox" checked={selectedSnapshots.includes(snapshot.snapshot_id)} onChange={(event) => toggleSnapshot(snapshot.snapshot_id, event.target.checked)} /><span><strong>{device.display_name}</strong><small>{snapshot.label ?? `Snapshot ${shortId(snapshot.snapshot_id)}`} - {snapshot.artifact_count} evidence file{snapshot.artifact_count === 1 ? '' : 's'}</small><select aria-label={`Assessment Pack for ${device.display_name}`} value={packBySnapshot[snapshot.snapshot_id] ?? ''} onChange={(event) => setPackBySnapshot((current) => ({ ...current, [snapshot.snapshot_id]: event.target.value }))}><option value="">Legacy technical baseline</option>{(assessmentPacks.data ?? []).map((pack) => <option key={pack.assessment_pack_version_id} value={pack.assessment_pack_version_id}>{pack.family} / {pack.name} v{pack.version}</option>)}</select></span><StatusBadge value="ready" /></label>)}</div>}
      {assessmentPacks.isError && <p className="error-message" role="alert">Assessment Pack choices are unavailable: {errorMessage(assessmentPacks.error)}</p>}
      {batch.isError && <p className="error-message" role="alert">{errorMessage(batch.error)}</p>}
      <button className="button-primary" disabled={selectedSnapshots.length < 2 || batch.isPending} onClick={() => batch.mutate()}>{batch.isPending ? 'Submitting batch...' : `Submit ${selectedSnapshots.length || ''} selected audits`}</button>
      <p className="quiet-state">Select at least two ready snapshots. Rejected items remain visible and do not discard accepted work.</p>
    </section>
    {batchResults && <section className="panel">
      <div className="section-title"><div><span className="eyebrow">Batch response</span><h2>{batchResults.accepted} accepted - {batchResults.rejected} rejected</h2></div></div>
      <div className="result-grid">{batchResults.results.map((result) => {
        const item = snapshotById.get(result.snapshot_id)
        return <article className="result-card" key={`${result.snapshot_id}-${result.audit_id ?? result.error_code}`}><div><strong>{item?.device.display_name ?? `Device ${shortId(result.device_id)}`}</strong><StatusBadge value={result.status} /></div><p>{item?.snapshot.label ?? `Snapshot ${shortId(result.snapshot_id)}`}</p>{result.status === 'accepted' && result.audit_id ? <><p>Audit <code>{shortId(result.audit_id)}</code> - Job <code>{shortId(result.job_id ?? '')}</code> - queued</p><div className="button-row"><Link className="button-secondary" to={`/audits/${result.audit_id}`}>Open audit</Link><Link className="button-primary" to={`/findings?audit=${result.audit_id}`}>Open findings</Link></div></> : <p className="error-message">{result.error_message ?? 'This item was rejected and no audit was created.'}</p>}</article>
      })}</div>
    </section>}
    <QueryState pending={audits.isPending} error={audits.error} empty={audits.data?.length === 0 ? 'No audits have been created yet.' : undefined}><div className="table-panel"><table><thead><tr><th>Audit</th><th>Device</th><th>Revision</th><th>Audit state</th><th>Job state</th><th>Created</th></tr></thead><tbody>{audits.data?.map((audit) => <tr key={audit.audit_id}><td><Link to={`/audits/${audit.audit_id}`}>Audit {shortId(audit.audit_id)}</Link></td><td>{names.get(audit.device_id) ?? `Device ${shortId(audit.device_id)}`}</td><td>{audit.revision_number}</td><td><StatusBadge value={audit.status} /></td><td>{audit.job ? <StatusBadge value={audit.job.status} /> : 'Not submitted'}</td><td>{formatDate(audit.created_at)}</td></tr>)}</tbody></table></div></QueryState>
  </section>
}
