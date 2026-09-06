import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'

import { createSnapshot, getDevice, listSnapshots, workflowKeys } from '../../shared/api/workflow'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import { errorMessage, shortId } from '../../shared/workflowFormat'

export function DeviceDetailPage() {
  const { deviceId = '' } = useParams()
  const queryClient = useQueryClient()
  const device = useQuery({ queryKey: workflowKeys.device(deviceId), queryFn: () => getDevice(deviceId), enabled: Boolean(deviceId) })
  const snapshots = useQuery({ queryKey: workflowKeys.snapshots(deviceId), queryFn: () => listSnapshots(deviceId), enabled: Boolean(deviceId) })
  const [showForm, setShowForm] = useState(false)
  const create = useMutation({ mutationFn: (request: { label?: string; captured_at?: string }) => createSnapshot(deviceId, request), onSuccess: () => { setShowForm(false); void queryClient.invalidateQueries({ queryKey: workflowKeys.snapshots(deviceId) }) } })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const captured = String(data.get('captured_at') ?? '')
    create.mutate({ label: String(data.get('label') ?? '') || undefined, captured_at: captured ? new Date(captured).toISOString() : undefined })
  }

  return <section className="page-stack"><Link className="back-link" to="/devices">← All Devices</Link><QueryState pending={device.isPending} error={device.error}><header className="page-heading heading-actions"><div><span className="eyebrow">Device</span><h1>{device.data?.display_name}</h1><p>{device.data?.latest_hostname ?? 'Hostname not recorded'} · {device.data?.device_class.replaceAll('_', ' ')}</p></div><StatusBadge value={device.data?.identity_status ?? 'unknown'} /></header></QueryState><div className="section-title"><div><span className="eyebrow">Step 3</span><h2>Evidence snapshots</h2></div><button className="button-primary" onClick={() => setShowForm((value) => !value)}>{showForm ? 'Close form' : 'Create draft Snapshot'}</button></div>{showForm && <form className="panel form-grid" onSubmit={submit}><div className="field"><label htmlFor="snapshot-label">Label <small>optional</small></label><input id="snapshot-label" name="label" maxLength={255} placeholder="September baseline" /></div><div className="field"><label htmlFor="captured-at">Evidence captured at <small>optional</small></label><input id="captured-at" name="captured_at" type="datetime-local" /></div>{create.isError && <p className="error-message span-two" role="alert">{errorMessage(create.error)}</p>}<div className="button-row span-two"><button className="button-primary" disabled={create.isPending}>{create.isPending ? 'Creating...' : 'Create draft Snapshot'}</button></div></form>}<QueryState pending={snapshots.isPending} error={snapshots.error} empty={snapshots.data?.length === 0 ? 'No evidence snapshots have been created for this device.' : undefined}><div className="timeline-list">{snapshots.data?.map((snapshot) => <Link to={`/snapshots/${snapshot.snapshot_id}`} className="timeline-item" key={snapshot.snapshot_id}><span className="timeline-dot" /><div><strong>{snapshot.label ?? `Snapshot ${shortId(snapshot.snapshot_id)}`}</strong><span>{snapshot.artifact_count} evidence file{snapshot.artifact_count === 1 ? '' : 's'}</span></div><StatusBadge value={snapshot.status} /></Link>)}</div></QueryState></section>
}
