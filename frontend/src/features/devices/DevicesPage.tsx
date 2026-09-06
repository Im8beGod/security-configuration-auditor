import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { createDevice, listDevices, workflowKeys } from '../../shared/api/workflow'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import { errorMessage, formatDate } from '../../shared/workflowFormat'
import type { DeviceClass, IdentityStatus } from '../../shared/types/workflow'

const deviceClasses: DeviceClass[] = ['unknown', 'router', 'switch', 'firewall', 'sase', 'load_balancer', 'wireless', 'cloud_network_control', 'virtual_network_device', 'other']
const identityStates: IdentityStatus[] = ['manually_confirmed', 'unresolved', 'partially_identified', 'identified']

export function DevicesPage() {
  const queryClient = useQueryClient()
  const devices = useQuery({ queryKey: workflowKeys.devices, queryFn: listDevices })
  const [showForm, setShowForm] = useState(false)
  const create = useMutation({ mutationFn: createDevice, onSuccess: () => { setShowForm(false); void queryClient.invalidateQueries({ queryKey: workflowKeys.devices }) } })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    create.mutate({ display_name: String(data.get('display_name') ?? ''), latest_hostname: String(data.get('latest_hostname') ?? ''), stable_serial_number: String(data.get('stable_serial_number') ?? ''), asset_tag: String(data.get('asset_tag') ?? ''), device_class: String(data.get('device_class')) as DeviceClass, identity_status: String(data.get('identity_status')) as IdentityStatus })
  }

  return <section className="page-stack">
    <header className="page-heading heading-actions"><div><span className="eyebrow">Step 2</span><h1>Devices</h1><p>Logical assets that organize evidence over time. No vendor or platform has been inferred.</p></div><button className="button-primary" onClick={() => setShowForm((value) => !value)}>{showForm ? 'Close form' : 'Create Device'}</button></header>
    {showForm && <form className="panel form-grid" onSubmit={submit}><div className="field span-two"><label htmlFor="display_name">Display name</label><input id="display_name" name="display_name" required maxLength={255} /></div><div className="field"><label htmlFor="latest_hostname">Hostname <small>optional</small></label><input id="latest_hostname" name="latest_hostname" maxLength={255} /></div><div className="field"><label htmlFor="stable_serial_number">Serial number <small>optional</small></label><input id="stable_serial_number" name="stable_serial_number" maxLength={255} /></div><div className="field"><label htmlFor="asset_tag">Asset tag <small>optional</small></label><input id="asset_tag" name="asset_tag" maxLength={255} /></div><div className="field"><label htmlFor="device_class">Device class</label><select id="device_class" name="device_class" defaultValue="unknown">{deviceClasses.map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></div><div className="field"><label htmlFor="identity_status">Identity confidence</label><select id="identity_status" name="identity_status" defaultValue="manually_confirmed">{identityStates.map((value) => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}</select></div>{create.isError && <p className="error-message span-two" role="alert">{errorMessage(create.error)}</p>}<div className="button-row span-two"><button className="button-primary" disabled={create.isPending}>{create.isPending ? 'Creating...' : 'Create Device'}</button></div></form>}
    <QueryState pending={devices.isPending} error={devices.error} empty={devices.data?.length === 0 ? 'Create your first device to organize uploaded evidence.' : undefined}><div className="card-grid">{devices.data?.map((device) => <Link className="entity-card" to={`/devices/${device.device_id}`} key={device.device_id}><div className="entity-card-top"><span className="entity-icon">D</span><StatusBadge value={device.is_active ? 'active' : 'inactive'} /></div><h2>{device.display_name}</h2><p>{device.latest_hostname ?? 'Hostname not recorded'}</p><dl className="mini-details"><div><dt>Class</dt><dd>{device.device_class.replaceAll('_', ' ')}</dd></div><div><dt>Identity</dt><dd>{device.identity_status.replaceAll('_', ' ')}</dd></div><div><dt>Last seen</dt><dd>{formatDate(device.last_seen_at)}</dd></div></dl><span className="text-link">Open device →</span></Link>)}</div></QueryState>
  </section>
}
