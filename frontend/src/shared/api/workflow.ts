import type { Artifact, AssessmentPackSummary, Audit, BatchAuditResponse, BulkUploadResponse, Device, DeviceCreate, JobSummary, ReevaluationEligibility, Snapshot } from '../types/workflow'
import { apiRequest } from './client'

export const workflowKeys = {
  artifacts: (unassigned = false) => ['artifacts', { unassigned }] as const,
  devices: ['devices'] as const,
  device: (id: string) => ['devices', id] as const,
  snapshots: (deviceId: string) => ['devices', deviceId, 'snapshots'] as const,
  snapshot: (id: string) => ['snapshots', id] as const,
  audits: ['audits'] as const,
  audit: (id: string) => ['audits', id] as const,
  job: (id: string) => ['jobs', id] as const,
  revisions: (id: string) => ['audits', id, 'revisions'] as const,
  reevaluation: (id: string) => ['audits', id, 'reevaluation-eligibility'] as const,
  assessmentPacks: ['assessment-packs'] as const,
}

const json = (value: unknown) => JSON.stringify(value)

export async function bulkUpload(files: File[]): Promise<BulkUploadResponse> {
  const body = new FormData()
  files.forEach((file) => body.append('files', file))
  return await apiRequest('/artifacts/bulk-upload', { method: 'POST', body }) as BulkUploadResponse
}

export async function listArtifacts(unassigned = false): Promise<Artifact[]> {
  return await apiRequest(`/artifacts${unassigned ? '?unassigned=true' : ''}`) as Artifact[]
}

export async function listDevices(): Promise<Device[]> {
  return await apiRequest('/devices') as Device[]
}

export async function getDevice(id: string): Promise<Device> {
  return await apiRequest(`/devices/${id}`) as Device
}

export async function createDevice(request: DeviceCreate): Promise<Device> {
  return await apiRequest('/devices', { method: 'POST', body: json(request) }) as Device
}

export async function listSnapshots(deviceId: string): Promise<Snapshot[]> {
  return await apiRequest(`/devices/${deviceId}/snapshots`) as Snapshot[]
}

export async function getSnapshot(id: string): Promise<Snapshot> {
  return await apiRequest(`/snapshots/${id}`) as Snapshot
}

export async function createSnapshot(deviceId: string, request: { label?: string; captured_at?: string }): Promise<Snapshot> {
  return await apiRequest(`/devices/${deviceId}/snapshots`, {
    method: 'POST', body: json({ ...request, source: 'upload', grouping_status: 'manually_confirmed' }),
  }) as Snapshot
}

export async function addArtifact(snapshotId: string, artifactId: string): Promise<Snapshot> {
  return await apiRequest(`/snapshots/${snapshotId}/artifacts/${artifactId}`, { method: 'POST' }) as Snapshot
}

export async function removeArtifact(snapshotId: string, artifactId: string): Promise<void> {
  await apiRequest(`/snapshots/${snapshotId}/artifacts/${artifactId}`, { method: 'DELETE' })
}

export async function finalizeSnapshot(id: string): Promise<Snapshot> {
  return await apiRequest(`/snapshots/${id}/finalize`, { method: 'POST' }) as Snapshot
}

export async function listAudits(): Promise<Audit[]> {
  return await apiRequest('/audits') as Audit[]
}

export async function getAudit(id: string): Promise<Audit> {
  return await apiRequest(`/audits/${id}`) as Audit
}

export async function listAssessmentPacks(profileVersionId?: string): Promise<AssessmentPackSummary[]> {
  const query = profileVersionId ? `?profile_version_id=${encodeURIComponent(profileVersionId)}` : ''
  return await apiRequest(`/audits/assessment-packs${query}`) as AssessmentPackSummary[]
}

export async function createAudit(snapshotId: string, assessmentPackVersionId?: string): Promise<Audit> {
  return await apiRequest('/audits', {
    method: 'POST', body: json({ snapshot_id: snapshotId, selected_frameworks: [], ...(assessmentPackVersionId ? { assessment_pack_version_id: assessmentPackVersionId } : {}) }),
  }) as Audit
}

export async function runAudit(id: string): Promise<Audit> {
  return await apiRequest(`/audits/${id}/run`, { method: 'POST' }) as Audit
}

export async function createBatchAudits(items: Array<{ device_id: string; snapshot_id: string; assessment_pack_version_id?: string }>): Promise<BatchAuditResponse> {
  return await apiRequest('/audits/batch', {
    method: 'POST',
    body: json({ items: items.map((item) => ({ ...item, selected_frameworks: [] })) }),
  }) as BatchAuditResponse
}

export async function getJob(id: string): Promise<JobSummary> {
  return await apiRequest(`/jobs/${id}`) as JobSummary
}

export async function getReevaluationEligibility(id: string): Promise<ReevaluationEligibility> {
  return await apiRequest(`/audits/${id}/reevaluation-eligibility`) as ReevaluationEligibility
}

export async function listAuditRevisions(id: string): Promise<Audit[]> {
  return await apiRequest(`/audits/${id}/revisions`) as Audit[]
}

export async function reevaluateAudit(id: string, knowledgePackVersionId: string): Promise<Audit> {
  return await apiRequest(`/audits/${id}/re-evaluate`, { method: 'POST', body: json({ knowledge_pack_version_id: knowledgePackVersionId }) }) as Audit
}
