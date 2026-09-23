import { apiRequest } from './client'

export interface RuntimeProfilePreview {
  profile_id: string
  profile_version_id: string
  vendor: string
  product_family: string
  os: string
  reader: string
  evidence_types: string[]
  capabilities: string[]
  preview_digest: string
}

export interface RuntimePublishResponse {
  status: string
  preview_digest?: string
  profile_version_id?: string
  runtime_rule_version_id?: string
  assessment_pack_version_id?: string
  rule_id?: string
  pack_key?: string
  version?: number
}

export interface RuntimeRulePreview {
  rule_id: string
  profile_version_ids: string[]
  canonical_field: string
  operator: string
}

const json = (value: unknown) => JSON.stringify(value)

function upload(file: File, fields: Record<string, string> = {}): FormData {
  const body = new FormData()
  body.append('file', file)
  Object.entries(fields).forEach(([key, value]) => body.append(key, value))
  return body
}

export async function previewRuntimeProfile(file: File): Promise<RuntimeProfilePreview> {
  return await apiRequest('/training/profile-manifests/preview', { method: 'POST', body: upload(file) }) as RuntimeProfilePreview
}

export async function publishRuntimeProfile(file: File, previewDigest: string): Promise<RuntimePublishResponse> {
  return await apiRequest('/training/profile-manifests/publish', { method: 'POST', body: upload(file, { preview_digest: previewDigest }) }) as RuntimePublishResponse
}

export async function previewRuntimeRule(payload: unknown): Promise<RuntimeRulePreview> {
  return await apiRequest('/runtime-rules/preview', { method: 'POST', body: json(payload) }) as RuntimeRulePreview
}

export async function publishRuntimeRule(payload: unknown): Promise<RuntimePublishResponse> {
  return await apiRequest('/runtime-rules/publish', { method: 'POST', body: json(payload) }) as RuntimePublishResponse
}

export async function previewRuntimeAssessmentPack(file: File): Promise<Record<string, unknown>> {
  return await apiRequest('/assessment-packs/preview', { method: 'POST', body: upload(file) }) as Record<string, unknown>
}

export async function publishRuntimeAssessmentPack(file: File, previewDigest: string): Promise<RuntimePublishResponse> {
  return await apiRequest('/assessment-packs/publish', { method: 'POST', body: upload(file, { preview_digest: previewDigest }) }) as RuntimePublishResponse
}
