export type ArtifactStatus = 'uploaded' | 'validating' | 'validated' | 'ready' | 'partially_supported' | 'needs_review' | 'rejected'
export type ContentFamily = 'text' | 'json' | 'xml' | 'unknown'
export type EvidenceType = 'configuration' | 'version_output' | 'inventory_output' | 'operational_output' | 'structured_export' | 'unknown_evidence'

export interface Artifact {
  artifact_id: string
  organization_id: string
  snapshot_id: string | null
  original_filename: string
  byte_size: number
  sha256: string
  mime_type: string | null
  encoding: string | null
  content_family: ContentFamily
  evidence_type: EvidenceType
  status: ArtifactStatus
  validation_issues: Array<Record<string, unknown>>
  uploaded_by: string | null
  created_at: string
  validated_at: string | null
  schema_version: string
}

export interface UploadFailure {
  filename: string
  status: 'failed'
  artifact: null
  error: { code: string; message: string }
}

export interface UploadSuccess {
  filename: string
  status: 'success'
  artifact: Artifact
  error: null
}

export interface BulkUploadResponse {
  total: number
  succeeded: number
  failed: number
  results: Array<UploadSuccess | UploadFailure>
}

export type DeviceClass = 'router' | 'switch' | 'firewall' | 'sase' | 'load_balancer' | 'wireless' | 'cloud_network_control' | 'virtual_network_device' | 'unknown' | 'other'
export type IdentityStatus = 'identified' | 'partially_identified' | 'unresolved' | 'manually_confirmed'

export interface Device {
  device_id: string
  organization_id: string
  display_name: string
  latest_hostname: string | null
  stable_serial_number: string | null
  asset_tag: string | null
  device_class: DeviceClass
  identity_status: IdentityStatus
  first_seen_at: string
  last_seen_at: string
  is_active: boolean
  created_at: string
  updated_at: string
  schema_version: string
}

export interface DeviceCreate {
  display_name: string
  latest_hostname?: string
  stable_serial_number?: string
  asset_tag?: string
  device_class: DeviceClass
  identity_status: IdentityStatus
}

export type SnapshotStatus = 'draft' | 'ready' | 'locked' | 'archived'
export type GroupingStatus = 'automatic' | 'manually_confirmed' | 'needs_review'
export type SnapshotSource = 'upload' | 'api' | 'collector' | 'import'

export interface Snapshot {
  snapshot_id: string
  device_id: string
  organization_id: string
  label: string | null
  captured_at: string | null
  ingested_at: string
  status: SnapshotStatus
  grouping_status: GroupingStatus
  snapshot_hash: string
  artifact_count: number
  source: SnapshotSource
  created_by: string | null
  created_at: string
  schema_version: string
  artifacts: Artifact[]
}

export type AuditStatus = 'draft' | 'queued' | 'processing' | 'completed' | 'completed_with_unknowns' | 'completed_with_errors' | 'failed'
export type JobStatus = 'queued' | 'processing' | 'completed' | 'failed'

export interface JobSummary {
  job_id: string
  job_type: 'audit' | 're_evaluation' | 'mapping_validation' | 'pdf_generation' | 'bulk_report_generation' | 'system_noop'
  status: JobStatus
  stage: string | null
  progress: number
  attempt_count: number
  audit_id: string | null
  device_id: string | null
  error_code: string | null
  error_message: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface Audit {
  audit_id: string
  organization_id: string
  device_id: string
  snapshot_id: string
  audit_batch_id: string | null
  revision_number: number
  previous_audit_id: string | null
  reevaluation_reason: string
  status: AuditStatus
  processing_stage: string | null
  selected_frameworks: string[]
  version_refs: Record<string, unknown>
  profile_resolution: Record<string, unknown>
  verdict_counts: Record<string, unknown>
  severity_counts: Record<string, unknown>
  coverage: Record<string, unknown>
  started_at: string | null
  completed_at: string | null
  created_at: string
  created_by: string | null
  schema_version: string
  job: JobSummary | null
}

export interface ReevaluationEligibility {
  eligible: boolean
  reason: string | null
  source_audit_id: string
  source_revision_number: number
  candidates: Array<{ knowledge_pack_version_id: string; knowledge_pack_id: string; version: number; published_at: string }>
}
