export type ReportStatus = 'pending' | 'generating' | 'ready' | 'failed'
export interface Report {
  report_id: string; organization_id: string; device_id: string; audit_id: string
  report_type: 'device_compliance'; format: 'pdf'; status: ReportStatus
  sha256: string | null; byte_size: number | null; template_version: string; generator_version: string
  audit_schema_version: string; source_finding_ids: string[]; generated_by: string | null
  created_at: string; generated_at: string | null; failure_code: string | null; failure_message: string | null; schema_version: string
}
