export type FindingVerdict = 'pass' | 'fail' | 'unknown' | 'manual_review' | 'not_applicable' | 'process_error'
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

export interface Finding {
  finding_id: string; audit_id: string; device_id: string; comparison_key: string
  rule_id: string; rule_pack_version_id: string; title: string; security_domain: string
  verdict: FindingVerdict | string; severity: FindingSeverity | string
  expected_state: Record<string, JsonValue> | null; observed_state: Record<string, JsonValue> | null
  explanation: string; affected_scope: Record<string, JsonValue> | null
  effective_state_refs: string[]; evidence_refs: Array<Record<string, JsonValue>>
  unknown_reason: string | null; framework_references: Array<Record<string, JsonValue>>
  remediation_procedure_id: string | null; created_at: string; schema_version: string
}

export interface FindingPage { items: Finding[]; total: number; offset: number; limit: number }
export interface EvidenceArtifact { artifact_id: string; original_filename: string; evidence_type: string; content_family: string; sha256: string; excerpt: string | null; truncated: boolean; available: boolean }
export interface EvidenceFact { fact_id: string; field_id: string; value: Record<string, JsonValue>; scope: Record<string, JsonValue>; state: string; extraction_method: string; mapping_id: string | null; mapping_version_id: string | null; knowledge_pack_version_id: string; validation_status: string; interpretation_confidence: string; evidence_refs: Array<Record<string, JsonValue>>; artifacts: EvidenceArtifact[] }
export interface EvidenceState { effective_state_id: string; field_id: string; scope: Record<string, JsonValue>; effective_value: Record<string, JsonValue> | null; resolution_status: string; resolution_trace: Array<Record<string, JsonValue>>; inherited_from: Record<string, JsonValue> | null; default_reference: string | null; referenced_objects: Array<Record<string, JsonValue>>; precedence_applied: Array<Record<string, JsonValue>>; unresolved_reason: string | null; facts: EvidenceFact[] }
export interface FindingEvidence { finding_id: string; states: EvidenceState[]; status: string }
