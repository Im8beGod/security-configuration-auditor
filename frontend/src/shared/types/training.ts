export type ReviewStatus = 'open' | 'under_review' | 'mapped' | 'dismissed' | 'not_actionable'
export type MappingStatus = 'suggested' | 'draft' | 'testing' | 'approved' | 'published' | 'superseded' | 'rejected'
export type ValidationFamily = 'positive' | 'alternate_values' | 'negative' | 'wrong_scope' | 'negation' | 'conflict' | 'regression'

export interface UnresolvedBlock {
  unresolved_block_id: string
  audit_id: string
  device_id: string
  snapshot_id: string
  profile_id: string | null
  profile_version_id: string | null
  source_ir_node_ids: string[]
  evidence_refs: Record<string, unknown>[]
  raw_text: string
  surrounding_context: string
  unknown_reason: string
  candidate_field_ids: string[]
  affected_rule_ids: string[]
  fingerprint: string
  occurrence: Record<string, unknown>
  review_status: ReviewStatus
  assigned_mapping_version_id: string | null
  created_at: string
  updated_at: string
  schema_version: string
}

export interface CanonicalField {
  field_id: string
  expected_types: string[]
  allowed_scope_types: string[]
  domain: string
  description: string
  repeatable: boolean
}

export interface MappingDefinition {
  profile_applicability: { profile_ids?: string[]; profile_version_ids: string[] }
  structural_match: Record<string, unknown>
  target_field_id: string
  value_extraction: Record<string, unknown>
  unit_conversion: { operation: string }
  scope_resolution: { strategy: string }
  negation_behavior: { operation: string }
  removal_behavior: { operation: string }
  default_behavior: { operation: string }
  examples: Array<{ family: ValidationFamily; node: Record<string, unknown>; expected_match: boolean; expected_value?: unknown }>
}

export interface MappingVersion extends Omit<MappingDefinition, 'profile_applicability'> {
  mapping_version_id: string
  mapping_id: string
  mapping_key: string
  version: number
  previous_mapping_version_id: string | null
  title: string
  description: string
  status: MappingStatus
  profile_applicability: { profile_ids?: string[]; profile_version_ids: string[] }
  validation_results: Record<string, unknown> & { passed?: boolean; families?: Partial<Record<ValidationFamily, boolean>> }
  origin: 'built_in' | 'administrator' | 'ai_assisted'
  ai_suggestion_metadata: { confidence?: number; similar_mapping_refs?: string[]; provider?: Record<string, string> } | null
  created_by: string | null
  approved_by: string | null
  knowledge_pack_version_id: string | null
  created_at: string
  approved_at: string | null
  published_at: string | null
  schema_version: string
}

export interface ValidationRequest { validation_run_id: string; job_id: string; status: string }
export interface Publication { mapping: MappingVersion; knowledge_pack_version_id: string; knowledge_pack_version: number }
export interface ImpactAnalysis {
  mapping_version_id: string
  matching_unresolved_block_ids: string[]
  affected_device_ids: string[]
  affected_historical_audit_ids: string[]
  potentially_affected_unknown_findings: number
  historical_profile_audit_count: number
  creates_audit_revision: false
}
export interface KnowledgePack { knowledge_pack_id: string; pack_key: string; name: string; created_at: string }
export interface KnowledgePackVersion { knowledge_pack_version_id: string; knowledge_pack_id: string; version: number; previous_knowledge_pack_version_id: string | null; mapping_version_ids: string[]; published_by: string; published_at: string }
export interface TrainingProfile { profile_id: string; profile_version_id: string; vendor: string; product_family: string; os: string; reader: string | null; coverage: Record<string, unknown>; capabilities: string[] }

export interface MappingSuggestionPreview {
  suggestion: { definition: MappingDefinition; description: string; confidence: number; caveats: string[]; provider_metadata: Record<string, string> }
  evidence_references: Record<string, string>[]
  redaction_occurred: boolean
  truncation_occurred: boolean
  adoption_token: string
  evidence: Record<string, string>
  validation: string
}
export interface LocalAIStatus { provider: string; model: string; enabled: boolean; available: boolean; reason: string }
