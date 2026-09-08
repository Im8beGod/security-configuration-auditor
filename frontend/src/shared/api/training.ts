import { apiRequest } from './client'
import type { MappingSuggestionPreview, LocalAIStatus, CanonicalField, ImpactAnalysis, KnowledgePack, KnowledgePackVersion, MappingDefinition, MappingVersion, Publication, ReviewStatus, TrainingProfile, UnresolvedBlock, ValidationRequest } from '../types/training'

const json = (value: unknown) => JSON.stringify(value)
export const trainingKeys = {
  unresolved: (status: string) => ['training', 'unresolved', status] as const,
  unresolvedDetail: (id: string) => ['training', 'unresolved', id] as const,
  mapping: (id: string) => ['training', 'mapping', id] as const,
  fields: ['training', 'fields'] as const,
  packs: ['training', 'packs'] as const,
  packVersions: (id: string) => ['training', 'packs', id, 'versions'] as const,
  impact: (id: string) => ['training', 'mapping', id, 'impact'] as const,
  profiles: ['training', 'profiles'] as const,
}

export async function listUnresolved(status: ReviewStatus | ''): Promise<UnresolvedBlock[]> { return await apiRequest(`/training/unresolved${status ? `?review_status=${status}` : ''}`) as UnresolvedBlock[] }
export async function getUnresolved(id: string): Promise<UnresolvedBlock> { return await apiRequest(`/training/unresolved/${id}`) as UnresolvedBlock }
export async function updateUnresolved(id: string, reviewStatus: ReviewStatus): Promise<UnresolvedBlock> { return await apiRequest(`/training/unresolved/${id}`, { method: 'PATCH', body: json({ review_status: reviewStatus }) }) as UnresolvedBlock }
export async function suggestMapping(id: string): Promise<MappingSuggestionPreview> { return await apiRequest(`/training/unresolved/${id}/suggest`, { method: 'POST' }) as MappingSuggestionPreview }
export async function localAIStatus(): Promise<LocalAIStatus> { return await apiRequest('/training/ai/status') as LocalAIStatus }
export async function adoptSuggestion(id: string, token: string): Promise<MappingVersion> { return await apiRequest(`/training/unresolved/${id}/adopt`, { method: 'POST', body: json({ adoption_token: token }) }) as MappingVersion }
export async function listCanonicalFields(): Promise<CanonicalField[]> { return await apiRequest('/training/canonical-fields') as CanonicalField[] }
export async function createMapping(payload: { mapping_key: string; title: string; description: string; definition: MappingDefinition; unresolved_block_id?: string }): Promise<MappingVersion> { return await apiRequest('/training/mappings', { method: 'POST', body: json(payload) }) as MappingVersion }
export async function getMapping(id: string): Promise<MappingVersion> { return await apiRequest(`/training/mappings/${id}`) as MappingVersion }
export async function updateMapping(mapping: MappingVersion, payload: { title: string; description: string; definition: MappingDefinition }): Promise<MappingVersion> { return await apiRequest(`/training/mappings/${mapping.mapping_version_id}`, { method: 'PUT', body: json(payload) }) as MappingVersion }
export async function validateMapping(id: string, evidenceArtifactId?: string): Promise<ValidationRequest> { return await apiRequest(`/training/mappings/${id}/validate`, { method: 'POST', body: json(evidenceArtifactId ? { evidence_artifact_id: evidenceArtifactId } : {}) }) as ValidationRequest }
export async function approveMapping(id: string): Promise<MappingVersion> { return await apiRequest(`/training/mappings/${id}/approve`, { method: 'POST' }) as MappingVersion }
export async function publishMapping(id: string): Promise<Publication> { return await apiRequest(`/training/mappings/${id}/publish`, { method: 'POST' }) as Publication }
export async function rejectMapping(id: string): Promise<MappingVersion> { return await apiRequest(`/training/mappings/${id}/reject`, { method: 'POST' }) as MappingVersion }
export async function getImpact(id: string): Promise<ImpactAnalysis> { return await apiRequest(`/training/mappings/${id}/impact`) as ImpactAnalysis }
export async function listKnowledgePacks(): Promise<KnowledgePack[]> { return await apiRequest('/training/knowledge-packs') as KnowledgePack[] }
export async function listKnowledgePackVersions(id: string): Promise<KnowledgePackVersion[]> { return await apiRequest(`/training/knowledge-packs/${id}/versions`) as KnowledgePackVersion[] }
export async function listTrainingProfiles(): Promise<TrainingProfile[]> { return await apiRequest('/training/profiles') as TrainingProfile[] }
