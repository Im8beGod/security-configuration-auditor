import { apiRequest } from './client'
import type { Finding, FindingEvidence, FindingPage, Remediation } from '../types/findings'

export type FindingFilters = { verdict?: string; severity?: string; security_domain?: string; rule_id?: string; framework?: string; offset?: number; limit?: number }
export const findingKeys = { list: (auditId: string, filters: FindingFilters) => ['audits', auditId, 'findings', filters] as const, detail: (id: string) => ['findings', id] as const, evidence: (id: string) => ['findings', id, 'evidence'] as const }

export async function listFindings(auditId: string, filters: FindingFilters): Promise<FindingPage> {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)) })
  return await apiRequest(`/audits/${auditId}/findings${query.size ? `?${query}` : ''}`) as FindingPage
}
export async function getFinding(id: string): Promise<Finding> { return await apiRequest(`/findings/${id}`) as Finding }
export async function getFindingEvidence(id: string): Promise<FindingEvidence> { return await apiRequest(`/findings/${id}/evidence`) as FindingEvidence }
export async function getRemediation(id: string): Promise<Remediation> { return await apiRequest(`/findings/${id}/remediation`) as Remediation }
export async function previewRemediation(id: string, parameters: Record<string, string>): Promise<Remediation> { return await apiRequest(`/findings/${id}/remediation/preview`, { method: 'POST', body: JSON.stringify({ parameters }) }) as Remediation }
