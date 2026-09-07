import type { Report } from '../types/reports'
import { apiDownload, apiRequest } from './client'
export const reportKey = (id: string) => ['reports', id] as const
export async function createReport(auditId: string): Promise<Report> { return await apiRequest(`/audits/${auditId}/reports`, { method: 'POST' }) as Report }
export async function getReport(reportId: string): Promise<Report> { return await apiRequest(`/reports/${reportId}`) as Report }
export async function downloadReport(reportId: string): Promise<Blob> { return apiDownload(`/reports/${reportId}/download`) }
