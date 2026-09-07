import type { Dashboard } from '../types/dashboard'
import { apiRequest } from './client'
export const dashboardKey = ['dashboard'] as const
export async function getDashboard(): Promise<Dashboard> { return await apiRequest('/dashboard') as Dashboard }
