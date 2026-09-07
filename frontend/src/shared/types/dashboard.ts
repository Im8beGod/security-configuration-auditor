export interface CoverageMetric { numerator: number; denominator: number; percentage: number | null; status: 'assessed' | 'not_assessed' }
export interface DashboardDevice { device_id: string; display_name: string; latest_audit_id: string | null; latest_audit_status: string | null; latest_completed_audit_id: string | null }
export interface RecentAudit { audit_id: string; device_id: string; device_name: string; status: string; created_at: string; completed_at: string | null; fail_count: number; unknown_count: number; critical_count: number; high_count: number }
export interface Dashboard {
  total_devices: number; audited_devices: number; unaudited_devices: number
  critical_risk_devices: number; high_risk_devices: number; devices_needing_review: number
  verdict_distribution: Record<string, number>; severity_distribution: Record<string, number>; audit_status_distribution: Record<string, number>
  vendor_distribution: Record<string, number>; profile_distribution: Record<string, number>; device_family_distribution: Record<string, number>
  coverage: Record<string, CoverageMetric>; devices: DashboardDevice[]; recent_audits: RecentAudit[]
}
