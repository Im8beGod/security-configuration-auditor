export type UserRole = 'analyst' | 'mapping_admin' | 'admin'

export interface LoginRequest {
  email: string
  password: string
}

export interface AuthUser {
  user_id: string
  organization_id: string
  email: string
  role: UserRole
  is_active: boolean
}
