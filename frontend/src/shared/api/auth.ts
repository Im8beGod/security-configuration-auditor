import type { AuthUser, LoginRequest, UserRole } from '../types/auth'
import { apiRequest } from './client'

const USER_ROLES: ReadonlySet<string> = new Set([
  'analyst',
  'mapping_admin',
  'admin',
])

function isAuthUser(value: unknown): value is AuthUser {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  return (
    'user_id' in value &&
    typeof value.user_id === 'string' &&
    'organization_id' in value &&
    typeof value.organization_id === 'string' &&
    'email' in value &&
    typeof value.email === 'string' &&
    'role' in value &&
    typeof value.role === 'string' &&
    USER_ROLES.has(value.role) &&
    'is_active' in value &&
    typeof value.is_active === 'boolean'
  )
}

function requireAuthUser(value: unknown): AuthUser {
  if (!isAuthUser(value)) {
    throw new Error('API returned an invalid user response')
  }
  return value
}

export async function login(credentials: LoginRequest): Promise<AuthUser> {
  const response = await apiRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  })
  return requireAuthUser(response)
}

export async function logout(): Promise<void> {
  await apiRequest('/auth/logout', { method: 'POST' })
}

export async function getCurrentUser(): Promise<AuthUser> {
  return requireAuthUser(await apiRequest('/auth/me'))
}

export type { AuthUser, LoginRequest, UserRole }
