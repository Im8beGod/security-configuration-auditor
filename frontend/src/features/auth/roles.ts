import type { UserRole } from '../../shared/types/auth'

export const TRAINING_ROLES: readonly UserRole[] = ['mapping_admin', 'admin']

export function canAccessTraining(role: UserRole | string): boolean {
  return role === 'mapping_admin' || role === 'admin'
}

export function userRoleLabel(role: UserRole): string {
  switch (role) {
    case 'analyst':
      return 'Analyst'
    case 'mapping_admin':
      return 'Mapping Admin'
    case 'admin':
      return 'Admin'
    default:
      return unknownRole(role)
  }
}

function unknownRole(_role: never): string {
  return 'Unknown role'
}
