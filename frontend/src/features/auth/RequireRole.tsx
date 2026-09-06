import { Outlet, useOutletContext } from 'react-router-dom'

import { AccessDeniedPage } from '../../shared/components/AccessDeniedPage'
import type { AuthUser, UserRole } from '../../shared/types/auth'

interface RequireRoleProps {
  allowedRoles: readonly UserRole[]
}

export function RequireRole({ allowedRoles }: RequireRoleProps) {
  const currentUser = useOutletContext<AuthUser>()

  if (!allowedRoles.includes(currentUser.role)) {
    return <AccessDeniedPage />
  }
  return <Outlet context={currentUser} />
}
