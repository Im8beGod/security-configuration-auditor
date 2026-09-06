import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

import { LogoutControl } from '../features/auth/LogoutControl'
import { canAccessTraining, userRoleLabel } from '../features/auth/roles'
import type { AuthUser } from '../shared/types/auth'

const primaryNavigation = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/uploads', label: 'Upload / Evidence' },
  { to: '/devices', label: 'Devices' },
  { to: '/audits', label: 'Audits' },
  { to: '/findings', label: 'Findings' },
  { to: '/reports', label: 'Reports' },
] as const

export function AuthenticatedAppLayout() {
  const currentUser = useOutletContext<AuthUser>()

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="project-identity">
          <span className="project-mark" aria-hidden="true">SIH</span>
          <div>
            <strong>Security Configuration Auditor</strong>
            <span>SIH 26155</span>
          </div>
        </div>
        <div className="account-summary">
          <div>
            <strong>{currentUser.email}</strong>
            <span>{userRoleLabel(currentUser.role)}</span>
          </div>
          <LogoutControl />
        </div>
      </header>

      <div className="app-body">
        <nav className="primary-navigation" aria-label="Primary">
          <ul>
            {primaryNavigation.map((item) => (
              <li key={item.to}>
                <NavLink to={item.to}>{item.label}</NavLink>
              </li>
            ))}
            {canAccessTraining(currentUser.role) && (
              <li>
                <NavLink to="/training">Training</NavLink>
              </li>
            )}
          </ul>
        </nav>

        <main className="app-content">
          <Outlet context={currentUser} />
        </main>
      </div>
    </div>
  )
}
