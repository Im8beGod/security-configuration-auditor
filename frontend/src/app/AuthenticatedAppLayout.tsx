import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

import { LogoutControl } from '../features/auth/LogoutControl'
import { canAccessTraining, userRoleLabel } from '../features/auth/roles'
import type { AuthUser } from '../shared/types/auth'

const primaryNavigation = [
  { to: '/dashboard', label: 'Dashboard', icon: '⌂' },
  { to: '/uploads', label: 'Upload / Evidence', icon: '↥' },
  { to: '/devices', label: 'Devices', icon: '◈' },
  { to: '/audits', label: 'Audits', icon: '◷' },
  { to: '/findings', label: 'Findings', icon: '!' },
  { to: '/reports', label: 'Reports', icon: '▤' },
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
        <div className="shell-status" aria-label="System status"><span className="status-pulse" />Audit engine online</div>
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
          <span className="nav-label">Overview</span>
          <ul>
            {primaryNavigation.map((item) => (
              <li key={item.to}>
                <NavLink to={item.to}><span className="nav-icon" aria-hidden="true">{item.icon}</span><span>{item.label}</span></NavLink>
              </li>
            ))}
            {canAccessTraining(currentUser.role) && (
              <li className="nav-advanced">
                <NavLink to="/training"><span className="nav-icon" aria-hidden="true">◇</span><span>Training</span></NavLink>
              </li>
            )}
            {currentUser.role === 'admin' && <li className="nav-advanced"><NavLink to="/admin/runtime"><span className="nav-icon" aria-hidden="true">⚙</span><span>Runtime publishing</span></NavLink></li>}
          </ul>
        </nav>

        <main className="app-content">
          <Outlet context={currentUser} />
        </main>
      </div>
    </div>
  )
}
