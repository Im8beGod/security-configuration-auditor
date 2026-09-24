import { NavLink, Outlet, useOutletContext } from 'react-router-dom'

import { LogoutControl } from '../features/auth/LogoutControl'
import { canAccessTraining, userRoleLabel } from '../features/auth/roles'
import type { AuthUser } from '../shared/types/auth'

const primaryNavigation = [
  { to: '/dashboard', label: 'Dashboard', icon: 'dashboard' },
  { to: '/uploads', label: 'Upload / Evidence', icon: 'upload' },
  { to: '/devices', label: 'Devices', icon: 'devices' },
  { to: '/audits', label: 'Audits', icon: 'audits' },
  { to: '/findings', label: 'Findings', icon: 'findings' },
  { to: '/reports', label: 'Reports', icon: 'reports' },
] as const

type NavIconName = (typeof primaryNavigation)[number]['icon'] | 'training' | 'runtime'

function NavIcon({ name }: { name: NavIconName }) {
  const paths: Record<NavIconName, string> = {
    dashboard: 'M3 10.5 12 3l9 7.5M5.5 9v10h13V9M9 19v-5h6v5',
    upload: 'M12 16V4m0 0L8 8m4-4 4 4M4 14v5h16v-5',
    devices: 'M4 5h16v14H4zM8 9h8M8 13h5',
    audits: 'M7 3h10v18H7zM9.5 7h5M9.5 11h5M9.5 15h3',
    findings: 'M12 3 21 19H3L12 3zm0 5v5m0 3h.01',
    reports: 'M6 3h9l3 3v15H6zM9 11h6M9 15h6M9 7h4',
    training: 'M4 5h16v14H4zM8 9h8M8 13h5',
    runtime: 'M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  }
  return <svg className="nav-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>
}

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
                <NavLink to={item.to}><span className="nav-icon"><NavIcon name={item.icon} /></span><span>{item.label}</span></NavLink>
              </li>
            ))}
            {canAccessTraining(currentUser.role) && (
              <li className="nav-advanced">
                <NavLink to="/training"><span className="nav-icon"><NavIcon name="training" /></span><span>Training</span></NavLink>
              </li>
            )}
            {currentUser.role === 'admin' && <li className="nav-advanced"><NavLink to="/admin/runtime"><span className="nav-icon"><NavIcon name="runtime" /></span><span>Runtime publishing</span></NavLink></li>}
          </ul>
        </nav>

        <main className="app-content">
          <Outlet context={currentUser} />
        </main>
      </div>
    </div>
  )
}
