import { createBrowserRouter, Navigate } from 'react-router-dom'

import { AuthenticatedAppLayout } from '../AuthenticatedAppLayout'
import { AuditsPage } from '../../features/audits/AuditsPage'
import { LoginPage } from '../../features/auth/LoginPage'
import { RequireAuth } from '../../features/auth/RequireAuth'
import { RequireRole } from '../../features/auth/RequireRole'
import { TRAINING_ROLES } from '../../features/auth/roles'
import { DashboardPage } from '../../features/dashboard/DashboardPage'
import { DevicesPage } from '../../features/devices/DevicesPage'
import { FindingsPage } from '../../features/findings/FindingsPage'
import { ReportsPage } from '../../features/reports/ReportsPage'
import { TrainingPage } from '../../features/training/TrainingPage'
import { NotFoundPage } from '../../shared/components/NotFoundPage'

export const router = createBrowserRouter([
  { path: '/', element: <Navigate to="/dashboard" replace /> },
  { path: '/login', element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <AuthenticatedAppLayout />,
        children: [
          { path: '/dashboard', element: <DashboardPage /> },
          { path: '/devices', element: <DevicesPage /> },
          { path: '/audits', element: <AuditsPage /> },
          { path: '/findings', element: <FindingsPage /> },
          { path: '/reports', element: <ReportsPage /> },
          {
            element: <RequireRole allowedRoles={TRAINING_ROLES} />,
            children: [{ path: '/training', element: <TrainingPage /> }],
          },
          { path: '*', element: <NotFoundPage /> },
        ],
      },
    ],
  },
])
