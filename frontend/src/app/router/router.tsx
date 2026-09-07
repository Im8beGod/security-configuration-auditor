import { createBrowserRouter, Navigate } from 'react-router-dom'

import { AuthenticatedAppLayout } from '../AuthenticatedAppLayout'
import { AuditsPage } from '../../features/audits/AuditsPage'
import { AuditDetailPage } from '../../features/audits/AuditDetailPage'
import { LoginPage } from '../../features/auth/LoginPage'
import { RequireAuth } from '../../features/auth/RequireAuth'
import { RequireRole } from '../../features/auth/RequireRole'
import { TRAINING_ROLES } from '../../features/auth/roles'
import { DashboardPage } from '../../features/dashboard/DashboardPage'
import { DevicesPage } from '../../features/devices/DevicesPage'
import { DeviceDetailPage } from '../../features/devices/DeviceDetailPage'
import { SnapshotDetailPage } from '../../features/devices/SnapshotDetailPage'
import { FindingsPage } from '../../features/findings/FindingsPage'
import { FindingDetailPage } from '../../features/findings/FindingDetailPage'
import { ReportsPage } from '../../features/reports/ReportsPage'
import { TrainingPage } from '../../features/training/TrainingPage'
import { UploadsPage } from '../../features/uploads/UploadsPage'
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
          { path: '/uploads', element: <UploadsPage /> },
          { path: '/devices', element: <DevicesPage /> },
          { path: '/devices/:deviceId', element: <DeviceDetailPage /> },
          { path: '/snapshots/:snapshotId', element: <SnapshotDetailPage /> },
          { path: '/audits', element: <AuditsPage /> },
          { path: '/audits/:auditId', element: <AuditDetailPage /> },
          { path: '/findings', element: <FindingsPage /> },
          { path: '/findings/:findingId', element: <FindingDetailPage /> },
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
