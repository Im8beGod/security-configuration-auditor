import { useQuery, type QueryClient } from '@tanstack/react-query'

import { getCurrentUser, type AuthUser } from '../../shared/api/auth'
import { ApiError } from '../../shared/api/client'

export const currentUserQueryKey = ['auth', 'me'] as const

async function resolveCurrentUser(): Promise<AuthUser | null> {
  try {
    return await getCurrentUser()
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return null
    }
    throw error
  }
}

export function useCurrentUser() {
  return useQuery({
    queryKey: currentUserQueryKey,
    queryFn: resolveCurrentUser,
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.status === 401) && failureCount < 1,
    refetchOnWindowFocus: false,
  })
}

export function clearAuthenticatedQueries(queryClient: QueryClient): void {
  queryClient.removeQueries()
  queryClient.setQueryData<AuthUser | null>(currentUserQueryKey, null)
}

export function handleSessionExpiry(
  queryClient: QueryClient,
  error: unknown,
): boolean {
  if (!(error instanceof ApiError) || error.status !== 401) {
    return false
  }
  clearAuthenticatedQueries(queryClient)
  return true
}
