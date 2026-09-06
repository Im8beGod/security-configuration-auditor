import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'

import {
  login,
  logout,
  type AuthUser,
  type LoginRequest,
} from '../../shared/api/auth'
import { clearAuthenticatedQueries, currentUserQueryKey } from './authState'

export function useLoginMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (credentials: LoginRequest) => login(credentials),
    onSuccess: (user: AuthUser) => {
      queryClient.setQueryData(currentUserQueryKey, user)
    },
  })
}

export function useLogoutMutation() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  return useMutation({
    mutationFn: logout,
    onSuccess: () => {
      clearAuthenticatedQueries(queryClient)
      navigate('/login', { replace: true })
    },
  })
}
