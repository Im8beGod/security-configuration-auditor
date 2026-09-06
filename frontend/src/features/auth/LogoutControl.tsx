import { useLogoutMutation } from './useAuthMutations'

export function LogoutControl() {
  const logout = useLogoutMutation()

  return (
    <div className="logout-control">
      <button
        type="button"
        disabled={logout.isPending}
        onClick={() => logout.mutate()}
      >
        {logout.isPending ? 'Signing out…' : 'Sign out'}
      </button>
      {logout.isError && <p role="alert">Sign out failed. Please try again.</p>}
    </div>
  )
}
