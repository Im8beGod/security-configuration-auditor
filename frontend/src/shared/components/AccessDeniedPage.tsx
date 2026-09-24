export function AccessDeniedPage() {
  return (
    <section className="state-panel state-panel-error" aria-labelledby="access-denied-title">
      <span className="eyebrow">Authorization boundary</span>
      <h1 id="access-denied-title">Access denied</h1>
      <p>You do not have permission to view this page.</p>
    </section>
  )
}
