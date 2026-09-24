interface PlaceholderPageProps {
  title: string
  description: string
}

export function PlaceholderPage({ title, description }: PlaceholderPageProps) {
  return (
    <section className="state-panel" aria-labelledby="placeholder-title">
      <span className="eyebrow">Workspace</span>
      <h1 id="placeholder-title">{title}</h1>
      <p>{description}</p>
    </section>
  )
}
