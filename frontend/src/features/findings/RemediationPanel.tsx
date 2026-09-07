import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { getRemediation, previewRemediation } from '../../shared/api/findings'

export function RemediationPanel({ findingId }: { findingId: string }) {
  const query = useQuery({ queryKey: ['findings', findingId, 'remediation'], queryFn: () => getRemediation(findingId) })
  const [values, setValues] = useState<Record<string, string>>({})
  const preview = useMutation({ mutationFn: () => previewRemediation(findingId, values) })

  if (query.isPending) return <section className="panel"><h2>Remediation</h2><p className="quiet-state">Loading reviewed remediation guidance...</p></section>
  if (query.isError || !query.data || query.data.status === 'unavailable') return <section className="panel"><h2>Remediation</h2><p>Remediation guidance is not available for this exact supported profile/version.</p></section>
  if (query.data.status === 'not_required') return <section className="panel"><h2>Remediation</h2><p>No remediation is required for this Finding's current verdict.</p></section>

  const item = preview.data ?? query.data
  const steps = item.rendered_steps ?? item.ordered_steps?.map((step) => step.text ?? '') ?? []
  return <section className="panel page-stack"><div><span className="eyebrow">How to fix this</span><h2>{item.title}</h2><p>{item.security_objective}</p></div>{item.safety_warnings?.map((warning) => <p className="boundary-note" key={warning}>{warning}</p>)}{item.required_parameters?.length ? <form className="form-grid" onSubmit={(event) => { event.preventDefault(); preview.mutate() }}>{item.required_parameters.map((field) => <label className="field" key={field.name}>{field.label ?? field.name}<input required={field.required !== false} value={values[field.name] ?? ''} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })} /></label>)}<button className="button-primary" disabled={preview.isPending}>Preview reviewed steps</button>{preview.isError && <p className="error-message" role="alert">Parameters could not be validated safely.</p>}</form> : null}{steps.map((step) => <pre className="evidence-excerpt" key={step}>{step}</pre>)}{item.verification_steps?.length ? <details><summary>Verify</summary>{item.verification_steps.map((step) => <pre className="evidence-excerpt" key={step.text}>{step.text}</pre>)}</details> : null}{item.rollback_steps?.length ? <details><summary>Rollback</summary>{item.rollback_steps.map((step) => <pre className="evidence-excerpt" key={step.text}>{step.text}</pre>)}</details> : null}<details><summary>Procedure provenance</summary><p>{item.procedure_key} · version {item.procedure_version} · {item.selection_source}</p></details></section>
}
