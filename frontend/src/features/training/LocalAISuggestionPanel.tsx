import type { LocalAIStatus, MappingSuggestionPreview } from '../../shared/types/training'
import { errorMessage } from '../../shared/workflowFormat'

interface Props {
  status?: LocalAIStatus
  statusError?: unknown
  preview?: MappingSuggestionPreview
  pending: boolean
  adopting: boolean
  error?: unknown
  onRefresh: () => void
  onSuggest: () => void
  onAdopt: () => void
  onDiscard: () => void
}

export function LocalAISuggestionPanel({ status, statusError, preview, pending, adopting, error, onRefresh, onSuggest, onAdopt, onDiscard }: Props) {
  return <section className="panel ai-entry">
    <div><span className="eyebrow">Optional assistance</span><h2>Suggest with local AI</h2>
      <p>{status ? `${status.provider} / ${status.model}: ${status.reason}` : statusError ? 'Local AI availability could not be checked. Manual authoring remains available.' : 'Checking local AI availability...'}</p>
      <button className="button-secondary" onClick={onRefresh}>Refresh availability</button>
      <p>Only redacted, minimized context is sent. Suggestions have no approval or publication authority.</p>
    </div>
    <button className="button-secondary" onClick={onSuggest} disabled={pending || adopting || !status?.available}>{pending ? 'Requesting...' : 'Suggest with local AI'}</button>
    {preview && <article className="page-stack">
      <h3>AI suggestion / unreviewed: {preview.suggestion.definition.target_field_id}</h3>
      <p>{preview.suggestion.description}</p>
      <p>Provider/model: {preview.suggestion.provider_metadata.provider} / {preview.suggestion.provider_metadata.model}</p>
      <p>Advisory confidence: {Math.round(preview.suggestion.confidence * 100)}%</p>
      <ul>{preview.suggestion.caveats.map((item, index) => <li key={index}>{item}</li>)}</ul>
      <p>{preview.validation}</p>
      <p>Redaction occurred: {preview.redaction_occurred ? 'yes' : 'no'}. Evidence truncated: {preview.truncation_occurred ? 'yes' : 'no'}.</p>
      <details open><summary>Redacted evidence considered</summary><pre className="evidence-excerpt">{JSON.stringify(preview.evidence, null, 2)}</pre></details>
      <details><summary>Source artifact references</summary><pre className="evidence-excerpt">{JSON.stringify(preview.evidence_references, null, 2)}</pre></details>
      <details open><summary>Proposed MappingDefinition</summary><pre className="evidence-excerpt">{JSON.stringify(preview.suggestion.definition, null, 2)}</pre></details>
      <p>Use as draft to edit the complete definition in the normal mapping editor.</p>
      <div className="button-row">
        <button className="button-primary" disabled={adopting || pending} onClick={onAdopt}>Use as draft</button>
        <button className="button-secondary" disabled={adopting} onClick={onDiscard}>Discard</button>
      </div>
    </article>}
    {Boolean(error) && <div><p className="error-message" role="alert">{errorMessage(error)}</p><p className="quiet-state">AI is optional. Continue with the manual Mapping editor below.</p></div>}
  </section>
}
