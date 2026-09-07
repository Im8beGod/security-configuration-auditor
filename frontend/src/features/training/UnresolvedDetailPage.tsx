import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { approveMapping, createMapping, getImpact, getMapping, getUnresolved, listCanonicalFields, publishMapping, suggestMapping, trainingKeys, updateMapping, validateMapping } from '../../shared/api/training'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import type { CanonicalField, MappingDefinition, MappingVersion, UnresolvedBlock, ValidationFamily } from '../../shared/types/training'
import { errorMessage } from '../../shared/workflowFormat'

const validationFamilies: ValidationFamily[] = ['positive', 'alternate_values', 'negative', 'wrong_scope', 'negation', 'conflict', 'regression']

function mappingDefinition(mapping: MappingVersion): MappingDefinition {
  return { profile_applicability: mapping.profile_applicability, structural_match: mapping.structural_match, target_field_id: mapping.target_field_id, value_extraction: mapping.value_extraction, unit_conversion: mapping.unit_conversion, scope_resolution: mapping.scope_resolution, negation_behavior: mapping.negation_behavior, removal_behavior: mapping.removal_behavior, default_behavior: mapping.default_behavior, examples: mapping.examples }
}

function buildDefinition(field: CanonicalField, profileVersion: string, command: string, parentCommand: string, literalText: string): MappingDefinition {
  const literals = literalText.trim() ? literalText.trim().split(/\s+/) : []
  const patterns: Record<string, unknown>[] = literals.map((value) => ({ operation: 'literal', value }))
  const expectedType = field.expected_types.includes('boolean') ? 'boolean' : field.expected_types.includes('duration') ? 'duration' : field.expected_types.includes('integer') ? 'integer' : field.expected_types.includes('string') ? 'string' : field.expected_types[0]
  let extraction: Record<string, unknown> = { operation: 'boolean_from_presence', output_type: 'boolean' }
  let sample = [...literals]
  let alternate = [...literals]
  let expected: unknown = true
  let alternateExpected: unknown = true
  if (expectedType === 'duration') {
    patterns.push({ operation: 'capture', name: 'minutes', value_type: 'integer' }, { operation: 'capture', name: 'seconds', value_type: 'integer' })
    extraction = { operation: 'duration_from_parts', parts: ['minutes', 'seconds'], output_type: 'duration' }
    sample = [...literals, '5', '0']; alternate = [...literals, '10', '30']; expected = 300; alternateExpected = 630
  } else if (expectedType === 'integer' || expectedType === 'number') {
    patterns.push({ operation: 'capture', name: 'value', value_type: expectedType })
    extraction = { operation: expectedType, capture: 'value', output_type: expectedType }
    sample = [...literals, '2']; alternate = [...literals, '3']; expected = expectedType === 'integer' ? 2 : 2; alternateExpected = 3
  } else if (expectedType !== 'boolean') {
    patterns.push({ operation: 'capture', name: 'value', value_type: 'string' })
    extraction = { operation: 'capture', capture: 'value', output_type: expectedType }
    sample = [...literals, 'example']; alternate = [...literals, 'alternate']; expected = 'example'; alternateExpected = 'alternate'
  }
  const scope = field.allowed_scope_types[0]
  const node = { command, arguments: sample, parent_command: parentCommand || null, scope_type: scope }
  const example = (family: ValidationFamily, candidate: Record<string, unknown>, expectedMatch: boolean, expectedValue?: unknown) => ({ family, node: candidate, expected_match: expectedMatch, ...(expectedValue === undefined ? {} : { expected_value: expectedValue }) })
  return {
    profile_applicability: { profile_version_ids: [profileVersion] },
    structural_match: { operation: 'command_equality', command, arguments: patterns, parent_command: parentCommand || null, ancestor_commands: [], scope_type: scope, negated: null },
    target_field_id: field.field_id,
    value_extraction: extraction,
    unit_conversion: { operation: 'none' }, scope_resolution: { strategy: scope },
    negation_behavior: { operation: 'reset_to_default' }, removal_behavior: { operation: 'remove_value' }, default_behavior: { operation: 'unknown' },
    examples: [
      example('positive', node, true, expected),
      example('alternate_values', { ...node, arguments: alternate }, true, alternateExpected),
      example('negative', { ...node, command: 'nonmatching-command' }, false),
      example('wrong_scope', { ...node, scope_type: 'wrong_scope' }, false),
      example('negation', { ...node, negated: true }, true, expected),
      example('conflict', node, true, expected),
      example('regression', { ...node, command: 'existing-owned-command' }, false),
    ],
  }
}

function MappingEditor({ block, fields, existing, onSaved }: { block: UnresolvedBlock; fields: CanonicalField[]; existing?: MappingVersion; onSaved: (mapping: MappingVersion) => void }) {
  const initialField = fields.find((field) => field.field_id === existing?.target_field_id) ?? fields.find((field) => block.candidate_field_ids.includes(field.field_id)) ?? fields[0]
  const existingMatch = existing?.structural_match
  const [fieldId, setFieldId] = useState(initialField.field_id)
  const [command, setCommand] = useState(typeof existingMatch?.command === 'string' ? existingMatch.command : typeof block.occurrence.command === 'string' ? block.occurrence.command : '')
  const [parent, setParent] = useState(typeof existingMatch?.parent_command === 'string' ? existingMatch.parent_command : typeof block.occurrence.parent_command === 'string' ? block.occurrence.parent_command : '')
  const [literals, setLiterals] = useState('')
  const [mappingKey, setMappingKey] = useState(existing?.mapping_key ?? `iosxe.${block.fingerprint.slice(0, 12)}`)
  const [title, setTitle] = useState(existing?.title ?? 'Reviewed unresolved syntax')
  const [description, setDescription] = useState(existing?.description ?? 'Administrator-authored bounded mapping for reviewed syntax.')
  const mutation = useMutation({
    mutationFn: () => {
      const field = fields.find((item) => item.field_id === fieldId) ?? initialField
      const definition = buildDefinition(field, block.profile_version_id ?? 'cisco.ios_xe.17@1.0.0', command, parent, literals)
      return existing ? updateMapping(existing, { title, description, definition }) : createMapping({ mapping_key: mappingKey, title, description, definition, unresolved_block_id: block.unresolved_block_id })
    },
    onSuccess: onSaved,
  })
  return <form className="panel mapping-editor" onSubmit={(event) => { event.preventDefault(); mutation.mutate() }}><div className="section-title"><div><span className="eyebrow">Bounded declarative controls</span><h2>{existing ? 'Edit draft Mapping' : 'Create Mapping manually'}</h2></div></div><p className="quiet-state">No code, regex, shell, or executable expressions are accepted. The server validates every operation and canonical field.</p><div className="form-grid"><label className="field">Mapping key<input required maxLength={255} value={mappingKey} disabled={Boolean(existing)} onChange={(event) => setMappingKey(event.target.value)} /></label><label className="field">Canonical target field<select value={fieldId} onChange={(event) => setFieldId(event.target.value)}>{fields.map((field) => <option key={field.field_id} value={field.field_id}>{field.field_id}</option>)}</select></label><label className="field">Title<input required maxLength={255} value={title} onChange={(event) => setTitle(event.target.value)} /></label><label className="field">Command equality<input required maxLength={100} value={command} onChange={(event) => setCommand(event.target.value)} /></label><label className="field">Parent command <small>optional</small><input maxLength={100} value={parent} onChange={(event) => setParent(event.target.value)} /></label><label className="field">Leading literal arguments <small>space separated</small><input value={literals} onChange={(event) => setLiterals(event.target.value)} /></label><label className="field span-two">Description<textarea required maxLength={2048} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></label></div>{mutation.isError && <p className="error-message" role="alert">{errorMessage(mutation.error)}</p>}<div className="button-row"><button className="button-primary" disabled={mutation.isPending}>{mutation.isPending ? 'Saving...' : existing ? 'Save revised draft' : 'Create draft Mapping'}</button></div></form>
}

function MappingWorkflow({ block, mappingId, fields }: { block: UnresolvedBlock; mappingId: string; fields: CanonicalField[] }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [showImpact, setShowImpact] = useState(false)
  const mapping = useQuery({ queryKey: trainingKeys.mapping(mappingId), queryFn: () => getMapping(mappingId), refetchInterval: (query) => query.state.data?.status === 'testing' ? 2000 : false })
  const refresh = async () => { await queryClient.invalidateQueries({ queryKey: trainingKeys.mapping(mappingId) }) }
  const adopt = useMutation({ mutationFn: () => updateMapping(mapping.data!, { title: mapping.data!.title, description: mapping.data!.description, definition: mappingDefinition(mapping.data!) }), onSuccess: refresh })
  const validate = useMutation({ mutationFn: () => validateMapping(mappingId), onSuccess: refresh })
  const approve = useMutation({ mutationFn: () => approveMapping(mappingId), onSuccess: refresh })
  const publish = useMutation({ mutationFn: () => publishMapping(mappingId), onSuccess: async () => { await refresh(); await queryClient.invalidateQueries({ queryKey: trainingKeys.packs }); await queryClient.invalidateQueries({ queryKey: trainingKeys.unresolvedDetail(block.unresolved_block_id) }) } })
  const impact = useQuery({ queryKey: trainingKeys.impact(mappingId), queryFn: () => getImpact(mappingId), enabled: showImpact })
  const actionError = adopt.error ?? validate.error ?? approve.error ?? publish.error
  if (mapping.isPending || mapping.isError || !mapping.data) return <QueryState pending={mapping.isPending} error={mapping.error}><span /></QueryState>
  const item = mapping.data
  const passed = item.validation_results.passed === true
  return <section className="page-stack"><article className="panel mapping-workflow"><div className="section-title"><div><span className="eyebrow">Mapping {item.mapping_key} · version {item.version}</span><h2>{item.title}</h2></div><StatusBadge value={item.status} /></div>{item.origin === 'ai_assisted' && <div className="ai-advisory"><strong>AI Suggested — Administrator Review Required</strong><span>Confidence is advisory only: {typeof item.ai_suggestion_metadata?.confidence === 'number' ? `${Math.round(item.ai_suggestion_metadata.confidence * 100)}%` : 'not supplied'}</span></div>}<p>{item.description}</p><dl className="detail-grid"><div><dt>Canonical field</dt><dd>{item.target_field_id}</dd></div><div><dt>Scope strategy</dt><dd>{String(item.scope_resolution.strategy).replaceAll('_', ' ')}</dd></div><div><dt>Origin</dt><dd>{item.origin.replaceAll('_', ' ')}</dd></div><div><dt>Knowledge Pack version</dt><dd>{item.knowledge_pack_version_id?.slice(0, 8) ?? 'Not published'}</dd></div></dl><details><summary>Bounded Mapping definition</summary><pre className="evidence-excerpt">{JSON.stringify(mappingDefinition(item), null, 2)}</pre></details><section className="validation-board"><h3>Deterministic validation</h3><div>{validationFamilies.map((family) => <article key={family}><span>{family.replaceAll('_', ' ')}</span><strong>{item.validation_results.families?.[family] === true ? 'Passed' : item.validation_results.families?.[family] === false ? 'Failed' : 'Not run'}</strong></article>)}</div></section>{actionError && <p className="error-message" role="alert">{errorMessage(actionError)}</p>}<div className="button-row">{item.status === 'suggested' && <button className="button-primary" onClick={() => adopt.mutate()} disabled={adopt.isPending}>Accept into administrator draft</button>}{['suggested', 'draft', 'testing'].includes(item.status) && <button className="button-secondary" onClick={() => setEditing((value) => !value)}>{editing ? 'Close editor' : 'Edit bounded Mapping'}</button>}{item.status === 'draft' && <button className="button-primary" onClick={() => validate.mutate()} disabled={validate.isPending}>Run seven-family validation</button>}{item.status === 'testing' && !passed && <button className="button-secondary" onClick={() => validate.mutate()} disabled={validate.isPending}>Run validation again</button>}{item.status === 'testing' && passed && <button className="button-primary" onClick={() => approve.mutate()} disabled={approve.isPending}>Approve as administrator</button>}{item.status === 'approved' && <button className="button-primary" onClick={() => publish.mutate()} disabled={publish.isPending}>Publish immutable Mapping</button>}{['published', 'superseded'].includes(item.status) && <button className="button-secondary" onClick={() => setShowImpact(true)}>Analyze read-only impact</button>}{['published', 'superseded'].includes(item.status) && <button disabled title="Historical re-evaluation begins in Step 12">Re-evaluate (Step 12)</button>}</div></article>{editing && <MappingEditor key={`${item.mapping_version_id}-${item.status}`} block={block} fields={fields} existing={item} onSaved={() => { setEditing(false); void refresh() }} />}{showImpact && <QueryState pending={impact.isPending} error={impact.error}><>{impact.data && <article className="panel impact-panel"><span className="eyebrow">Read-only impact analysis</span><h2>Potentially re-evaluable evidence</h2><div className="metric-grid"><article><span>Unresolved blocks</span><strong>{impact.data.matching_unresolved_block_ids.length}</strong></article><article><span>Affected devices</span><strong>{impact.data.affected_device_ids.length}</strong></article><article><span>Potentially affected UNKNOWN findings</span><strong>{impact.data.potentially_affected_unknown_findings}</strong></article></div><p className="boundary-note">This analysis creates no Audit revision and predicts no PASS or FAIL outcome.</p></article>}</></QueryState>}</section>
}

export function UnresolvedDetailPage() {
  const { unresolvedId = '' } = useParams()
  const queryClient = useQueryClient()
  const [mappingId, setMappingId] = useState<string | null>(null)
  const unresolved = useQuery({ queryKey: trainingKeys.unresolvedDetail(unresolvedId), queryFn: () => getUnresolved(unresolvedId), enabled: Boolean(unresolvedId) })
  const fields = useQuery({ queryKey: trainingKeys.fields, queryFn: listCanonicalFields })
  const suggest = useMutation({ mutationFn: () => suggestMapping(unresolvedId), onSuccess: async (mapping) => { setMappingId(mapping.mapping_version_id); await queryClient.invalidateQueries({ queryKey: trainingKeys.unresolvedDetail(unresolvedId) }) } })
  const block = unresolved.data
  const activeMappingId = mappingId ?? block?.assigned_mapping_version_id
  return <section className="page-stack training-detail"><Link className="back-link" to="/training">← Review Center</Link><QueryState pending={unresolved.isPending || fields.isPending} error={unresolved.error ?? fields.error}><>{block && fields.data && <><header className="page-heading"><div><span className="eyebrow">Unresolved evidence review</span><h1>{block.unknown_reason.replaceAll('_', ' ')}</h1><p>Original evidence remains unchanged. Review context before authoring any canonical mapping.</p></div><StatusBadge value={block.review_status} /></header><div className="training-context-grid"><article className="panel"><span className="eyebrow">Unresolved source</span><h2>Observed syntax</h2><pre className="evidence-excerpt">{block.raw_text}</pre><dl className="detail-grid"><div><dt>Profile</dt><dd>{block.profile_version_id ?? 'Unresolved'}</dd></div><div><dt>Audit</dt><dd>{block.audit_id}</dd></div><div><dt>Snapshot</dt><dd>{block.snapshot_id}</dd></div><div><dt>Fingerprint</dt><dd>{block.fingerprint.slice(0, 16)}</dd></div></dl></article><article className="panel"><span className="eyebrow">Bounded neighboring IR</span><h2>Surrounding context</h2><pre className="evidence-excerpt">{block.surrounding_context || 'No neighboring context was retained.'}</pre><details><summary>Evidence provenance</summary><pre className="evidence-excerpt">{JSON.stringify(block.evidence_refs, null, 2)}</pre></details><p><strong>Candidate fields:</strong> {block.candidate_field_ids.join(', ') || 'None determined'}</p><p><strong>Affected rules:</strong> {block.affected_rule_ids.join(', ') || 'Not deterministically known'}</p></article></div>{!activeMappingId && <section className="panel ai-entry"><div><span className="eyebrow">Optional assistance</span><h2>Request an AI suggestion</h2><p>Only redacted, minimized context is sent. Suggestions have no approval or publication authority.</p></div><button className="button-secondary" onClick={() => suggest.mutate()} disabled={suggest.isPending}>{suggest.isPending ? 'Requesting...' : 'Request AI suggestion'}</button>{suggest.isError && <div><p className="error-message" role="alert">{errorMessage(suggest.error)}</p><p className="quiet-state">AI is optional. Continue with the manual Mapping editor below.</p></div>}</section>}{activeMappingId ? <MappingWorkflow block={block} mappingId={activeMappingId} fields={fields.data} /> : <MappingEditor block={block} fields={fields.data} onSaved={(mapping) => { setMappingId(mapping.mapping_version_id); void queryClient.invalidateQueries({ queryKey: trainingKeys.unresolvedDetail(unresolvedId) }) }} />}</>}</></QueryState></section>
}
