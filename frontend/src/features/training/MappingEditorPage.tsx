import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { listArtifacts } from '../../shared/api/workflow'
import { approveMapping, createMapping, getMapping, listTrainingProfiles, publishMapping, trainingKeys, updateMapping, validateMapping } from '../../shared/api/training'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import type { Artifact } from '../../shared/types/workflow'
import type { MappingDefinition, MappingVersion } from '../../shared/types/training'

const emptyDefinition = (profileVersionId: string): MappingDefinition => ({
  profile_applicability: { profile_version_ids: [profileVersionId] },
  structural_match: { operation: 'xml_path', command: 'xml', xml_path: { path: [], source: 'text', capture: 'value', value_type: 'string', start_mode: 'document_root' } },
  target_field_id: 'management.remote.ssh.enabled',
  value_extraction: { operation: 'capture', capture: 'value', output_type: 'string' },
  unit_conversion: { operation: 'none' }, scope_resolution: { strategy: 'device' },
  negation_behavior: { operation: 'unsupported' }, removal_behavior: { operation: 'unsupported' },
  default_behavior: { operation: 'unknown' }, examples: [],
})

const definitionOf = (mapping: MappingVersion): MappingDefinition => ({
  profile_applicability: mapping.profile_applicability, structural_match: mapping.structural_match,
  target_field_id: mapping.target_field_id, value_extraction: mapping.value_extraction,
  unit_conversion: mapping.unit_conversion, scope_resolution: mapping.scope_resolution,
  negation_behavior: mapping.negation_behavior, removal_behavior: mapping.removal_behavior,
  default_behavior: mapping.default_behavior, examples: mapping.examples,
})

function SemanticResult({ mapping }: { mapping: MappingVersion }) {
  const semantic = (mapping.validation_results.semantic ?? {}) as Record<string, any>
  if (!mapping.validation_results.semantic) return null
  return <section className="panel"><div className="section-title"><div><span className="eyebrow">Executable evidence result</span><h2>{String(semantic.status ?? 'unavailable').replaceAll('_', ' ')}</h2></div></div><dl className="detail-grid"><div><dt>Evidence</dt><dd>{semantic.evidence_filename ?? 'Not provided'}</dd></div><div><dt>Reader</dt><dd>{semantic.reader_id ?? 'Unavailable'}</dd></div><div><dt>Matched paths</dt><dd>{Array.isArray(semantic.matched_paths) ? semantic.matched_paths.length : 0}</dd></div></dl><h3>Matched structural paths</h3><pre className="evidence-excerpt">{JSON.stringify(semantic.matched_paths ?? [], null, 2)}</pre><h3>Candidate SecurityFacts</h3><pre className="evidence-excerpt">{JSON.stringify(semantic.facts ?? [], null, 2)}</pre><h3>Candidate EffectiveStates</h3><pre className="evidence-excerpt">{JSON.stringify(semantic.effective_states ?? [], null, 2)}</pre></section>
}

export function MappingEditorPage() {
  const { mappingId } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const existing = useQuery({ queryKey: ['training-mapping', mappingId], queryFn: () => getMapping(mappingId as string), enabled: Boolean(mappingId), refetchInterval: (query) => query.state.data?.status === 'testing' ? 1000 : false })
  const profiles = useQuery({ queryKey: trainingKeys.profiles, queryFn: listTrainingProfiles })
  const artifacts = useQuery({ queryKey: ['artifacts'], queryFn: () => listArtifacts(false) })
  const [mappingKey, setMappingKey] = useState('juniper.junos.mapping')
  const [title, setTitle] = useState('Juniper declarative mapping')
  const [description, setDescription] = useState('Administrator-reviewed bounded mapping')
  const [profileVersionId, setProfileVersionId] = useState('juniper.junos.18@1.0.0')
  const [definitionText, setDefinitionText] = useState(JSON.stringify(emptyDefinition('juniper.junos.18@1.0.0'), null, 2))
  const [artifactId, setArtifactId] = useState('')

  useEffect(() => {
    if (!existing.data) return
    setMappingKey(existing.data.mapping_key); setTitle(existing.data.title); setDescription(existing.data.description)
    setProfileVersionId(existing.data.profile_applicability.profile_version_ids[0] ?? profileVersionId)
    setDefinitionText(JSON.stringify(definitionOf(existing.data), null, 2))
  }, [existing.data])

  const save = useMutation({ mutationFn: async () => {
    let definition: MappingDefinition
    try { definition = JSON.parse(definitionText) as MappingDefinition } catch { throw new Error('MappingDefinition JSON is invalid') }
    return mappingId ? updateMapping(existing.data as MappingVersion, { title, description, definition }) : createMapping({ mapping_key: mappingKey, title, description, definition })
  }, onSuccess: (mapping) => { void navigate(`/training/mappings/${mapping.mapping_version_id}`) } })
  const validate = useMutation({ mutationFn: () => validateMapping(mappingId as string, artifactId || undefined), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['training-mapping', mappingId] }) })
  const approve = useMutation({ mutationFn: () => approveMapping(mappingId as string), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['training-mapping', mappingId] }) })
  const publish = useMutation({ mutationFn: () => publishMapping(mappingId as string), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['training-mapping', mappingId] }) })
  const selected = existing.data
  const readyArtifacts = (artifacts.data ?? []).filter((item: Artifact) => item.status === 'ready' && item.snapshot_id)
  const profileOptions = profiles.data ?? []

  return <section className="page-stack training-detail"><Link className="back-link" to="/training">← Review Center</Link><header className="page-heading"><div><span className="eyebrow">Bounded declarative controls</span><h1>{selected ? selected.title : 'Create Mapping'}</h1><p>Server validation remains authoritative. No code, regex, shell, or executable expressions are accepted.</p></div>{selected && <StatusBadge value={selected.status} />}</header><QueryState pending={Boolean(mappingId) && existing.isPending} error={existing.error}><>{!selected && <section className="panel form-grid"><label className="field">Mapping key<input value={mappingKey} onChange={(event) => setMappingKey(event.target.value)} /></label><label className="field">Compatible profile<select value={profileVersionId} onChange={(event) => { setProfileVersionId(event.target.value); setDefinitionText(JSON.stringify(emptyDefinition(event.target.value), null, 2)) }}>{profileOptions.map((profile) => <option key={profile.profile_version_id} value={profile.profile_version_id}>{profile.profile_version_id}</option>)}</select></label></section>}<section className="panel form-grid"><label className="field">Title<input value={title} onChange={(event) => setTitle(event.target.value)} /></label><label className="field span-two">Description<textarea rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></label><label className="field span-two">Complete MappingDefinition JSON<small>Lossless editor for profile applicability, xml_path segments, occurrence/index, namespace, extraction, and scope.</small><textarea rows={24} value={definitionText} onChange={(event) => setDefinitionText(event.target.value)} /></label></section>{save.isError && <p className="error-message" role="alert">{(save.error as Error).message}</p>}<div className="button-row"><button className="button-primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving...' : selected ? 'Save draft' : 'Create draft Mapping'}</button></div>{selected && <><section className="panel"><div className="section-title"><div><span className="eyebrow">Development evidence</span><h2>Run executable validation</h2></div></div><label className="field">Evidence artifact<select value={artifactId} onChange={(event) => setArtifactId(event.target.value)}><option value="">Use examples only</option>{readyArtifacts.map((artifact) => <option key={artifact.artifact_id} value={artifact.artifact_id}>{artifact.original_filename} · {artifact.evidence_type}</option>)}</select></label><div className="button-row">{['draft', 'testing'].includes(selected.status) && <button className="button-primary" disabled={validate.isPending || selected.status === 'testing'} onClick={() => validate.mutate()}>{validate.isPending ? 'Queueing...' : 'Validate selected evidence'}</button>}{selected.status === 'testing' && <span className="quiet-state">Validation is running. This page refreshes automatically.</span>}{selected.status === 'testing' && selected.validation_results.passed === true && <button className="button-primary" onClick={() => approve.mutate()}>Approve mapping</button>}{selected.status === 'approved' && <button className="button-primary" onClick={() => publish.mutate()}>Publish immutable Mapping</button>}</div></section><SemanticResult mapping={selected} /></>}</></QueryState></section>
}
