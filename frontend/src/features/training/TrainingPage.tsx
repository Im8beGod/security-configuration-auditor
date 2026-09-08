import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'

import { listKnowledgePacks, listKnowledgePackVersions, listTrainingProfiles, listUnresolved, trainingKeys } from '../../shared/api/training'
import { QueryState, StatusBadge } from '../../shared/components/WorkflowUi'
import type { KnowledgePack, ReviewStatus } from '../../shared/types/training'

const statuses: Array<{ value: ReviewStatus | ''; label: string }> = [
  { value: '', label: 'All review states' }, { value: 'open', label: 'Open' },
  { value: 'under_review', label: 'Under review' }, { value: 'mapped', label: 'Mapped' },
  { value: 'dismissed', label: 'Dismissed' }, { value: 'not_actionable', label: 'Not actionable' },
]

function PackHistory({ pack }: { pack: KnowledgePack }) {
  const versions = useQuery({ queryKey: trainingKeys.packVersions(pack.knowledge_pack_id), queryFn: () => listKnowledgePackVersions(pack.knowledge_pack_id) })
  return <article className="pack-card"><div><strong>{pack.name}</strong><span>{pack.pack_key}</span></div>{versions.isPending ? <small>Loading versions...</small> : versions.isError ? <small>Version history unavailable</small> : <ol>{versions.data?.map((version) => <li key={version.knowledge_pack_version_id}><span>Version {version.version}</span><small>{version.mapping_version_ids.length} published mapping{version.mapping_version_ids.length === 1 ? '' : 's'} · {new Date(version.published_at).toLocaleString()}</small></li>)}</ol>}</article>
}

export function TrainingPage() {
  const [params, setParams] = useSearchParams()
  const requested = params.get('status') ?? ''
  const status = statuses.some((item) => item.value === requested) ? requested as ReviewStatus | '' : ''
  const unresolved = useQuery({ queryKey: trainingKeys.unresolved(status), queryFn: () => listUnresolved(status) })
  const packs = useQuery({ queryKey: trainingKeys.packs, queryFn: listKnowledgePacks })
  const profiles = useQuery({ queryKey: trainingKeys.profiles, queryFn: listTrainingProfiles })

  return <section className="page-stack training-page">
    <header className="page-heading"><div><span className="eyebrow">Administrator-supervised learning</span><h1>Review Center</h1><p>Turn unresolved syntax into bounded canonical mappings. Deterministic validation and human approval remain mandatory.</p></div><div className="button-row"><Link className="button-primary" to="/training/mappings/new">Create mapping</Link><span className="trust-chip">AI advisory only</span></div></header>
    <section className="panel review-toolbar"><label>Review status<select value={status} onChange={(event) => setParams(event.target.value ? { status: event.target.value } : {})}>{statuses.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label><div><strong>{unresolved.data?.length ?? 0}</strong><span>visible items</span></div></section>
    <QueryState pending={unresolved.isPending} error={unresolved.error} empty={unresolved.data?.length === 0 ? 'No unresolved evidence is waiting in this review state.' : undefined}>
      <div className="review-grid">{unresolved.data?.map((item) => <Link className="review-card" to={`/training/unresolved/${item.unresolved_block_id}`} key={item.unresolved_block_id}><div className="review-card-head"><span className="eyebrow">{item.profile_id ?? 'Unresolved profile'}</span><StatusBadge value={item.review_status} /></div><code>{item.raw_text}</code><p>{item.unknown_reason.replaceAll('_', ' ')}</p><dl><div><dt>Audit</dt><dd>{item.audit_id.slice(0, 8)}</dd></div><div><dt>Evidence</dt><dd>{item.evidence_refs.length}</dd></div></dl></Link>)}</div>
    </QueryState>
    <section className="page-stack"><div className="section-title"><div><span className="eyebrow">Immutable publication history</span><h2>Knowledge Packs</h2></div></div><QueryState pending={packs.isPending} error={packs.error} empty={packs.data?.length === 0 ? 'No administrator mapping pack has been published yet.' : undefined}><div className="pack-grid">{packs.data?.map((pack) => <PackHistory pack={pack} key={pack.knowledge_pack_id} />)}</div></QueryState></section>
    <section className="page-stack"><div className="section-title"><div><span className="eyebrow">Declarative profile registry</span><h2>Supported profile versions</h2></div></div><QueryState pending={profiles.isPending} error={profiles.error} empty="No published profile manifests are available."><div className="pack-grid">{profiles.data?.map((profile) => <article className="pack-card" key={profile.profile_version_id}><strong>{profile.vendor} {profile.product_family}</strong><span>{profile.profile_version_id} · {profile.reader ?? 'No structural reader'}</span><small>{String(profile.coverage.supported_version_family ?? 'Applicability is version constrained.')}</small></article>)}</div></QueryState></section>
  </section>
}
