import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'

import { errorMessage } from '../../shared/workflowFormat'
import {
  previewRuntimeAssessmentPack, previewRuntimeProfile, previewRuntimeRule,
  publishRuntimeAssessmentPack, publishRuntimeProfile, publishRuntimeRule,
} from '../../shared/api/runtime'

const ruleExample = JSON.stringify({
  rule_id: 'acme.runtime.ssh-enabled',
  profile_version_ids: ['runtime.acme.edge@1.0.0'],
  canonical_field: 'management.remote.ssh.enabled',
  operator: 'equals', expected: true,
  title: 'SSH enabled', security_domain: 'management', severity: 'high',
  framework_references: [],
}, null, 2)

function ErrorText({ error }: { error: unknown }) {
  return error ? <p className="error-message" role="alert">{errorMessage(error)}</p> : null
}

export function RuntimeAdminPage() {
  const [profileFile, setProfileFile] = useState<File | null>(null)
  const [profileDigest, setProfileDigest] = useState('')
  const [ruleText, setRuleText] = useState(ruleExample)
  const [rulePayload, setRulePayload] = useState<unknown>()
  const [packFile, setPackFile] = useState<File | null>(null)
  const [packDigest, setPackDigest] = useState('')

  const profilePreview = useMutation({ mutationFn: () => previewRuntimeProfile(profileFile as File), onSuccess: (result) => setProfileDigest(result.preview_digest) })
  const profilePublish = useMutation({ mutationFn: () => publishRuntimeProfile(profileFile as File, profileDigest) })
  const rulePreview = useMutation({ mutationFn: () => { const payload = JSON.parse(ruleText) as unknown; return previewRuntimeRule(payload).then((result) => { setRulePayload(payload); return result }) } })
  const rulePublish = useMutation({ mutationFn: () => publishRuntimeRule(rulePayload) })
  const packPreview = useMutation({ mutationFn: () => previewRuntimeAssessmentPack(packFile as File), onSuccess: (result) => setPackDigest(String(result.source_digest ?? '')) })
  const packPublish = useMutation({ mutationFn: () => publishRuntimeAssessmentPack(packFile as File, packDigest) })

  return <section className="page-stack">
    <header className="page-heading"><div><span className="eyebrow">Administrator only</span><h1>Runtime publishing</h1><p>Publish tenant-scoped profiles, safe automatic rules, and versioned assessment packs. Every form uses the existing server preview and validation boundary.</p></div></header>
    <section className="panel form-grid"><div className="section-title span-two"><div><span className="eyebrow">1 · Profile manifest</span><h2>Create and publish a runtime profile</h2></div></div><label className="field span-two">Manifest JSON<input type="file" accept="application/json,.json" onChange={(event) => { setProfileFile(event.target.files?.[0] ?? null); setProfileDigest('') }} /></label><div className="button-row"><button className="button-primary" disabled={!profileFile || profilePreview.isPending} onClick={() => profilePreview.mutate()}>Preview profile</button><button disabled={!profileFile || !profileDigest || profilePublish.isPending} onClick={() => profilePublish.mutate()}>Publish profile</button></div><ErrorText error={profilePreview.error ?? profilePublish.error} />{profilePreview.data && <p className="quiet-state">Validated {profilePreview.data.profile_version_id}; publish digest {profileDigest.slice(0, 12)}…</p>}{profilePublish.data && <p className="success-message">Profile published: {profilePublish.data.profile_version_id}</p>}</section>
    <section className="panel form-grid"><div className="section-title span-two"><div><span className="eyebrow">2 · Automatic rule</span><h2>Create and publish a safe runtime rule</h2></div></div><label className="field span-two">Rule JSON<textarea rows={14} value={ruleText} onChange={(event) => { setRuleText(event.target.value); setRulePayload(undefined) }} /></label><div className="button-row"><button className="button-primary" disabled={rulePreview.isPending} onClick={() => rulePreview.mutate()}>Preview rule</button><button disabled={!rulePayload || rulePublish.isPending} onClick={() => rulePublish.mutate()}>Publish rule</button></div><ErrorText error={rulePreview.error ?? rulePublish.error} />{rulePreview.data && <p className="quiet-state">Validated {rulePreview.data.rule_id} using {rulePreview.data.operator} on {rulePreview.data.canonical_field}.</p>}{rulePublish.data && <p className="success-message">Rule published: {rulePublish.data.runtime_rule_version_id}</p>}</section>
    <section className="panel form-grid"><div className="section-title span-two"><div><span className="eyebrow">3 · Assessment pack</span><h2>Create and publish a runtime assessment pack</h2></div></div><label className="field span-two">Pack JSON<input type="file" accept="application/json,.json" onChange={(event) => { setPackFile(event.target.files?.[0] ?? null); setPackDigest('') }} /></label><div className="button-row"><button className="button-primary" disabled={!packFile || packPreview.isPending} onClick={() => packPreview.mutate()}>Preview pack</button><button disabled={!packFile || !packDigest || packPublish.isPending} onClick={() => packPublish.mutate()}>Publish pack</button></div><ErrorText error={packPreview.error ?? packPublish.error} />{packPreview.data && <p className="quiet-state">Validated pack digest {packDigest.slice(0, 12)}…</p>}{packPublish.data && <p className="success-message">Assessment pack published: {packPublish.data.assessment_pack_version_id}</p>}</section>
  </section>
}
