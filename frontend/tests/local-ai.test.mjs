import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
after(() => server.close())
const { ApiError } = await server.ssrLoadModule('/src/shared/api/client.ts')
const { LocalAISuggestionPanel } = await server.ssrLoadModule('/src/features/training/LocalAISuggestionPanel.tsx')
const actions = { pending: false, adopting: false, onRefresh() {}, onSuggest() {}, onAdopt() {}, onDiscard() {} }
const render = (props) => renderToStaticMarkup(createElement(LocalAISuggestionPanel, { ...actions, ...props }))
const status = { provider: 'ollama', model: 'local-qwen', enabled: true, available: true, reason: 'Ready' }

test('renders provider availability and unavailable manual fallback', () => {
  assert.match(render({ status }), /ollama \/ local-qwen: Ready/)
  assert.match(render({ status: { ...status, available: false, reason: 'Unavailable' } }), /disabled=""/)
  assert.match(render({ statusError: new Error('offline') }), /Manual authoring remains available/)
})

test('renders loading and safe suggestion error states', () => {
  assert.match(render({ status, pending: true }), /Requesting/)
  const html = render({ status, error: new ApiError(422, 'Schema validation failed') })
  assert.match(html, /role="alert"/)
  assert.match(html, /Schema validation failed/)
  assert.match(html, /manual Mapping editor/)
})

test('full definition survives preview and adoption receives the same token', async () => {
  const definition = { structural_match: { operation: 'xml_path', xml_path: { path: [{ local_name: 'server', occurrence: 'any', namespace_uri: 'urn:example', index: 2 }], source: 'text', capture: 'value' } }, target_field_id: 'time.ntp.server', scope_resolution: { strategy: 'device', xml_unsupported_qualifier_paths: [['routing-instance']] }, examples: [] }
  const preview = { suggestion: { definition, description: '<script>untrusted</script>', confidence: 0.7, caveats: ['Review scope'], provider_metadata: { provider: 'ollama', model: 'local-qwen' } }, evidence_references: [{ artifact_id: 'test-artifact' }], adoption_token: 'signed-preview', evidence: { unresolved_text: '<name>192.0.2.1</name>' }, validation: 'Executable validation required', redaction_occurred: true, truncation_occurred: false }
  const before = JSON.stringify(preview)
  const html = render({ status, preview })
  for (const value of ['AI suggestion / unreviewed', 'namespace_uri', 'urn:example', 'xml_unsupported_qualifier_paths', 'Use as draft', 'Discard']) assert.ok(html.includes(value))
  assert.ok(!html.includes('<script>'))
  assert.equal(JSON.stringify(preview), before)
  const { adoptSuggestion } = await server.ssrLoadModule('/src/shared/api/training.ts')
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (_url, init) => {
    assert.deepEqual(JSON.parse(init.body), { adoption_token: preview.adoption_token })
    return new Response(JSON.stringify({ status: 'draft', ...definition }), { status: 201, headers: { 'Content-Type': 'application/json' } })
  }
  try {
    const draft = await adoptSuggestion('block-id', preview.adoption_token)
    assert.equal(draft.status, 'draft')
    assert.deepEqual(draft.structural_match, definition.structural_match)
    assert.deepEqual(draft.scope_resolution, definition.scope_resolution)
  } finally { globalThis.fetch = originalFetch }
})
