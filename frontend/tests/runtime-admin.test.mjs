import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { createServer } from 'vite'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
after(() => server.close())

test('admin runtime page exposes preview-before-publish flows for all runtime artifacts', async () => {
  const { RuntimeAdminPage } = await server.ssrLoadModule('/src/features/runtime/RuntimeAdminPage.tsx')
  const html = renderToStaticMarkup(createElement(QueryClientProvider, { client: new QueryClient() }, createElement(RuntimeAdminPage)))
  for (const text of ['Runtime publishing', 'Preview profile', 'Publish profile', 'Preview rule', 'Publish rule', 'Preview pack', 'Publish pack']) {
    assert.ok(html.includes(text), text)
  }
})
