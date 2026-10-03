import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createServer } from 'vite'
import { createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { VueQueryPlugin } from '@tanstack/vue-query'

test('account switching and credential mutations preserve isolation', async t => {
  const server = await createServer({ server: { middlewareMode: true }, optimizeDeps: { noDiscovery: true, include: [] }, appType: 'custom', logLevel: 'error' })
  const originalFetch = globalThis.fetch
  const originalWindow = globalThis.window
  globalThis.window = new EventTarget()
  const session = await server.ssrLoadModule('/src/lib/session.ts')
  const client = await server.ssrLoadModule('/src/api/client.ts')
  const { api } = await server.ssrLoadModule('/src/api/endpoints.ts')
  const { queryClient } = await server.ssrLoadModule('/src/lib/queryClient.ts')
  const queries = await server.ssrLoadModule('/src/lib/queries.ts')
  const identity = id => ({ user: { id, role: 'user', username: `user${id}` }, csrf_token: `session-${id}`, mfa_required: false })
  const rule = { id: 1, name: 'private rule A', listen_port: 41000, target_host: '8.8.8.8', target_port: 443, protocol: 'tcp', source_cidrs: [], enabled: true }
  try {
    await t.test('new login clears recovery codes and old cached data', () => {
      session.acceptSession(identity(1))
      session.clearSession()
      session.sessionState.recoveryCodes = ['private-recovery-code']
      session.sessionState.recoveryOwner = 1
      queryClient.setQueryData(['rules'], [rule])
      session.acceptSession(identity(2))
      assert.deepEqual([...session.sessionState.recoveryCodes], [])
      assert.equal(session.sessionState.recoveryOwner, null)
      assert.equal(queryClient.getQueryData(['rules']), undefined)
    })

    await t.test('late toggle failure cannot restore account A into account B', async () => {
      session.acceptSession(identity(1))
      queryClient.setQueryData(['rules'], [rule])
      let answer
      globalThis.fetch = () => new Promise(resolve => { answer = resolve })
      let toggle
      const app = createSSRApp({ setup() { toggle = queries.provideToggle(); return () => null } })
      app.use(VueQueryPlugin, { queryClient })
      await renderToString(app)
      const pending = toggle.mutateAsync({ rule, enabled: false })
      const rejected = assert.rejects(pending, error => client.isStaleError(error))
      while (!answer) await new Promise(resolve => setTimeout(resolve, 0))
      session.clearSession()
      session.acceptSession(identity(2))
      queryClient.setQueryData(['rules'], [{ ...rule, id: 2, name: 'rule B' }])
      answer(new Response(JSON.stringify({ ...rule, enabled: false }), { status: 200 }))
      await rejected
      assert.deepEqual(queryClient.getQueryData(['rules']).map(item => item.name), ['rule B'])
    })

    await t.test('polling and logout wait while MFA response delivers recovery codes', async () => {
      session.acceptSession(identity(1))
      let answer
      globalThis.fetch = () => new Promise(resolve => { answer = resolve })
      let expired = false
      const listener = () => { expired = true }
      window.addEventListener('relaydeck:session-expired', listener)
      const pending = api.confirmMfa('123456')
      assert.equal(client.securityMutationPending.value, true)
      await assert.rejects(api.rules(), error => error.code === 'stale_read')
      await assert.rejects(api.logout(), error => error.code === 'security_pending')
      answer(new Response(JSON.stringify({ recovery_codes: ['delivered'] }), { status: 200 }))
      assert.deepEqual(await pending, { recovery_codes: ['delivered'] })
      assert.equal(expired, false)
      assert.equal(client.securityMutationPending.value, false)
      window.removeEventListener('relaydeck:session-expired', listener)
    })
  } finally {
    session.clearSession()
    globalThis.fetch = originalFetch
    globalThis.window = originalWindow
    await server.close()
  }
})
