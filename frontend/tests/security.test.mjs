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
  const identity = id => ({ user: { id, role: 'user', username: `user${id}` }, csrf_token: `session-${id}`, session_ref: `ref-${id}`, mfa_required: false })
  const rule = { id: 1, name: 'private rule A', listen_port: 41000, target_host: '8.8.8.8', target_port: 443, protocol: 'tcp', source_cidrs: [], enabled: true }
  try {
    await t.test('new login clears recovery codes and old cached data', () => {
      session.acceptSession(identity(1))
      session.clearSession()
      session.sessionState.recoveryCodes = ['private-recovery-code']
      session.sessionState.recoveryOwner = 1
      queryClient.setQueryData(['rules'], [rule])
      session.acceptSession(identity(2), true)
      assert.deepEqual([...session.sessionState.recoveryCodes], [])
      assert.equal(session.sessionState.recoveryOwner, null)
      assert.equal(queryClient.getQueryData(['rules']), undefined)
    })

    await t.test('late toggle failure cannot restore account A into account B', async () => {
      session.acceptSession(identity(1), true)
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
      session.acceptSession(identity(2), true)
      queryClient.setQueryData(['rules'], [{ ...rule, id: 2, name: 'rule B' }])
      answer(new Response(JSON.stringify({ ...rule, enabled: false }), { status: 200 }))
      await rejected
      assert.deepEqual(queryClient.getQueryData(['rules']).map(item => item.name), ['rule B'])
    })

    await t.test('polling and logout wait while MFA response delivers recovery codes', async () => {
      session.acceptSession(identity(1), true)
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
    await t.test('a stalled upgrade times out once and still permits status reconciliation', async t => {
      session.acceptSession(identity(1), true)
      t.mock.timers.enable({ apis: ['setTimeout'] })
      let posts = 0
      let signal
      globalThis.fetch = (url, input) => {
        if (input.method === 'GET') return Promise.resolve(new Response(JSON.stringify({ current_version: '0.2.0', job: null }), { status: 200 }))
        posts += 1
        signal = input.signal
        return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }))
      }
      const pending = api.startUpgrade({ offer: 'a'.repeat(64), password: 'test password', code: '123456', acknowledge: true })
      const rejected = assert.rejects(pending, error => error.status === 0 && error.code === 'request_timeout')
      t.mock.timers.tick(30_000)
      await rejected
      assert.equal(signal.aborted, true)
      assert.equal(posts, 1, 'an ambiguous upgrade acknowledgement must never be automatically retried')
      assert.equal((await api.upgradeStatus()).job, null)
    })

    await t.test('a stalled response body releases the credential mutation guard on timeout', async t => {
      session.acceptSession(identity(1), true)
      t.mock.timers.enable({ apis: ['setTimeout'] })
      globalThis.fetch = async (url, { signal }) => ({ status: 200, ok: true, text: () => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted body')), { once: true })) })
      const pending = api.confirmMfa('123456')
      const rejected = assert.rejects(pending, error => error.code === 'request_timeout')
      assert.equal(client.securityMutationPending.value, true)
      await Promise.resolve()
      t.mock.timers.tick(30_000)
      await rejected
      assert.equal(client.securityMutationPending.value, false)
    })

    await t.test('a timed out old request cannot affect a newly logged in account', async t => {
      session.acceptSession(identity(1), true)
      t.mock.timers.enable({ apis: ['setTimeout'] })
      globalThis.fetch = (url, { signal }) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }))
      const pending = api.rules()
      const rejected = assert.rejects(pending, error => client.isStaleError(error))
      session.acceptSession(identity(2), true)
      t.mock.timers.tick(30_000)
      await rejected
      assert.equal(session.sessionState.session.user.id, 2)
    })

    await t.test('a completed request clears its abort deadline', async t => {
      session.acceptSession(identity(1), true)
      t.mock.timers.enable({ apis: ['setTimeout'] })
      let signal
      globalThis.fetch = async (url, input) => { signal = input.signal; return new Response('[]', { status: 200 }) }
      assert.deepEqual(await api.rules(), [])
      t.mock.timers.tick(30_000)
      assert.equal(signal.aborted, false)
    })

    await t.test('identity refresh cannot retain forms from another account', async () => {
      session.acceptSession(identity(1), true)
      queryClient.setQueryData(['rules'], [rule])
      globalThis.fetch = async () => new Response(JSON.stringify(identity(2)), { status: 200 })
      let changed = false
      const listener = () => { changed = true }
      window.addEventListener('relaydeck:session-changed', listener)
      await session.refreshIdentity()
      assert.equal(session.sessionState.session, null)
      assert.equal(queryClient.getQueryData(['rules']), undefined)
      assert.equal(changed, true)
      window.removeEventListener('relaydeck:session-changed', listener)
    })
  } finally {
    session.clearSession()
    globalThis.fetch = originalFetch
    globalThis.window = originalWindow
    await server.close()
  }
})
