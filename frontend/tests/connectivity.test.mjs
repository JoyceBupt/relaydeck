import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createServer } from 'vite'
import { createRenderer, nextTick, reactive, ssrContextKey } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'

test('connectivity results belong to the checked rule configuration', async t => {
  const server = await createServer({ server: { middlewareMode: true, hmr: false }, optimizeDeps: { noDiscovery: true, include: [] }, appType: 'custom', logLevel: 'error' })
  const { default: Drawer } = await server.ssrLoadModule('/src/components/RuleDrawer.vue')
  const originalFetch = globalThis.fetch
  const rule = { id: 1, owner_id: 1, owner_username: 'tenant', name: 'Forward', listen_port: 62001, target_host: 'example.com', target_ip: '8.8.8.8', target_port: 443, protocol: 'tcp', source_cidrs: [], enabled: true, runtime_status: 'active', runtime_updated_at: 100, updated_at: 100 }
  const props = reactive({ open: true, ruleId: 1, rules: [rule], loaded: true, users: [], health: undefined, sequence: [1, 2] })
  const result = () => ({ rule_id: props.ruleId, revision: 1, target_ip: props.rules[0].target_ip, target_port: props.rules[0].target_port, checked_at: 110, tcp_listener: true, udp_listener: null, target_tcp: { status: 'connected', elapsed_ms: 12 } })
  const success = () => { globalThis.fetch = async () => new Response(JSON.stringify(result())) }
  const failure = () => { globalThis.fetch = async () => new Response(JSON.stringify({ error: { code: 'check_failed', message: '检测请求失败' } }), { status: 503 }) }
  // Mount the real setup in a renderer with no DOM. Browser QA exercises its template.
  const renderer = createRenderer({ createComment: () => ({}), insert() {}, remove() {}, parentNode() {}, nextSibling() {} })
  let state
  const app = renderer.createApp({ setup() { state = Drawer.setup(props, { expose() {} }); return () => null } })
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  app.use(VueQueryPlugin, { queryClient })
  app.use(createRouter({ history: createMemoryHistory(), routes: [] }))
  app.provide(ssrContextKey, { modules: new Set() })
  const update = async patch => { props.rules = props.rules.map(item => ({ ...item, ...patch })); await nextTick() }
  try {
    app.mount({})
    await t.test('heartbeat and runtime status refreshes preserve the result and timestamp', async () => {
      success()
      await state.runCheck()
      assert.equal(state.checkResult.value?.checked_at, 110)
      await update({ runtime_updated_at: 115 })
      await update({ runtime_status: 'pending', runtime_updated_at: 120 })
      await update({ runtime_status: 'active', runtime_updated_at: 125 })
      assert.equal(state.checkResult.value?.checked_at, 110)
    })
    await t.test('failed checks remain visible across background refreshes', async () => {
      failure()
      await state.runCheck()
      assert.equal(state.checkError.value, '检测请求失败')
      await update({ runtime_updated_at: 130 })
      assert.equal(state.checkError.value, '检测请求失败')
    })
    await t.test('polling during a check keeps it pending and does not issue a second probe', async () => {
      let answer
      let requests = 0
      globalThis.fetch = () => { requests += 1; return new Promise(resolve => { answer = resolve }) }
      const pending = state.runCheck()
      while (!answer) await new Promise(resolve => setTimeout(resolve, 0))
      await update({ runtime_updated_at: 135 })
      assert.equal(state.check.isPending.value, true)
      await state.runCheck()
      assert.equal(requests, 1)
      answer(new Response(JSON.stringify(result())))
      await pending
      assert.ok(state.checkResult.value)
    })
    await t.test('saved configuration changes invalidate results even within one timestamp', async () => {
      for (const patch of [{ listen_port: 62002 }, { target_ip: '1.1.1.1' }, { source_cidrs: ['192.0.2.0/24'] }, { protocol: 'both' }, { enabled: false }]) {
        success()
        await state.runCheck()
        assert.ok(state.checkResult.value)
        await update(patch)
        assert.equal(state.checkResult.value, null)
      }
    })
    await t.test('rule navigation clears the result', async () => {
      success()
      await state.runCheck()
      props.ruleId = 2
      props.rules = [{ ...rule, id: 2 }]
      await nextTick()
      assert.equal(state.checkResult.value, null)
    })
    await t.test('late results and errors cannot return after configuration changes', async () => {
      for (const status of [200, 503]) {
        let answer
        const oldResult = { ...result(), checked_at: 1 }
        globalThis.fetch = () => new Promise(resolve => { answer = resolve })
        const pending = state.runCheck()
        while (!answer) await new Promise(resolve => setTimeout(resolve, 0))
        await update({ listen_port: props.rules[0].listen_port + 1 })
        success()
        await state.runCheck()
        assert.ok(state.checkResult.value)
        const latestResult = state.checkResult.value
        answer(new Response(JSON.stringify(status === 200 ? oldResult : { error: { code: 'check_failed', message: '旧检测失败' } }), { status }))
        await pending
        assert.equal(state.checkError.value, '')
        assert.deepEqual(state.checkResult.value, latestResult)
      }
    })
  } finally {
    app.unmount()
    queryClient.clear()
    globalThis.fetch = originalFetch
    await server.close()
  }
})
