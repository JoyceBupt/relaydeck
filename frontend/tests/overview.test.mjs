import assert from 'node:assert/strict'
import { test } from 'node:test'
import { createServer } from 'vite'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { VueQueryPlugin } from '@tanstack/vue-query'

test('overview distinguishes unavailable data and keeps every account reachable', async t => {
  const server = await createServer({ server: { middlewareMode: true, hmr: false }, optimizeDeps: { noDiscovery: true, include: [] }, appType: 'custom', logLevel: 'error' })
  const { default: Topology } = await server.ssrLoadModule('/src/components/RelayTopology.vue')
  const { default: Overview } = await server.ssrLoadModule('/src/pages/OverviewPage.vue')
  const { default: Executor } = await server.ssrLoadModule('/src/components/ExecutorStatus.vue')
  const { queryClient } = await server.ssrLoadModule('/src/lib/queryClient.ts')
  queryClient.setDefaultOptions({ queries: { retry: false, retryOnMount: false } })
  const { acceptSession, clearSession } = await server.ssrLoadModule('/src/lib/session.ts')
  const render = async (component, props = {}) => {
    const app = createSSRApp(component, props)
    app.use(VueQueryPlugin, { queryClient })
    app.component('RouterLink', { props: { to: [String, Object], custom: Boolean }, setup: (props, { slots }) => () => {
      const href = typeof props.to === 'string' ? props.to : props.to.path
      return props.custom ? slots.default?.({ href, navigate: () => {} }) : h('a', { href }, slots.default?.())
    } })
    return renderToString(app)
  }
  const rule = { id: 1, name: '失败转发', owner_id: 1, owner_username: 'owner', runtime_status: 'failed', listen_port: 62001, target_host: '8.8.8.8', target_port: 443 }
  try {
    acceptSession({ user: { id: 1, role: 'user', max_rules: 10, rule_count: 0, expires_at: null }, csrf_token: 'qa', session_ref: 'qa' }, true)
    await t.test('first load uses placeholders instead of zero counts or checking status', async () => {
      const html = await render(Overview)
      assert.match(html, /skeleton/)
      assert.doesNotMatch(html.match(/<section[^>]*topology-title[^]*?<\/section>/)[0], /stat-value[^>]*>0|暂无转发/)
      const health = await render(Executor)
      assert.match(health, /加载中/)
      assert.doesNotMatch(health, /检查中/)
    })
    await t.test('failed initial request has retry and no false empty state', async () => {
      queryClient.getQueryCache().find({ queryKey: ['rules'] }).setState({ status: 'error', fetchStatus: 'idle', error: new Error('unavailable') })
      const html = await render(Overview)
      assert.match(html, /转发加载失败/)
      assert.match(html, /重试/)
      assert.doesNotMatch(html.match(/<section[^>]*topology-title[^]*?<\/section>/)[0], /暂无转发|stat-value[^>]*>0/)
    })
    await t.test('individual failures expose a linked stream and keyboard-accessible entry', async () => {
      const html = await render(Topology, { rules: [rule] })
      assert.match(html, /aria-label="失败转发，62001，失败"/)
      assert.match(html, /<a href="\/rules\/1" tabindex="-1"/)
    })
    await t.test('many rules collapse by account without dropping later accounts', async () => {
      const rules = Array.from({ length: 20 }, (_, index) => ({ ...rule, id: index + 1, owner_id: index < 15 ? 1 : 2, owner_username: index < 15 ? 'owner' : 'tenant', listen_port: 62001 + index }))
      const html = await render(Topology, { rules, admin: true })
      assert.match(html, /owner，15 条转发，展开/)
      assert.match(html, /tenant，5 条转发，展开/)
      assert.doesNotMatch(html, /另有|href="\/rules\/1"/)
    })
  } finally {
    clearSession()
    await server.close()
  }
})
