import { createRouter, createWebHistory, type RouteLocationNormalized } from 'vue-router'
import { forcedMfa, isAdmin, loadSession, mustChangePassword, sessionState } from './lib/session'

declare module 'vue-router' {
  interface RouteMeta { public?: boolean; admin?: boolean; title?: string }
}

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./pages/LoginPage.vue'), meta: { public: true, title: '登录' } },
    { path: '/recovery-codes', name: 'recovery', component: () => import('./pages/RecoveryCodesPage.vue'), meta: { public: true, title: '保存恢复码' } },
    { path: '/setup/password', name: 'setup-password', component: () => import('./pages/ForcePasswordPage.vue'), meta: { title: '设置新密码' } },
    {
      path: '/',
      component: () => import('./components/AppShell.vue'),
      children: [
        { path: '', name: 'overview', component: () => import('./pages/OverviewPage.vue'), meta: { title: '总览' } },
        { path: 'rules', name: 'rules', component: () => import('./pages/RulesPage.vue'), meta: { title: '转发' } },
        { path: 'rules/new', name: 'rule-new', component: () => import('./pages/RulesPage.vue'), meta: { title: '新建转发' } },
        { path: 'rules/:id(\\d+)', name: 'rule', component: () => import('./pages/RulesPage.vue'), meta: { title: '转发' } },
        { path: 'accounts', name: 'accounts', component: () => import('./pages/AccountsPage.vue'), meta: { admin: true, title: '账户' } },
        { path: 'accounts/new', name: 'account-new', component: () => import('./pages/AccountsPage.vue'), meta: { admin: true, title: '新建账户' } },
        { path: 'accounts/:id(\\d+)', name: 'account', component: () => import('./pages/AccountsPage.vue'), meta: { admin: true, title: '账户' } },
        { path: 'audit', name: 'audit', component: () => import('./pages/AuditPage.vue'), meta: { admin: true, title: '审计' } },
        { path: 'settings', name: 'settings', component: () => import('./pages/SettingsPage.vue'), meta: { title: '设置' } },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: (to, from) => (to.path === from.path ? false : { top: 0 }),
})

function nextQuery(to: RouteLocationNormalized) {
  return to.fullPath === '/' ? {} : { next: to.fullPath }
}

router.beforeEach(async to => {
  await loadSession()
  const session = sessionState.session
  if (to.name === 'recovery') return sessionState.recoveryCodes.length ? true : { name: 'login' }
  if (to.meta.public) return session && to.name === 'login' ? { path: '/' } : true
  if (!session) return { name: 'login', query: nextQuery(to) }
  if (mustChangePassword.value) return to.name === 'setup-password' ? true : { name: 'setup-password' }
  if (to.name === 'setup-password') return { path: '/' }
  if (forcedMfa.value) return to.name === 'settings' ? true : { name: 'settings', hash: '#security' }
  if (to.meta.admin && !isAdmin.value) return { path: '/' }
  return true
})

router.afterEach(to => {
  document.title = to.meta.title ? `${to.meta.title} · RelayDeck` : 'RelayDeck'
})
