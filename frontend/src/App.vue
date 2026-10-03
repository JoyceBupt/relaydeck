<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ApiError, request, setCsrfToken } from './api'
import type { Audit, Health, Rule, RuleInput, Session, User, ViewMode } from './types'

type Page = 'rules' | 'users' | 'audit' | 'account'
type DialogMode = 'rule' | 'user' | 'reset' | 'delete'
const session = ref<Session | null>(null)
let sessionEpoch = 0
const health = ref<Health | null>(null)
const booting = ref(true)
const page = ref<Page>('rules')
const authBusy = ref(false)
const authError = ref('')
const login = reactive({ username: '', password: '' })
const password = reactive({ current_password: '', new_password: '', confirm: '' })
const passwordBusy = ref(false)
const passwordError = ref('')
const passwordSuccess = ref('')
const rules = ref<Rule[]>([])
const users = ref<User[]>([])
const audit = ref<Audit[]>([])
const listBusy = ref(false)
const listError = ref('')
const rowBusy = ref<number | null>(null)
const search = ref('')
const notice = ref('')
const preferenceBusy = ref(false)
const dialog = ref<HTMLDialogElement | null>(null)
const dialogMode = ref<DialogMode>('rule')
const dialogBusy = ref(false)
const dialogError = ref('')
const editingRule = ref<Rule | null>(null)
const editingUser = ref<User | null>(null)
const deletingRule = ref<Rule | null>(null)
const ruleForm = reactive({ name: '', owner_id: 0, listen_port: 30000, target_host: '', target_port: 443, protocol: 'tcp' as Rule['protocol'], sources: '', enabled: true })
const userForm = reactive({ username: '', password: '', enabled: true, port_start: 30000, port_end: 30099, max_rules: 5, expires: '' })
const resetPassword = ref('')
const isAdmin = computed(() => session.value?.user.role === 'admin')
const viewMode = computed(() => session.value?.user.view_mode || 'table')
const forcedPassword = computed(() => session.value?.user.must_change_password)
const executorText = computed(() => health.value?.executor === 'unconfigured' ? '执行器未接入' : health.value ? '执行器状态未知' : '状态不可用')
const filteredRules = computed(() => {
  const needle = search.value.trim().toLocaleLowerCase()
  return rules.value.filter(rule => !needle || `${rule.name} ${rule.listen_port} ${rule.target_host} ${rule.owner_username}`.toLocaleLowerCase().includes(needle))
})
const dialogTitle = computed(() => ({ rule: editingRule.value ? '编辑转发' : '新建转发', user: editingUser.value ? '编辑账户' : '新建账户', reset: '重置密码', delete: '删除转发' })[dialogMode.value])
const selectedOwner = computed(() => users.value.find(user => user.id === ruleForm.owner_id) || session.value?.user)
const canCreateRule = computed(() => isAdmin.value ? users.value.some(canCreateFor) : !!session.value && canCreateFor(session.value.user))
const pageTitle = computed(() => ({ rules: '转发规则', users: '账户管理', audit: '操作记录', account: '我的账户' })[page.value])
const auditLabels: Record<string, string> = {
  login: '登录', logout: '退出登录', 'user.create': '创建账户', 'user.update': '修改账户', 'user.password': '重置密码',
  'rule.create': '创建转发', 'rule.update': '修改转发', 'rule.delete': '删除转发', 'password.update': '修改密码', 'preferences.update': '修改偏好',
  user_create: '创建账户', user_update: '修改账户', user_password_reset: '重置密码', rule_create: '创建转发', rule_update: '修改转发', rule_delete: '删除转发', password_change: '修改密码', preferences_update: '修改偏好',
  user_created: '创建账户', user_updated: '修改账户', password_reset: '重置密码', password_changed: '修改密码',
  rule_created: '创建转发', rule_updated: '修改转发', rule_deleted: '删除转发',
}
function message(error: unknown) { return error instanceof Error ? error.message : '操作失败，请重试' }
function protocolText(protocol: Rule['protocol']) { return protocol === 'both' ? 'TCP / UDP' : protocol.toUpperCase() }
function targetText(rule: Rule) { return `${rule.target_host.includes(':') ? `[${rule.target_host}]` : rule.target_host}:${rule.target_port}` }
function dateTime(value: number) { return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value * 1000)) }
function expiryText(value: number | null) { return value === null ? '长期' : new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium' }).format(new Date(value * 1000)) }
function dateInput(value: number | null) {
  if (value === null) return ''
  const date = new Date(value * 1000)
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}
function expiryValue(value: string) { return value ? Math.floor(new Date(`${value}T23:59:59`).getTime() / 1000) : null }
function acceptSession(value: Session) { session.value = value; setCsrfToken(value.csrf_token) }
function clearDialogSecrets() { resetPassword.value = ''; userForm.password = '' }
function clearTemporarySecrets() {
  clearDialogSecrets()
  login.password = ''
  password.current_password = ''; password.new_password = ''; password.confirm = ''
}
function canCreateFor(user: User) {
  return user.enabled && (user.expires_at === null || user.expires_at > Date.now() / 1000) && user.rule_count < user.max_rules
}
function selectOwner() {
  const owner = selectedOwner.value
  if (owner && (ruleForm.listen_port < owner.port_start || ruleForm.listen_port > owner.port_end)) ruleForm.listen_port = owner.port_start
}
function expireSession() {
  sessionEpoch += 1
  listBusy.value = false
  const wasSignedIn = session.value !== null
  session.value = null
  setCsrfToken('')
  rules.value = []; users.value = []; audit.value = []
  dialog.value?.close()
  clearTemporarySecrets()
  authError.value = wasSignedIn ? '登录已失效，请重试' : ''
  passwordError.value = ''; passwordSuccess.value = ''
  page.value = 'rules'
}
async function refreshIdentity() {
  const epoch = sessionEpoch
  const identity = await request<Session>('/session')
  if (epoch === sessionEpoch && session.value) acceptSession(identity)
}
async function loadHealth() { try { health.value = await request<Health>('/health') } catch { health.value = null } }
async function loadPage() {
  if (!session.value || forcedPassword.value) return
  const epoch = sessionEpoch
  const destination = page.value
  const current = () => epoch === sessionEpoch && destination === page.value && session.value !== null
  listBusy.value = true; listError.value = ''
  try {
    if (destination === 'rules') {
      const nextRules = await request<Rule[]>('/rules')
      const nextUsers = isAdmin.value ? await request<User[]>('/users') : []
      if (current()) { rules.value = nextRules; users.value = nextUsers }
    } else if (destination === 'users') {
      const nextUsers = await request<User[]>('/users')
      if (current()) users.value = nextUsers
    } else if (destination === 'audit') {
      const nextAudit = await request<Audit[]>('/audit')
      if (current()) audit.value = nextAudit
    } else await refreshIdentity()
  } catch (error) { if (current()) listError.value = message(error) }
  finally { if (current()) listBusy.value = false }
}
async function navigate(destination: Page) {
  if (listBusy.value || destination === page.value) return
  page.value = destination; notice.value = ''; search.value = ''
  await loadPage()
}
async function submitLogin() {
  sessionEpoch += 1
  authBusy.value = true; authError.value = ''
  try {
    acceptSession(await request<Session>('/login', 'POST', { username: login.username.trim(), password: login.password }))
    login.password = ''; page.value = 'rules'
    await loadPage()
  } catch (error) { authError.value = message(error) }
  finally { authBusy.value = false }
}
async function logout() {
  authBusy.value = true; notice.value = ''
  try {
    await request('/logout', 'POST')
    session.value = null; setCsrfToken(''); rules.value = []; users.value = []; audit.value = []
    clearTemporarySecrets()
    authError.value = ''; page.value = 'rules'
  } catch (error) { notice.value = message(error) }
  finally { authBusy.value = false }
}
async function changePassword() {
  passwordError.value = ''; passwordSuccess.value = ''
  if (password.new_password !== password.confirm) { passwordError.value = '两次密码不一致'; return }
  passwordBusy.value = true
  try {
    await request('/password', 'PUT', { current_password: password.current_password, new_password: password.new_password })
    expireSession()
    authError.value = '密码已更新，请登录'
  } catch (error) { passwordError.value = message(error) }
  finally { passwordBusy.value = false }
}
async function changeView(mode: ViewMode) {
  if (mode === viewMode.value || preferenceBusy.value) return
  preferenceBusy.value = true; notice.value = ''
  try {
    const result = await request<{ view_mode: ViewMode }>('/preferences', 'PUT', { view_mode: mode })
    if (session.value) session.value.user.view_mode = result.view_mode
  } catch (error) { notice.value = message(error) }
  finally { preferenceBusy.value = false }
}
async function showDialog(mode: DialogMode) {
  dialogMode.value = mode; dialogError.value = ''
  await nextTick(); dialog.value?.showModal()
}
function closeDialog() { if (!dialogBusy.value) { dialog.value?.close(); clearDialogSecrets() } }
function cancelDialog(event: Event) { if (dialogBusy.value) event.preventDefault() }
async function openRule(rule: Rule | null = null) {
  if (!rule && !canCreateRule.value) { notice.value = '账户额度不可用'; return }
  editingRule.value = rule
  const owner = session.value && canCreateFor(session.value.user) ? session.value.user : users.value.find(canCreateFor)
  Object.assign(ruleForm, rule ? { ...rule, sources: rule.source_cidrs.join('\n') } : { name: '', owner_id: owner?.id || 0, listen_port: owner?.port_start || 1024, target_host: '', target_port: 443, protocol: 'tcp', sources: '', enabled: true })
  await showDialog('rule')
}
async function openUser(user: User | null = null) {
  editingUser.value = user
  Object.assign(userForm, user ? { ...user, password: '', expires: dateInput(user.expires_at) } : { username: '', password: '', enabled: true, port_start: 30000, port_end: 30099, max_rules: 5, expires: '' })
  await showDialog('user')
}
async function openReset(user: User) { editingUser.value = user; resetPassword.value = ''; await showDialog('reset') }
async function openDelete(rule: Rule) { deletingRule.value = rule; await showDialog('delete') }
function ruleInput(rule: Rule): RuleInput { return { name: rule.name, listen_port: rule.listen_port, target_host: rule.target_host, target_port: rule.target_port, protocol: rule.protocol, source_cidrs: rule.source_cidrs, enabled: rule.enabled } }
async function toggleRule(rule: Rule) {
  rowBusy.value = rule.id; notice.value = ''
  try {
    await request(`/rules/${rule.id}`, 'PUT', { ...ruleInput(rule), enabled: !rule.enabled })
    notice.value = '已保存，待生效'
    await loadPage()
    try { await refreshIdentity() } catch { if (session.value) notice.value = '已保存；刷新失败' }
  }
  catch (error) { notice.value = message(error) }
  finally { rowBusy.value = null }
}
async function submitDialog() {
  dialogBusy.value = true; dialogError.value = ''; notice.value = ''
  try {
    if (dialogMode.value === 'rule') {
      if (!editingRule.value && (!selectedOwner.value || !canCreateFor(selectedOwner.value))) throw new Error('账户额度不可用')
      const data: RuleInput = { name: ruleForm.name.trim(), listen_port: Number(ruleForm.listen_port), target_host: ruleForm.target_host.trim(), target_port: Number(ruleForm.target_port), protocol: ruleForm.protocol, source_cidrs: ruleForm.sources.split(/[\n,]/).map(value => value.trim()).filter(Boolean), enabled: ruleForm.enabled }
      if (!editingRule.value && isAdmin.value) data.owner_id = Number(ruleForm.owner_id)
      await request(editingRule.value ? `/rules/${editingRule.value.id}` : '/rules', editingRule.value ? 'PUT' : 'POST', data)
      notice.value = '已保存，待生效'
    } else if (dialogMode.value === 'user') {
      const grant = { enabled: userForm.enabled, port_start: Number(userForm.port_start), port_end: Number(userForm.port_end), max_rules: Number(userForm.max_rules), expires_at: expiryValue(userForm.expires) }
      if (grant.port_start > grant.port_end) throw new Error('端口范围无效')
      if (editingUser.value) await request(`/users/${editingUser.value.id}`, 'PUT', grant)
      else await request('/users', 'POST', { username: userForm.username.trim(), password: userForm.password, port_start: grant.port_start, port_end: grant.port_end, max_rules: grant.max_rules, expires_at: grant.expires_at })
      notice.value = '账户已保存'
    } else if (dialogMode.value === 'reset') {
      await request(`/users/${editingUser.value!.id}/password`, 'POST', { password: resetPassword.value })
      notice.value = '密码已重置'
    } else {
      await request(`/rules/${deletingRule.value!.id}`, 'DELETE')
      notice.value = '已删除，待生效'
    }
    dialog.value?.close(); resetPassword.value = ''; userForm.password = ''
    await loadPage()
    try { await refreshIdentity() } catch { if (session.value) notice.value = '已保存；刷新失败' }
  } catch (error) { dialogError.value = message(error) }
  finally { dialogBusy.value = false }
}
onMounted(async () => {
  window.addEventListener('relaydeck:session-expired', expireSession)
  await loadHealth()
  try { acceptSession(await request<Session>('/session')) }
  catch (error) { if (!(error instanceof ApiError && error.status === 401)) authError.value = message(error) }
  booting.value = false
  await loadPage()
})
onUnmounted(() => window.removeEventListener('relaydeck:session-expired', expireSession))
</script>

<template>
  <div v-if="booting" class="boot-state" role="status"><span class="spinner"></span>正在连接</div>

  <div v-else-if="!session" class="login-page">
    <div class="login-brand"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h11m-4-4 4 4-4 4M20 17H9m4-4-4 4 4 4" /></svg></span>RelayDeck</div>
    <main class="login-main">
      <form class="login-form" @submit.prevent="submitLogin">
        <h1>登录</h1>
        <label>账户<input v-model="login.username" name="username" autocomplete="username" required maxlength="64" autofocus :disabled="authBusy" /></label>
        <label>密码<input v-model="login.password" name="password" type="password" autocomplete="current-password" required :disabled="authBusy" /></label>
        <p v-if="authError" class="form-error" role="alert">{{ authError }}</p>
        <button class="button primary login-submit" type="submit" :disabled="authBusy">{{ authBusy ? '登录中' : '登录' }}</button>
      </form>
    </main>
    <footer class="login-footer">{{ health ? `RelayDeck ${health.version}` : '服务状态不可用' }}</footer>
  </div>

  <div v-else-if="forcedPassword" class="login-page">
    <div class="login-brand"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h11m-4-4 4 4-4 4M20 17H9m4-4-4 4 4 4" /></svg></span>RelayDeck</div>
    <main class="login-main">
      <form class="login-form" @submit.prevent="changePassword">
        <h1>更新密码</h1>
        <p class="form-hint">首次登录，请更新密码</p>
        <label>当前密码<input v-model="password.current_password" type="password" autocomplete="current-password" required :disabled="passwordBusy" /></label>
        <label>新密码<input v-model="password.new_password" type="password" autocomplete="new-password" minlength="12" required :disabled="passwordBusy" /><span class="field-hint">至少 12 位</span></label>
        <label>确认密码<input v-model="password.confirm" type="password" autocomplete="new-password" minlength="12" required :disabled="passwordBusy" /></label>
        <p v-if="passwordError" class="form-error" role="alert">{{ passwordError }}</p>
        <button class="button primary login-submit" :disabled="passwordBusy">{{ passwordBusy ? '保存中' : '保存' }}</button>
        <button class="button text-button login-submit" type="button" :disabled="authBusy || passwordBusy" @click="logout">退出</button>
        <p v-if="notice" class="form-error" role="alert">{{ notice }}</p>
      </form>
    </main>
  </div>

  <div v-else class="app-shell">
    <a class="skip-link" href="#main">跳至内容</a>
    <aside class="sidebar">
      <a href="#" class="brand" @click.prevent="navigate('rules')"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h11m-4-4 4 4-4 4M20 17H9m4-4-4 4 4 4" /></svg></span>RelayDeck</a>
      <nav aria-label="主导航" class="main-nav">
        <button :class="{ active: page === 'rules' }" :aria-current="page === 'rules' ? 'page' : undefined" @click="navigate('rules')"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h14m-4-4 4 4-4 4M20 17H6m4-4-4 4 4 4" /></svg>转发规则</button>
        <button v-if="isAdmin" :class="{ active: page === 'users' }" :aria-current="page === 'users' ? 'page' : undefined" @click="navigate('users')"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3" /><path d="M3 21v-3a6 6 0 0 1 12 0v3m1-16a3 3 0 0 1 0 6m2 4a5 5 0 0 1 3 4v2" /></svg>账户管理</button>
        <button v-if="isAdmin" :class="{ active: page === 'audit' }" :aria-current="page === 'audit' ? 'page' : undefined" @click="navigate('audit')"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3H5v18h14V3h-3M8 3h8v4H8zM8 12h8m-8 4h6" /></svg>操作记录</button>
        <button :class="{ active: page === 'account' }" :aria-current="page === 'account' ? 'page' : undefined" @click="navigate('account')"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4" /><path d="M4 21v-2a8 8 0 0 1 16 0v2" /></svg>我的账户</button>
      </nav>
      <div class="sidebar-footer"><span class="version">v{{ health?.version || '0.1.0' }}</span><span>单机转发</span></div>
    </aside>
    <div class="workspace">
      <header class="topbar"><span class="executor-status"><span class="status-dot" aria-hidden="true"></span>{{ executorText }}</span><div class="signed-in"><span>{{ session.user.username }}</span><span class="role-label">{{ isAdmin ? '管理员' : '用户' }}</span><button class="button text-button compact" :disabled="authBusy" @click="logout">退出</button></div></header>
      <main id="main" class="main-content" tabindex="-1">
        <div class="page-heading"><div><h1>{{ pageTitle }}</h1><p v-if="page === 'rules' && !isAdmin" class="page-detail">端口 {{ session.user.port_start }}–{{ session.user.port_end }}<span class="detail-divider">/</span>规则 {{ session.user.rule_count }} / {{ session.user.max_rules }}</p><p v-else-if="page === 'rules'" class="page-detail">{{ rules.length }} 条规则</p></div><div class="heading-actions"><button class="button secondary" :disabled="listBusy" @click="loadPage">刷新</button><button v-if="page === 'rules'" class="button primary" :disabled="listBusy" @click="openRule()">新建</button><button v-if="page === 'users'" class="button primary" :disabled="listBusy" @click="openUser()">开户</button></div></div>
        <div v-if="notice" class="notice" role="status">{{ notice }}<button class="dismiss" aria-label="关闭提示" @click="notice = ''"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg></button></div>
        <div v-if="listError" class="error-strip" role="alert"><span>{{ listError }}</span><button class="button text-button" :disabled="listBusy" @click="loadPage">重试</button></div>

        <section v-if="page === 'rules'" aria-label="转发规则">
          <div class="list-toolbar"><label class="search-box"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5" /></svg><input v-model="search" type="search" placeholder="搜索名称、端口" aria-label="搜索转发" /></label><div class="view-toggle" role="group" aria-label="显示方式"><button :aria-pressed="viewMode === 'table'" :class="{ selected: viewMode === 'table' }" :disabled="preferenceBusy" @click="changeView('table')"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="1" /><path d="M3 9h18M3 14h18M9 4v16" /></svg>表格</button><button :aria-pressed="viewMode === 'cards'" :class="{ selected: viewMode === 'cards' }" :disabled="preferenceBusy" @click="changeView('cards')"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="1" /><rect x="3" y="14" width="18" height="6" rx="1" /></svg>卡片</button></div></div>
          <div v-if="listBusy" class="loading-row" role="status"><span class="spinner"></span>正在加载</div>
          <div v-else-if="!filteredRules.length && !listError" class="empty-state"><svg viewBox="0 0 40 40" aria-hidden="true"><path d="M5 12h27m-7-7 7 7-7 7M35 28H8m7-7-7 7 7 7" /></svg><h2>{{ search ? '暂无匹配' : '暂无转发' }}</h2><button v-if="search" class="button secondary" @click="search = ''">清空</button><button v-else class="button primary" @click="openRule()">新建</button></div>
          <div v-else-if="!listBusy && viewMode === 'table'" class="table-frame" role="region" aria-label="转发表格" tabindex="0">
            <table><thead><tr><th scope="col">名称</th><th v-if="isAdmin" scope="col">账户</th><th scope="col">入口端口</th><th scope="col">目标</th><th scope="col">协议</th><th scope="col">配置</th><th scope="col">运行状态</th><th scope="col" class="actions-col">操作</th></tr></thead><tbody><tr v-for="rule in filteredRules" :key="rule.id"><th scope="row" class="rule-name">{{ rule.name }}</th><td v-if="isAdmin">{{ rule.owner_username }}</td><td class="numeric endpoint">{{ rule.listen_port }}</td><td><span class="endpoint target">{{ targetText(rule) }}</span><span v-if="rule.source_cidrs.length" class="cell-detail">来源 {{ rule.source_cidrs.length }} 个网段</span><span v-else class="cell-detail">不限来源</span></td><td><span class="protocol">{{ protocolText(rule.protocol) }}</span></td><td><span :class="['state-label', { muted: !rule.enabled }]">{{ rule.enabled ? '已启用' : '已停用' }}</span></td><td><span class="pending-label">待生效</span></td><td class="actions-col"><div class="row-actions"><button class="button text-button compact" :disabled="rowBusy !== null" @click="openRule(rule)">编辑</button><button class="button text-button compact" :disabled="rowBusy !== null" @click="toggleRule(rule)">{{ rowBusy === rule.id ? '保存中' : rule.enabled ? '停用' : '启用' }}</button><button class="button text-button compact danger-text" :disabled="rowBusy !== null" @click="openDelete(rule)">删除</button></div></td></tr></tbody></table>
          </div>
          <div v-else-if="!listBusy" class="rule-cards"><article v-for="rule in filteredRules" :key="rule.id" class="rule-card"><div class="rule-card-head"><h2>{{ rule.name }}</h2><span class="pending-label">待生效</span></div><div class="card-endpoints"><span class="endpoint numeric">{{ rule.listen_port }}</span><svg viewBox="0 0 24 24" aria-label="转发至" role="img"><path d="M4 12h16m-6-6 6 6-6 6" /></svg><span class="endpoint target">{{ targetText(rule) }}</span></div><dl class="rule-facts"><div v-if="isAdmin"><dt>账户</dt><dd>{{ rule.owner_username }}</dd></div><div><dt>协议</dt><dd>{{ protocolText(rule.protocol) }}</dd></div><div><dt>配置</dt><dd :class="{ muted: !rule.enabled }">{{ rule.enabled ? '已启用' : '已停用' }}</dd></div><div><dt>来源</dt><dd>{{ rule.source_cidrs.length ? rule.source_cidrs.join('、') : '不限' }}</dd></div></dl><div class="card-actions"><button class="button secondary compact" :disabled="rowBusy !== null" @click="openRule(rule)">编辑</button><button class="button secondary compact" :disabled="rowBusy !== null" @click="toggleRule(rule)">{{ rowBusy === rule.id ? '保存中' : rule.enabled ? '停用' : '启用' }}</button><button class="button text-button compact danger-text" :disabled="rowBusy !== null" @click="openDelete(rule)">删除</button></div></article></div>
        </section>

        <section v-else-if="page === 'users'" aria-label="账户管理">
          <div v-if="listBusy" class="loading-row" role="status"><span class="spinner"></span>正在加载</div>
          <div v-else-if="!users.length && !listError" class="empty-state"><h2>暂无账户</h2><button class="button primary" @click="openUser()">开户</button></div>
          <div v-else class="table-frame" role="region" aria-label="账户表格" tabindex="0"><table><thead><tr><th scope="col">账户</th><th scope="col">角色</th><th scope="col">端口范围</th><th scope="col">规则</th><th scope="col">到期</th><th scope="col">状态</th><th scope="col" class="actions-col">操作</th></tr></thead><tbody><tr v-for="user in users" :key="user.id"><th scope="row">{{ user.username }}<span v-if="user.id === session.user.id" class="cell-detail">当前账户</span></th><td>{{ user.role === 'admin' ? '管理员' : '用户' }}</td><td class="numeric endpoint">{{ user.port_start }}–{{ user.port_end }}</td><td class="numeric">{{ user.rule_count }} / {{ user.max_rules }}</td><td>{{ expiryText(user.expires_at) }}</td><td><span :class="['state-label', { muted: !user.enabled }]">{{ user.enabled ? '已启用' : '已停用' }}</span></td><td class="actions-col"><div class="row-actions"><button v-if="user.role === 'user'" class="button text-button compact" @click="openUser(user)">编辑</button><button v-if="user.role === 'user'" class="button text-button compact" @click="openReset(user)">重置</button><button v-else class="button text-button compact" @click="navigate('account')">设置</button></div></td></tr></tbody></table></div>
        </section>

        <section v-else-if="page === 'audit'" aria-label="操作记录">
          <div v-if="listBusy" class="loading-row" role="status"><span class="spinner"></span>正在加载</div>
          <div v-else-if="!audit.length && !listError" class="empty-state"><h2>暂无记录</h2></div>
          <div v-else class="table-frame" role="region" aria-label="操作记录表格" tabindex="0"><table><thead><tr><th scope="col">时间</th><th scope="col">账户</th><th scope="col">操作</th><th scope="col">对象</th></tr></thead><tbody><tr v-for="entry in audit" :key="entry.id"><td class="numeric">{{ dateTime(entry.created_at) }}</td><td>{{ entry.actor_username }}</td><td>{{ auditLabels[entry.action] || '其他操作' }}</td><td class="numeric">{{ entry.resource_id === null ? '—' : `#${entry.resource_id}` }}</td></tr></tbody></table></div>
        </section>

        <section v-else class="account-layout" aria-label="我的账户"><div class="account-info"><h2>账户信息</h2><dl class="account-facts"><div><dt>账户</dt><dd>{{ session.user.username }}</dd></div><div><dt>角色</dt><dd>{{ isAdmin ? '管理员' : '用户' }}</dd></div><div><dt>端口范围</dt><dd class="numeric">{{ session.user.port_start }}–{{ session.user.port_end }}</dd></div><div><dt>规则额度</dt><dd class="numeric">{{ session.user.rule_count }} / {{ session.user.max_rules }}</dd></div><div><dt>到期时间</dt><dd>{{ expiryText(session.user.expires_at) }}</dd></div><div><dt>显示方式</dt><dd>{{ viewMode === 'table' ? '表格' : '卡片' }}</dd></div></dl></div><form class="password-form" @submit.prevent="changePassword"><h2>修改密码</h2><label>当前密码<input v-model="password.current_password" type="password" autocomplete="current-password" required :disabled="passwordBusy" /></label><label>新密码<input v-model="password.new_password" type="password" autocomplete="new-password" minlength="12" required :disabled="passwordBusy" /><span class="field-hint">至少 12 位</span></label><label>确认密码<input v-model="password.confirm" type="password" autocomplete="new-password" minlength="12" required :disabled="passwordBusy" /></label><p v-if="passwordError" class="form-error" role="alert">{{ passwordError }}</p><p v-if="passwordSuccess" class="form-success" role="status">{{ passwordSuccess }}</p><button class="button primary" :disabled="passwordBusy">{{ passwordBusy ? '保存中' : '保存' }}</button></form></section>
      </main>
    </div>

    <dialog ref="dialog" class="editor-dialog" aria-labelledby="dialog-title" @cancel="cancelDialog" @close="clearDialogSecrets">
      <form @submit.prevent="submitDialog"><header class="dialog-heading"><h2 id="dialog-title">{{ dialogTitle }}</h2><button class="dismiss" type="button" aria-label="关闭表单" :disabled="dialogBusy" @click="closeDialog"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg></button></header>
        <div class="dialog-content">
          <template v-if="dialogMode === 'rule'">
            <label>名称<input v-model="ruleForm.name" required maxlength="64" :disabled="dialogBusy" /></label>
            <label v-if="isAdmin && !editingRule">所属账户<select v-model="ruleForm.owner_id" :disabled="dialogBusy" required @change="selectOwner"><option v-for="user in users" :key="user.id" :value="user.id" :disabled="!canCreateFor(user)">{{ user.username }}</option></select></label>
            <div class="field-row"><label>入口端口<input v-model.number="ruleForm.listen_port" type="number" inputmode="numeric" required :min="selectedOwner?.port_start || 1024" :max="selectedOwner?.port_end || 65535" :disabled="dialogBusy" /><span v-if="selectedOwner" class="field-hint">{{ selectedOwner.port_start }}–{{ selectedOwner.port_end }}</span></label><label>协议<select v-model="ruleForm.protocol" :disabled="dialogBusy"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP / UDP</option></select></label></div>
            <div class="field-row target-fields"><label>目标地址<input v-model="ruleForm.target_host" required maxlength="253" placeholder="公网 IP 或域名" spellcheck="false" :disabled="dialogBusy" /></label><label>目标端口<input v-model.number="ruleForm.target_port" type="number" inputmode="numeric" min="1" max="65535" required :disabled="dialogBusy" /></label></div>
            <label>来源网段<textarea v-model="ruleForm.sources" rows="3" placeholder="203.0.113.0/24" spellcheck="false" :disabled="dialogBusy"></textarea><span class="field-hint">每行一条；留空不限</span></label>
            <label class="checkbox-label"><input v-model="ruleForm.enabled" type="checkbox" :disabled="dialogBusy" />启用转发</label>
          </template>
          <template v-else-if="dialogMode === 'user'">
            <label>账户<input v-model="userForm.username" required maxlength="32" autocomplete="off" :disabled="dialogBusy || !!editingUser" /></label>
            <label v-if="!editingUser">初始密码<input v-model="userForm.password" type="password" autocomplete="new-password" required minlength="12" :disabled="dialogBusy" /><span class="field-hint">至少 12 位</span></label>
            <div class="field-row"><label>起始端口<input v-model.number="userForm.port_start" type="number" inputmode="numeric" min="1024" max="65535" required :disabled="dialogBusy" /></label><label>结束端口<input v-model.number="userForm.port_end" type="number" inputmode="numeric" min="1024" max="65535" required :disabled="dialogBusy" /></label></div>
            <div class="field-row"><label>规则上限<input v-model.number="userForm.max_rules" type="number" inputmode="numeric" min="0" max="30" required :disabled="dialogBusy" /></label><label>到期日期<input v-model="userForm.expires" type="date" :disabled="dialogBusy" /><span class="field-hint">留空长期有效</span></label></div>
            <label v-if="editingUser" class="checkbox-label"><input v-model="userForm.enabled" type="checkbox" :disabled="dialogBusy || editingUser.id === session.user.id" />启用账户</label>
          </template>
          <template v-else-if="dialogMode === 'reset'"><p class="dialog-subject">{{ editingUser?.username }}</p><label>临时密码<input v-model="resetPassword" type="password" autocomplete="new-password" minlength="12" required :disabled="dialogBusy" /><span class="field-hint">下次登录须更新密码</span></label></template>
          <template v-else><p class="dialog-subject">{{ deletingRule?.name }}</p><p class="delete-description">删除后无法恢复</p></template>
          <p v-if="dialogError" class="form-error" role="alert">{{ dialogError }}</p>
        </div>
        <footer class="dialog-footer"><button class="button secondary" type="button" :disabled="dialogBusy" @click="closeDialog">取消</button><button :class="['button', dialogMode === 'delete' ? 'danger' : 'primary']" :disabled="dialogBusy">{{ dialogBusy ? '处理中' : dialogMode === 'delete' ? '删除' : dialogMode === 'reset' ? '重置' : '保存' }}</button></footer>
      </form>
    </dialog>
  </div>
</template>
