<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Copy, ShieldCheck } from '@lucide/vue'
import Segmented from '../components/Segmented.vue'
import QrCode from '../components/QrCode.vue'
import { api } from '../api/endpoints'
import { errorMessage, isStaleError } from '../api/client'
import type { ViewMode } from '../types'
import { acceptSession, clearSession, currentUser, forcedMfa, isAdmin, sessionState } from '../lib/session'
import { theme, themeLabels, type ThemePreference } from '../lib/theme'
import { expiry } from '../lib/format'
import { validatePassword } from '../lib/validation'
import { reportError } from '../lib/queries'
import { toast } from '../lib/toast'

const route = useRoute()
const router = useRouter()
const user = computed(() => currentUser.value)
const userExpiry = computed(() => (user.value ? expiry(user.value.expires_at) : null))

// Appearance
const themeOptions = (Object.keys(themeLabels) as ThemePreference[]).map(value => ({ value, label: themeLabels[value] }))
const savingView = ref(false)
async function setView(mode: string) {
  const session = sessionState.session
  if (!session || mode === session.user.view_mode || savingView.value) return
  savingView.value = true
  try {
    const result = await api.setPreference(mode as ViewMode)
    if (sessionState.session) acceptSession({ ...sessionState.session, user: { ...sessionState.session.user, view_mode: result.view_mode } })
    toast('已保存显示方式')
  } catch (error) { reportError(error, '没能保存') } finally { savingView.value = false }
}

// Two-factor authentication
type MfaStep = 'idle' | 'password' | 'scan' | 'disable'
const mfaStep = ref<MfaStep>('idle')
const mfa = reactive({ password: '', code: '', secret: '', uri: '' })
const mfaBusy = ref(false)
const mfaError = ref('')
const codeInput = ref<HTMLInputElement | null>(null)
function resetMfa() { Object.assign(mfa, { password: '', code: '', secret: '', uri: '' }); mfaStep.value = 'idle'; mfaError.value = '' }

async function beginMfa() {
  if (mfaBusy.value) return
  mfaBusy.value = true
  mfaError.value = ''
  const epoch = sessionState.epoch
  try {
    const enrollment = await api.beginMfa(mfa.password)
    if (epoch !== sessionState.epoch) return
    Object.assign(mfa, { password: '', secret: enrollment.secret, uri: enrollment.otpauth_uri })
    mfaStep.value = 'scan'
    await nextTick()
    codeInput.value?.focus()
  } catch (error) { if (!isStaleError(error)) mfaError.value = errorMessage(error) } finally { mfaBusy.value = false }
}

async function confirmMfa() {
  if (mfaBusy.value) return
  mfaBusy.value = true
  mfaError.value = ''
  const epoch = sessionState.epoch
  try {
    const result = await api.confirmMfa(mfa.code.trim())
    if (epoch !== sessionState.epoch) return
    // Enrollment revokes every session; the codes are shown once, then the viewer signs in again.
    clearSession()
    sessionState.recoveryCodes = result.recovery_codes
    await router.replace({ name: 'recovery' })
  } catch (error) { if (!isStaleError(error)) { mfaError.value = errorMessage(error); mfa.code = '' } } finally { mfaBusy.value = false }
}

async function disableMfa() {
  if (mfaBusy.value) return
  mfaBusy.value = true
  mfaError.value = ''
  const epoch = sessionState.epoch
  try {
    await api.disableMfa(mfa.password, mfa.code.trim())
    if (epoch !== sessionState.epoch) return
    clearSession('双因素验证已停用，请重新登录')
    await router.replace({ name: 'login' })
  } catch (error) { if (!isStaleError(error)) mfaError.value = errorMessage(error) } finally { mfaBusy.value = false }
}

async function copySecret() {
  try { await navigator.clipboard.writeText(mfa.secret); toast('已复制密钥') } catch { toast('复制失败', { description: '请手动选中复制', tone: 'danger' }) }
}

// Password
const password = reactive({ current: '', next: '', confirm: '' })
const passwordBusy = ref(false)
const passwordError = ref('')
const passwordTouched = ref(false)
const nextError = computed(() => (passwordTouched.value || password.next ? validatePassword(password.next) : ''))
const confirmError = computed(() => (password.confirm && password.confirm !== password.next ? '两次输入不一致' : ''))
async function changePassword() {
  passwordTouched.value = true
  if (validatePassword(password.next) || password.confirm !== password.next || passwordBusy.value) return
  passwordBusy.value = true
  passwordError.value = ''
  try {
    await api.changePassword(password.current, password.next)
    clearSession('密码已更新，请用新密码登录')
    await router.replace({ name: 'login' })
  } catch (error) { if (!isStaleError(error)) passwordError.value = errorMessage(error) } finally { passwordBusy.value = false }
}

const security = ref<HTMLElement | null>(null)
onMounted(() => { if (route.hash === '#security' || forcedMfa.value) security.value?.scrollIntoView({ block: 'start' }) })
</script>

<template>
  <div class="mx-auto grid max-w-3xl gap-8">
    <div>
      <h1 class="text-2xl font-semibold tracking-[-0.02em]">设置</h1>
      <p class="mt-1 text-muted">账户信息、外观和登录安全。</p>
    </div>

    <section v-if="user && !forcedMfa" class="panel" aria-labelledby="profile-title">
      <div class="px-5 pt-5">
        <h2 id="profile-title" class="text-sm font-semibold">账户</h2>
        <p class="mt-1 text-sm text-muted">{{ isAdmin ? '管理员的授权固定，不能在面板中修改。' : '授权由管理员分配，如需调整请联系管理员。' }}</p>
      </div>
      <dl class="grid grid-cols-2 gap-x-6 gap-y-4 px-5 py-5 text-sm sm:grid-cols-4">
        <div><dt class="text-muted">用户名</dt><dd class="mt-0.5 truncate font-medium">{{ user.username }}</dd></div>
        <div><dt class="text-muted">角色</dt><dd class="mt-0.5 font-medium">{{ isAdmin ? '管理员' : '租户' }}</dd></div>
        <div><dt class="text-muted">端口段</dt><dd class="mt-0.5 font-mono font-medium tabular">{{ user.port_start }}–{{ user.port_end }}</dd></div>
        <div><dt class="text-muted">规则额度</dt><dd class="mt-0.5 font-medium tabular">{{ user.rule_count }} / {{ user.max_rules }}</dd></div>
        <div class="col-span-2"><dt class="text-muted">有效期</dt><dd class="mt-0.5 font-medium" :class="userExpiry?.tone === 'soon' ? 'text-warning' : ''">{{ userExpiry?.text }}</dd></div>
      </dl>
    </section>

    <section v-if="!forcedMfa" class="panel" aria-labelledby="appearance-title">
      <div class="px-5 pt-5">
        <h2 id="appearance-title" class="text-sm font-semibold">外观</h2>
        <p class="mt-1 text-sm text-muted">主题只保存在这台设备上；转发列表的显示方式跟随账户。</p>
      </div>
      <div class="grid gap-4 px-5 py-5">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <span class="font-medium">主题</span>
          <Segmented v-model="theme" label="主题" :options="themeOptions" />
        </div>
        <div class="flex flex-wrap items-center justify-between gap-3">
          <span class="font-medium">转发列表</span>
          <Segmented :model-value="user?.view_mode ?? 'table'" label="转发列表显示方式" :disabled="savingView" :options="[{ value: 'table', label: '列表' }, { value: 'cards', label: '卡片' }]" @update:model-value="setView" />
        </div>
      </div>
    </section>

    <section id="security" ref="security" class="panel scroll-mt-24" :class="forcedMfa ? 'border-warning/50' : ''" aria-labelledby="mfa-title">
      <div class="flex items-start justify-between gap-4 px-5 pt-5">
        <div>
          <h2 id="mfa-title" class="text-sm font-semibold">双因素验证</h2>
          <p class="mt-1 text-sm text-muted">登录时除了密码，还需要认证器应用（如 1Password、Google Authenticator）生成的 6 位验证码。</p>
        </div>
        <span v-if="user?.mfa_enabled" class="chip shrink-0 bg-success-soft text-success"><ShieldCheck class="size-3" />已启用</span>
      </div>

      <div class="px-5 py-5">
        <template v-if="!user?.mfa_enabled">
          <div v-if="mfaStep === 'idle'">
            <button type="button" class="btn btn-primary" @click="mfaStep = 'password'">启用双因素验证</button>
          </div>
          <form v-else-if="mfaStep === 'password'" class="grid max-w-sm gap-3" @submit.prevent="beginMfa">
            <label class="field">
              <span class="field-label">先确认当前密码</span>
              <input v-model="mfa.password" class="input" type="password" autocomplete="current-password" maxlength="128" required autofocus :disabled="mfaBusy" />
            </label>
            <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
            <div class="flex gap-2">
              <button class="btn btn-primary" type="submit" :disabled="mfaBusy || !mfa.password">{{ mfaBusy ? '正在验证…' : '继续' }}</button>
              <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
            </div>
          </form>
          <form v-else-if="mfaStep === 'scan'" class="grid gap-5 sm:grid-cols-[11rem_minmax(0,1fr)]" @submit.prevent="confirmMfa">
            <QrCode :value="mfa.uri" label="用认证器扫描此二维码" class="size-44 border border-line" />
            <div class="grid content-start gap-4">
              <div>
                <p class="font-medium">1. 用认证器应用扫描二维码</p>
                <p class="mt-1 text-sm text-muted">扫不了的话，手动输入下面的密钥。设置在 10 分钟内有效。</p>
                <div class="mt-2 flex items-center gap-2">
                  <code class="min-w-0 flex-1 truncate rounded-md bg-surface-2 px-2.5 py-1.5 font-mono text-xs tracking-wide">{{ mfa.secret }}</code>
                  <button type="button" class="btn btn-secondary btn-sm btn-icon" aria-label="复制密钥" @click="copySecret"><Copy class="size-4" /></button>
                </div>
              </div>
              <label class="field">
                <span class="field-label">2. 输入认证器显示的 6 位验证码</span>
                <input ref="codeInput" v-model="mfa.code" class="input input-mono h-12 w-48 text-center !text-2xl tracking-[0.4em]" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000" required :disabled="mfaBusy" :aria-invalid="!!mfaError" />
              </label>
              <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
              <p class="field-hint">确认后所有设备都会退出登录，接着会显示一次性的恢复码。</p>
              <div class="flex gap-2">
                <button class="btn btn-primary" type="submit" :disabled="mfaBusy || mfa.code.length !== 6">{{ mfaBusy ? '正在验证…' : '确认启用' }}</button>
                <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
              </div>
            </div>
          </form>
        </template>
        <template v-else>
          <p v-if="sessionState.session?.mfa_required" class="text-sm text-muted">这个部署要求管理员始终开启双因素验证，无法停用。</p>
          <button v-else-if="mfaStep !== 'disable'" type="button" class="btn btn-secondary" @click="mfaStep = 'disable'">停用双因素验证</button>
          <form v-else class="grid max-w-sm gap-3" @submit.prevent="disableMfa">
            <label class="field">
              <span class="field-label">当前密码</span>
              <input v-model="mfa.password" class="input" type="password" autocomplete="current-password" maxlength="128" required autofocus :disabled="mfaBusy" />
            </label>
            <label class="field">
              <span class="field-label">验证码或恢复码</span>
              <input v-model="mfa.code" class="input input-mono" autocomplete="one-time-code" maxlength="35" required :disabled="mfaBusy" />
            </label>
            <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
            <div class="flex gap-2">
              <button class="btn btn-danger" type="submit" :disabled="mfaBusy || !mfa.password || !mfa.code">{{ mfaBusy ? '正在处理…' : '停用' }}</button>
              <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
            </div>
          </form>
        </template>
      </div>
    </section>

    <section v-if="!forcedMfa" class="panel" aria-labelledby="password-title">
      <div class="px-5 pt-5">
        <h2 id="password-title" class="text-sm font-semibold">修改密码</h2>
        <p class="mt-1 text-sm text-muted">修改后所有设备都会退出登录。</p>
      </div>
      <form class="grid max-w-sm gap-4 px-5 py-5" novalidate @submit.prevent="changePassword">
        <input class="sr-only" :value="user?.username" autocomplete="username" readonly tabindex="-1" aria-hidden="true" />
        <label class="field">
          <span class="field-label">当前密码</span>
          <input v-model="password.current" class="input" type="password" autocomplete="current-password" required :disabled="passwordBusy" />
        </label>
        <label class="field">
          <span class="field-label">新密码</span>
          <input v-model="password.next" class="input" type="password" autocomplete="new-password" required :disabled="passwordBusy" :aria-invalid="!!nextError" @blur="passwordTouched = true" />
          <span :class="nextError ? 'field-error' : 'field-hint'">{{ nextError || '至少 12 个字符' }}</span>
        </label>
        <label class="field">
          <span class="field-label">确认新密码</span>
          <input v-model="password.confirm" class="input" type="password" autocomplete="new-password" required :disabled="passwordBusy" :aria-invalid="!!confirmError" />
          <span v-if="confirmError" class="field-error">{{ confirmError }}</span>
        </label>
        <p v-if="passwordError" class="rounded-md bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">{{ passwordError }}</p>
        <div><button class="btn btn-primary" type="submit" :disabled="passwordBusy || !password.current || !password.next || !password.confirm">{{ passwordBusy ? '正在保存…' : '更新密码' }}</button></div>
      </form>
    </section>
  </div>
</template>
