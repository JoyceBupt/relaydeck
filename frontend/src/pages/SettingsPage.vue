<script setup lang="ts">
import { computed, nextTick, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Copy, ShieldCheck } from '@lucide/vue'
import UpgradePanel from '../components/UpgradePanel.vue'
import QrCode from '../components/QrCode.vue'
import OtpInput from '../components/OtpInput.vue'
import PasswordInput from '../components/PasswordInput.vue'
import { api } from '../api/endpoints'
import { errorMessage, isStaleError } from '../api/client'
import { clearSession, currentUser, forcedMfa, sessionState } from '../lib/session'
import { validatePassword } from '../lib/validation'
import { toast } from '../lib/toast'

const route = useRoute()
const router = useRouter()
const user = computed(() => currentUser.value)

// Two-factor authentication
type MfaStep = 'idle' | 'password' | 'scan' | 'disable'
const mfaStep = ref<MfaStep>('idle')
const mfa = reactive({ password: '', code: '', secret: '', uri: '' })
const mfaBusy = ref(false)
const mfaError = ref('')
const codeInput = ref<InstanceType<typeof OtpInput> | null>(null)
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
    mfaBusy.value = false
    await nextTick()
    codeInput.value?.focus()
  } catch (error) { if (!isStaleError(error)) mfaError.value = errorMessage(error) } finally { mfaBusy.value = false }
}

async function confirmMfa() {
  if (mfaBusy.value) return
  mfaBusy.value = true
  mfaError.value = ''
  const epoch = sessionState.epoch
  const enrollmentOwner = currentUser.value?.id ?? null
  try {
    const result = await api.confirmMfa(mfa.code.trim())
    if (epoch !== sessionState.epoch) return
    // Enrollment revokes every session; the codes are shown once, then the viewer signs in again.
    clearSession()
    sessionState.recoveryCodes = result.recovery_codes
    sessionState.recoveryOwner = enrollmentOwner
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
    clearSession('两步验证已关闭')
    await router.replace({ name: 'login' })
  } catch (error) { if (!isStaleError(error)) mfaError.value = errorMessage(error) } finally { mfaBusy.value = false }
}

async function copySecret() {
  try { await navigator.clipboard.writeText(mfa.secret); toast('已复制密钥') } catch { toast('复制失败', { tone: 'danger' }) }
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
    clearSession('密码已修改')
    await router.replace({ name: 'login' })
  } catch (error) { if (!isStaleError(error)) passwordError.value = errorMessage(error) } finally { passwordBusy.value = false }
}

const security = ref<HTMLElement | null>(null)
onMounted(() => { if (route.hash === '#security' || forcedMfa.value) security.value?.scrollIntoView({ block: 'start' }) })
</script>

<template>
  <div class="mx-auto grid max-w-3xl gap-8">
    <div>
      <h1 class="page-title">设置</h1>
      <p v-if="forcedMfa" class="mt-1 text-warning">管理员须先开启两步验证</p>
    </div>

    <UpgradePanel v-if="sessionState.session?.can_upgrade" />

    <section id="security" ref="security" class="panel scroll-mt-24" :class="forcedMfa ? 'border-warning/50' : ''" aria-labelledby="mfa-title">
      <div class="flex items-center justify-between gap-4 px-5 pt-5">
        <h2 id="mfa-title" class="text-sm font-semibold">两步验证</h2>
        <span v-if="user?.mfa_enabled" class="chip chip-green shrink-0"><ShieldCheck class="size-3" />已开启</span>
      </div>

      <div class="px-5 py-5">
        <template v-if="!user?.mfa_enabled">
          <div v-if="mfaStep === 'idle'">
            <button type="button" class="btn btn-primary" @click="mfaStep = 'password'">开启</button>
          </div>
          <form v-else-if="mfaStep === 'password'" class="grid max-w-sm gap-3" @submit.prevent="beginMfa">
            <label class="field">
              <span class="field-label">当前密码</span>
              <PasswordInput v-model="mfa.password" autocomplete="current-password" maxlength="128" required autofocus :disabled="mfaBusy" />
            </label>
            <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
            <div class="flex gap-2">
              <button class="btn btn-primary" type="submit" :disabled="mfaBusy || !mfa.password">{{ mfaBusy ? '验证中…' : '继续' }}</button>
              <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
            </div>
          </form>
          <form v-else-if="mfaStep === 'scan'" class="grid gap-5 sm:grid-cols-[11rem_minmax(0,1fr)]" @submit.prevent="confirmMfa">
            <QrCode :value="mfa.uri" label="用认证器扫描此二维码" class="size-44 rounded-xl border border-line" />
            <div class="grid content-start gap-4">
              <div>
                <p class="font-medium">用认证器扫描二维码</p>
                <p class="mt-1 text-sm text-muted">或输入密钥，10 分钟内有效</p>
                <div class="mt-2 flex items-center gap-2">
                  <code class="min-w-0 flex-1 truncate rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 font-mono text-xs tracking-wide">{{ mfa.secret }}</code>
                  <button type="button" class="btn btn-secondary btn-sm btn-icon" aria-label="复制密钥" @click="copySecret"><Copy class="size-4" /></button>
                </div>
              </div>
              <div class="field max-w-xs">
                <span class="field-label">验证码</span>
                <OtpInput ref="codeInput" v-model="mfa.code" label="验证码" :disabled="mfaBusy" :invalid="!!mfaError" @complete="confirmMfa" />
              </div>
              <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
              <p class="field-hint">开启后所有设备将退出登录</p>
              <div class="flex gap-2">
                <button class="btn btn-primary" type="submit" :disabled="mfaBusy || mfa.code.length !== 6">{{ mfaBusy ? '验证中…' : '开启' }}</button>
                <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
              </div>
            </div>
          </form>
        </template>
        <template v-else>
          <p v-if="sessionState.session?.mfa_required" class="text-sm text-muted">管理员不能关闭</p>
          <button v-else-if="mfaStep !== 'disable'" type="button" class="btn btn-secondary" @click="mfaStep = 'disable'">关闭</button>
          <form v-else class="grid max-w-sm gap-3" @submit.prevent="disableMfa">
            <label class="field">
              <span class="field-label">当前密码</span>
              <PasswordInput v-model="mfa.password" autocomplete="current-password" maxlength="128" required autofocus :disabled="mfaBusy" />
            </label>
            <label class="field">
              <span class="field-label">验证码或恢复码</span>
              <input v-model="mfa.code" class="input input-mono" autocomplete="one-time-code" maxlength="35" required :disabled="mfaBusy" />
            </label>
            <p v-if="mfaError" class="field-error" role="alert">{{ mfaError }}</p>
            <div class="flex gap-2">
              <button class="btn btn-danger" type="submit" :disabled="mfaBusy || !mfa.password || !mfa.code">{{ mfaBusy ? '处理中…' : '关闭' }}</button>
              <button class="btn btn-ghost" type="button" :disabled="mfaBusy" @click="resetMfa">取消</button>
            </div>
          </form>
        </template>
      </div>
    </section>

    <section v-if="!forcedMfa" class="panel" aria-labelledby="password-title">
      <div class="px-5 pt-5">
        <h2 id="password-title" class="text-sm font-semibold">修改密码</h2>
        <p class="mt-1 text-sm text-muted">修改后所有设备将退出登录</p>
      </div>
      <form class="grid max-w-sm gap-4 px-5 py-5" novalidate @submit.prevent="changePassword">
        <input class="sr-only" :value="user?.username" autocomplete="username" readonly tabindex="-1" aria-hidden="true" />
        <label class="field">
          <span class="field-label">当前密码</span>
          <PasswordInput v-model="password.current" autocomplete="current-password" required :disabled="passwordBusy" />
        </label>
        <label class="field">
          <span class="field-label">新密码</span>
          <PasswordInput v-model="password.next" autocomplete="new-password" required :disabled="passwordBusy" :aria-invalid="nextError ? 'true' : undefined" @blur="passwordTouched = true" />
          <span :class="nextError ? 'field-error' : 'field-hint'">{{ nextError || '至少 12 个字符' }}</span>
        </label>
        <label class="field">
          <span class="field-label">确认新密码</span>
          <PasswordInput v-model="password.confirm" autocomplete="new-password" required :disabled="passwordBusy" :aria-invalid="confirmError ? 'true' : undefined" />
          <span v-if="confirmError" class="field-error">{{ confirmError }}</span>
        </label>
        <p v-if="passwordError" class="field-error" role="alert">{{ passwordError }}</p>
        <div><button class="btn btn-primary" type="submit" :disabled="passwordBusy || !password.current || !password.next || !password.confirm">{{ passwordBusy ? '保存中…' : '修改密码' }}</button></div>
      </form>
    </section>
  </div>
</template>
