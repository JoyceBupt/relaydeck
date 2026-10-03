<script setup lang="ts">
import { nextTick, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { LoaderCircle } from '@lucide/vue'
import AuthFrame from '../components/AuthFrame.vue'
import PasswordInput from '../components/PasswordInput.vue'
import OtpInput from '../components/OtpInput.vue'
import { ApiError, errorMessage } from '../api/client'
import { api } from '../api/endpoints'
import { acceptSession, sessionState } from '../lib/session'

const router = useRouter()
const route = useRoute()
const form = reactive({ username: '', password: '', code: '' })
const step = ref<'password' | 'code'>('password')
const useRecovery = ref(false)
const busy = ref(false)
// Why the viewer landed here (signed out, password changed…); shown in place of the subtitle.
const notice = ref(sessionState.notice)
const error = ref('')
const locked = ref(false)
const codeInvalid = ref(false)
const otp = ref<InstanceType<typeof OtpInput> | null>(null)
const recoveryInput = ref<HTMLInputElement | null>(null)
const passwordInput = ref<InstanceType<typeof PasswordInput> | null>(null)

// Typing again clears the failure styling from the previous attempt.
watch(() => form.code, code => { if (code) codeInvalid.value = false })

function explain(failure: unknown) {
  if (failure instanceof ApiError && failure.code === 'rate_limited') return '尝试次数过多，1 分钟后再试'
  // The API answers every credential failure with the same generic 401 on purpose.
  if (failure instanceof ApiError && failure.status === 401) return '用户名或密码错误'
  return errorMessage(failure)
}

// Fields are disabled while a request runs; focus can only land once that ends.
async function focusCode() {
  busy.value = false
  await nextTick()
  if (useRecovery.value) recoveryInput.value?.focus()
  else otp.value?.focus()
}

async function submit() {
  if (busy.value || !form.username || (step.value === 'password' ? !form.password : !form.code)) return
  busy.value = true
  error.value = ''
  codeInvalid.value = false
  const epoch = sessionState.epoch
  try {
    const session = await api.login(form.username.trim(), form.password, step.value === 'code' ? form.code.trim() : undefined)
    if (epoch !== sessionState.epoch) return
    form.password = ''
    form.code = ''
    acceptSession(session, true)
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') && !route.query.next.startsWith('//') ? route.query.next : '/'
    await router.replace(next)
  } catch (failure) {
    if (failure instanceof ApiError && failure.code === 'mfa_required') {
      notice.value = ''
      step.value = 'code'
      await focusCode()
      return
    }
    error.value = explain(failure)
    locked.value = failure instanceof ApiError && failure.code === 'mfa_locked'
    if (step.value === 'code') {
      form.code = ''
      codeInvalid.value = true
      await focusCode()
    }
  } finally { busy.value = false }
}

async function back() {
  Object.assign(form, { password: '', code: '' })
  error.value = ''
  locked.value = false
  useRecovery.value = false
  step.value = 'password'
  await nextTick()
  passwordInput.value?.focus()
}

async function toggleRecovery() {
  useRecovery.value = !useRecovery.value
  form.code = ''
  error.value = ''
  codeInvalid.value = false
  await focusCode()
}
</script>

<template>
  <AuthFrame
    :title="step === 'password' ? '登录' : '两步验证'"
    :description="step === 'password' ? notice || undefined : useRecovery ? '输入一组未使用的恢复码' : '输入认证器中的 6 位验证码'"
  >
    <form class="grid gap-4" novalidate @submit.prevent="submit">
      <div v-if="step === 'password'" key="password" class="anim-step grid gap-4">
        <label class="field">
          <span class="field-label">用户名</span>
          <input v-model="form.username" class="input" name="username" autocomplete="username" autocapitalize="off" spellcheck="false" required maxlength="32" autofocus :disabled="busy" />
        </label>
        <label class="field">
          <span class="field-label">密码</span>
          <PasswordInput ref="passwordInput" v-model="form.password" name="password" autocomplete="current-password" required maxlength="128" :disabled="busy" :aria-invalid="error ? 'true' : undefined" />
        </label>
      </div>

      <div v-else key="code" class="anim-step grid gap-4">
        <p class="flex items-center justify-between gap-3 text-sm">
          <span class="min-w-0 truncate text-muted">{{ form.username }}</span>
          <button type="button" class="shrink-0 text-accent hover:underline disabled:opacity-50" :disabled="busy" @click="back">切换账户</button>
        </p>
        <OtpInput v-if="!useRecovery" ref="otp" v-model="form.code" label="验证码" :disabled="busy" :invalid="codeInvalid" @complete="submit" />
        <input
          v-else ref="recoveryInput" v-model="form.code" class="input input-mono" name="code" aria-label="恢复码" autocomplete="one-time-code" autocapitalize="off" spellcheck="false"
          maxlength="35" placeholder="xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx" required :disabled="busy" :aria-invalid="codeInvalid ? 'true' : undefined"
        />
      </div>

      <p v-if="error" class="field-error -mt-1" role="alert">
        {{ error }}<button v-if="locked && !useRecovery" type="button" class="ml-2 text-accent hover:underline" @click="toggleRecovery">使用恢复码</button>
      </p>

      <button class="btn btn-primary mt-1 h-10 w-full" type="submit" :disabled="busy || !form.username || (step === 'password' ? !form.password : !form.code)">
        <LoaderCircle v-if="busy" class="anim-spin size-4" aria-hidden="true" />
        {{ step === 'password' ? '登录' : '验证' }}
      </button>

      <button v-if="step === 'code'" type="button" class="mx-auto text-sm text-muted hover:text-fg disabled:opacity-50" :disabled="busy" @click="toggleRecovery">
        {{ useRecovery ? '使用验证码' : '使用恢复码' }}
      </button>
    </form>
  </AuthFrame>
</template>
