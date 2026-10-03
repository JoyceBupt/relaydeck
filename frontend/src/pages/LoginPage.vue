<script setup lang="ts">
import { nextTick, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft } from '@lucide/vue'
import AuthFrame from '../components/AuthFrame.vue'
import { ApiError, errorMessage } from '../api/client'
import { api } from '../api/endpoints'
import { acceptSession, sessionState } from '../lib/session'

const router = useRouter()
const route = useRoute()
const form = reactive({ username: '', password: '', code: '' })
const step = ref<'password' | 'code'>('password')
const useRecovery = ref(false)
const busy = ref(false)
const error = ref(sessionState.notice)
const codeInput = ref<HTMLInputElement | null>(null)
const passwordInput = ref<HTMLInputElement | null>(null)

async function submit() {
  if (busy.value) return
  busy.value = true
  error.value = ''
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
      step.value = 'code'
      await nextTick()
      codeInput.value?.focus()
    } else {
      error.value = errorMessage(failure)
      if (step.value === 'code') { form.code = ''; codeInput.value?.focus() }
    }
  } finally { busy.value = false }
}

async function back() {
  step.value = 'password'
  form.code = ''
  form.password = ''
  error.value = ''
  useRecovery.value = false
  await nextTick()
  passwordInput.value?.focus()
}

async function toggleRecovery() {
  useRecovery.value = !useRecovery.value
  form.code = ''
  await nextTick()
  codeInput.value?.focus()
}
</script>

<template>
  <AuthFrame
    :title="step === 'password' ? '登录' : '两步验证'"
    :description="step === 'password' ? '使用管理员发放的账户登录控制台。' : useRecovery ? '输入一组未使用过的恢复码。' : '打开认证器应用，输入当前显示的 6 位验证码。'"
  >
    <form class="grid gap-4" novalidate @submit.prevent="submit">
      <template v-if="step === 'password'">
        <label class="field">
          <span class="field-label">用户名</span>
          <input v-model="form.username" class="input" name="username" autocomplete="username" required maxlength="32" autofocus :disabled="busy" />
        </label>
        <label class="field">
          <span class="field-label">密码</span>
          <input ref="passwordInput" v-model="form.password" class="input" type="password" name="password" autocomplete="current-password" required maxlength="128" :disabled="busy" />
        </label>
      </template>
      <template v-else>
        <p class="-mt-2 text-xs text-muted">账户 <span class="font-medium text-fg">{{ form.username }}</span></p>
        <label class="field">
          <span class="field-label">{{ useRecovery ? '恢复码' : '验证码' }}</span>
          <input
            ref="codeInput" v-model="form.code" class="input input-mono"
            :class="useRecovery ? '' : 'h-12 text-center !text-2xl tracking-[0.5em]'"
            name="code" autocomplete="one-time-code" :inputmode="useRecovery ? 'text' : 'numeric'"
            :maxlength="useRecovery ? 35 : 6" :placeholder="useRecovery ? 'xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx' : '000000'"
            required :disabled="busy" :aria-invalid="!!error"
          />
        </label>
      </template>

      <p v-if="error" class="rounded-md bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">{{ error }}</p>

      <button class="btn btn-primary mt-1 w-full" type="submit" :disabled="busy || !form.username || (step === 'password' ? !form.password : !form.code)">
        {{ busy ? '正在验证…' : step === 'password' ? '登录' : '验证并登录' }}
      </button>

      <div v-if="step === 'code'" class="flex items-center justify-between">
        <button type="button" class="btn btn-ghost btn-sm -ml-2.5" :disabled="busy" @click="back"><ArrowLeft class="size-4" />换个账户</button>
        <button type="button" class="text-sm font-medium text-accent hover:underline" :disabled="busy" @click="toggleRecovery">
          {{ useRecovery ? '改用验证码' : '改用恢复码' }}
        </button>
      </div>
    </form>
  </AuthFrame>
</template>
