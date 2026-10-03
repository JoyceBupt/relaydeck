<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import AuthFrame from '../components/AuthFrame.vue'
import PasswordInput from '../components/PasswordInput.vue'
import { errorMessage } from '../api/client'
import { api } from '../api/endpoints'
import { clearSession, currentUser } from '../lib/session'
import { validatePassword } from '../lib/validation'

const router = useRouter()
const form = reactive({ current: '', next: '', confirm: '' })
const busy = ref(false)
const error = ref('')
const touched = ref(false)
const nextError = computed(() => (touched.value || form.next ? validatePassword(form.next) : ''))
// A rough strength hint for people who type a password themselves; the server only enforces length.
const strength = computed(() => {
  const value = form.next
  if (!value) return null
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z\d]/].filter(pattern => pattern.test(value)).length
  let score = value.length >= 12 ? 1 : 0
  if (score && value.length >= 16) score++
  if (score && classes >= 3) score++
  if (score && (value.length >= 20 || classes === 4)) score++
  const name = currentUser.value?.username.toLowerCase()
  if (name && value.toLowerCase().includes(name)) score = Math.min(score, 1)
  return { score, label: ['太短', '偏弱', '一般', '较强', '很强'][score], tone: score <= 1 ? 'is-bad' : score === 2 ? 'is-warn' : 'is-ok' }
})
const confirmError = computed(() => (form.confirm && form.confirm !== form.next ? '两次输入不一致' : ''))

async function submit() {
  touched.value = true
  if (validatePassword(form.next) || form.confirm !== form.next || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await api.changePassword(form.current, form.next)
    clearSession('密码已修改')
    await router.replace({ name: 'login' })
  } catch (failure) { error.value = errorMessage(failure) } finally { busy.value = false }
}

async function signOut() {
  try { await api.logout() } catch { /* session may already be gone */ }
  clearSession()
  await router.replace({ name: 'login' })
}
</script>

<template>
  <AuthFrame title="修改初始密码" :description="currentUser?.username">
    <form class="grid gap-4" novalidate @submit.prevent="submit">
      <input class="sr-only" :value="currentUser?.username" autocomplete="username" readonly tabindex="-1" aria-hidden="true" />
      <label class="field">
        <span class="field-label">初始密码</span>
        <PasswordInput v-model="form.current" autocomplete="current-password" required :disabled="busy" />
      </label>
      <label class="field">
        <span class="field-label">新密码</span>
        <PasswordInput v-model="form.next" autocomplete="new-password" required :disabled="busy" :aria-invalid="nextError ? 'true' : undefined" @blur="touched = true" />
        <span v-if="strength" class="flex items-center gap-3">
          <span class="meter w-28" aria-hidden="true"><span v-for="index in 4" :key="index" :class="index <= strength.score ? strength.tone : ''" /></span>
          <span class="text-xs text-muted">强度：{{ strength.label }}</span>
        </span>
        <span :class="nextError ? 'field-error' : 'field-hint'">{{ nextError || '至少 12 个字符' }}</span>
      </label>
      <label class="field">
        <span class="field-label">确认新密码</span>
        <PasswordInput v-model="form.confirm" autocomplete="new-password" required :disabled="busy" :aria-invalid="confirmError ? 'true' : undefined" />
        <span v-if="confirmError" class="field-error">{{ confirmError }}</span>
      </label>
      <p v-if="error" class="field-error" role="alert">{{ error }}</p>
      <button class="btn btn-primary mt-1 w-full" type="submit" :disabled="busy || !form.current || !form.next || !form.confirm">{{ busy ? '保存中…' : '修改密码' }}</button>
      <button class="btn btn-ghost w-full" type="button" :disabled="busy" @click="signOut">退出登录</button>
    </form>
  </AuthFrame>
</template>
