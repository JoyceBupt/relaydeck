<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import AuthFrame from '../components/AuthFrame.vue'
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
const confirmError = computed(() => (form.confirm && form.confirm !== form.next ? '两次输入不一致' : ''))

async function submit() {
  touched.value = true
  if (validatePassword(form.next) || form.confirm !== form.next || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await api.changePassword(form.current, form.next)
    clearSession('密码已更新，请用新密码登录')
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
  <AuthFrame title="设置新密码" :description="`首次登录需要替换管理员发放的初始密码${currentUser ? `（${currentUser.username}）` : ''}。完成后请重新登录。`">
    <form class="grid gap-4" novalidate @submit.prevent="submit">
      <input class="sr-only" :value="currentUser?.username" autocomplete="username" readonly tabindex="-1" aria-hidden="true" />
      <label class="field">
        <span class="field-label">初始密码</span>
        <input v-model="form.current" class="input" type="password" autocomplete="current-password" required :disabled="busy" />
      </label>
      <label class="field">
        <span class="field-label">新密码</span>
        <input v-model="form.next" class="input" type="password" autocomplete="new-password" required :disabled="busy" :aria-invalid="!!nextError" @blur="touched = true" />
        <span :class="nextError ? 'field-error' : 'field-hint'">{{ nextError || '至少 12 个字符，建议使用密码管理器生成' }}</span>
      </label>
      <label class="field">
        <span class="field-label">确认新密码</span>
        <input v-model="form.confirm" class="input" type="password" autocomplete="new-password" required :disabled="busy" :aria-invalid="!!confirmError" />
        <span v-if="confirmError" class="field-error">{{ confirmError }}</span>
      </label>
      <p v-if="error" class="rounded-md bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">{{ error }}</p>
      <button class="btn btn-primary mt-1 w-full" type="submit" :disabled="busy || !form.current || !form.next || !form.confirm">{{ busy ? '正在保存…' : '更新密码' }}</button>
      <button class="btn btn-ghost w-full" type="button" :disabled="busy" @click="signOut">退出登录</button>
    </form>
  </AuthFrame>
</template>
