<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useMutation } from '@tanstack/vue-query'
import { ArrowRightLeft, Copy, KeyRound, RotateCw, ShieldCheck, Sparkles } from '@lucide/vue'
import SideDrawer from './SideDrawer.vue'
import PortRuler from './PortRuler.vue'
import StatusMark from './StatusMark.vue'
import UiSwitch from './UiSwitch.vue'
import ConfirmDialog from './ConfirmDialog.vue'
import { api } from '../api/endpoints'
import { errorMessage, isStaleError } from '../api/client'
import type { Rule, User } from '../types'
import { afterRuleChange, usePorts, useRetry } from '../lib/queries'
import { dateInputValue, expiry, expiryFromDateInput, nowSeconds } from '../lib/format'
import { validatePassword, validateUsername } from '../lib/validation'
import { generatePassword } from '../lib/password'
import { toast } from '../lib/toast'

const props = defineProps<{ open: boolean; userId: number | null; users: User[]; rules: Rule[]; loaded: boolean }>()
const emit = defineEmits<{ close: [] }>()
const router = useRouter()

const user = computed(() => (props.userId === null ? null : props.users.find(item => item.id === props.userId) ?? null))
const isNew = computed(() => props.userId === null)
const missing = computed(() => !isNew.value && props.loaded && !user.value)
const ports = usePorts(computed(() => (user.value ? user.value.id : null)))
const statuses = computed(() => Object.fromEntries(props.rules.map(rule => [rule.id, { name: rule.name, status: rule.runtime_status }])))
const ownRules = computed(() => props.rules.filter(rule => rule.owner_id === props.userId))
const failed = computed(() => ownRules.value.filter(rule => rule.runtime_status === 'failed'))

interface FormState { username: string; password: string; enabled: boolean; port_start: number | null; port_end: number | null; max_rules: number | null; expires: string }
const form = reactive<FormState>({ username: '', password: '', enabled: true, port_start: null, port_end: null, max_rules: 5, expires: '' })
const baseline = ref('')
const initializedFor = ref<string | null>(null)
const submitted = ref(false)
const serverError = ref('')
const snapshot = () => JSON.stringify(form)

function suggestRange() {
  const highest = Math.max(29_999, ...props.users.map(item => item.port_end))
  const start = Math.ceil((highest + 1) / 100) * 100
  return start + 99 <= 65535 ? { start, end: start + 99 } : { start: null, end: null }
}
function load() {
  const key = `${props.userId ?? 'new'}`
  if (initializedFor.value === key || (!isNew.value && !user.value)) return
  if (user.value) {
    Object.assign(form, { username: user.value.username, password: '', enabled: user.value.enabled, port_start: user.value.port_start, port_end: user.value.port_end, max_rules: user.value.max_rules, expires: dateInputValue(user.value.expires_at) })
  } else {
    const range = suggestRange()
    Object.assign(form, { username: '', password: generatePassword(), enabled: true, port_start: range.start, port_end: range.end, max_rules: 5, expires: '' })
  }
  submitted.value = false
  serverError.value = ''
  initializedFor.value = key
  baseline.value = snapshot()
}
watch(() => [props.open, props.userId, user.value?.id], () => { if (props.open) load(); else initializedFor.value = null }, { immediate: true })
const dirty = computed(() => initializedFor.value !== null && snapshot() !== baseline.value)

const overlap = computed(() => {
  if (form.port_start === null || form.port_end === null) return null
  return props.users.find(item => item.id !== props.userId && item.port_start <= form.port_end! && item.port_end >= form.port_start!) ?? null
})
const errors = computed(() => {
  const start = form.port_start
  const end = form.port_end
  let range = ''
  if (start === null || end === null || !Number.isInteger(start) || !Number.isInteger(end)) range = '填写起止端口'
  else if (start < 1024 || end > 65535) range = '范围 1024–65535'
  else if (start > end) range = '起始端口大于结束端口'
  else if (overlap.value) range = `与 ${overlap.value.username} 的端口段 ${overlap.value.port_start}–${overlap.value.port_end} 重叠`
  const expiresAt = expiryFromDateInput(form.expires)
  return {
    username: isNew.value ? validateUsername(form.username) : '',
    password: isNew.value ? validatePassword(form.password) : '',
    range,
    maxRules: form.max_rules === null || !Number.isInteger(form.max_rules) || form.max_rules < 0 || form.max_rules > 30 ? '范围 0–30' : '',
    expires: form.enabled && expiresAt !== null && expiresAt <= nowSeconds() ? '须晚于今天' : '',
  }
})
const valid = computed(() => Object.values(errors.value).every(message => !message))
const show = (field: keyof typeof errors.value) => (submitted.value ? errors.value[field] : '')

// Narrowing a grant disables rules outside it on the server; say so before saving.
const affected = computed(() => {
  if (isNew.value || form.port_start === null || form.port_end === null || form.max_rules === null) return 0
  const enabled = ownRules.value.filter(rule => rule.enabled)
  const outside = enabled.filter(rule => rule.listen_port < form.port_start! || rule.listen_port > form.port_end!)
  const inside = enabled.length - outside.length
  return outside.length + Math.max(0, inside - form.max_rules)
})

const save = useMutation({
  mutationFn: () => {
    const grant = { port_start: form.port_start!, port_end: form.port_end!, max_rules: form.max_rules!, expires_at: expiryFromDateInput(form.expires) }
    return isNew.value
      ? api.createUser({ username: form.username.trim(), password: form.password, ...grant })
      : api.updateUser(props.userId!, { enabled: form.enabled, ...grant })
  },
  onSettled: afterRuleChange,
})

async function submit() {
  submitted.value = true
  serverError.value = ''
  if (!valid.value || save.isPending.value) return
  try {
    const saved = await save.mutateAsync()
    baseline.value = snapshot()
    if (isNew.value) {
      toast(`已创建 ${saved.username}`)
      initializedFor.value = `${saved.id}`
      form.password = ''
      await router.replace(`/accounts/${saved.id}`)
    } else {
      toast(`已保存 ${saved.username}`)
    }
  } catch (error) { if (!isStaleError(error)) serverError.value = errorMessage(error) }
}

async function copyPassword(value: string) {
  try { await navigator.clipboard.writeText(value); toast('已复制密码') } catch { toast('复制失败', { tone: 'danger' }) }
}

const resetOpen = ref(false)
const resetPassword = ref('')
const reset = useMutation({ mutationFn: () => api.resetPassword(props.userId!, resetPassword.value), onSettled: afterRuleChange })
function openReset() { resetPassword.value = generatePassword(); resetOpen.value = true }
async function confirmReset() {
  if (validatePassword(resetPassword.value)) return
  try {
    await reset.mutateAsync()
    toast(`已重置 ${user.value?.username} 的密码`)
    resetOpen.value = false
    resetPassword.value = ''
  } catch (error) { if (!isStaleError(error)) toast('重置失败', { description: errorMessage(error), tone: 'danger' }) }
}

const retry = useRetry()
const confirmDiscard = ref(false)
let pending: (() => void) | null = null
function guard(action: () => void) { if (dirty.value) { pending = action; confirmDiscard.value = true } else action() }
function requestClose() { guard(() => emit('close')) }
function onBeforeClose(event: Event) { if (dirty.value) { event.preventDefault(); requestClose() } }
function discard() { confirmDiscard.value = false; baseline.value = snapshot(); pending?.(); pending = null }

const expiryInfo = computed(() => (user.value ? expiry(user.value.expires_at) : null))
</script>

<template>
  <SideDrawer :open="open" :title="isNew ? '新建账户' : user?.username ?? '账户'" :description="user ? `ID ${user.id} · ${user.role === 'admin' ? '管理员' : '租户'}` : undefined" @close="requestClose" @before-close="onBeforeClose">
    <p v-if="missing" class="py-8 text-center text-muted">账户不存在</p>
    <div v-else class="grid gap-6">
      <section v-if="user" class="grid gap-3">
        <div class="flex flex-wrap gap-1.5">
          <span class="chip" :class="user.enabled ? 'chip-green' : ''">{{ user.enabled ? '已启用' : '已停用' }}</span>
          <span v-if="expiryInfo" class="chip" :class="expiryInfo.tone === 'soon' ? 'chip-amber' : expiryInfo.tone === 'expired' ? 'chip-red' : ''">{{ expiryInfo.text }}</span>
          <span class="chip" :class="user.mfa_enabled ? 'chip-blue' : ''"><ShieldCheck class="size-3" />{{ user.mfa_enabled ? '两步验证' : '无两步验证' }}</span>
          <span v-if="user.must_change_password" class="chip chip-violet">未改初始密码</span>
        </div>
        <div v-if="failed.length" class="grid gap-1">
          <div class="flex min-h-8 items-center gap-2">
            <StatusMark status="failed" />
            <span class="font-medium text-danger">{{ failed.length }} 条生效失败</span>
            <button type="button" class="btn btn-secondary btn-sm ml-auto" :disabled="retry.isPending.value" @click="retry.mutate(user.id)"><RotateCw class="size-3.5" />重试</button>
          </div>
          <p v-if="failed[0].runtime_error" class="font-mono text-xs text-danger [overflow-wrap:anywhere]">{{ failed[0].runtime_error }}</p>
        </div>
        <div class="flex flex-wrap gap-2">
          <RouterLink :to="{ path: '/rules', query: { owner: String(user.id) } }" class="btn btn-secondary btn-sm"><ArrowRightLeft class="size-4" />查看 {{ user.rule_count }} 条转发</RouterLink>
          <button v-if="user?.role !== 'admin'" type="button" class="btn btn-secondary btn-sm" @click="openReset"><KeyRound class="size-4" />重置密码</button>
        </div>
      </section>

      <form id="account-form" class="grid gap-5" novalidate @submit.prevent="submit">
        <template v-if="isNew">
          <label class="field">
            <span class="field-label">用户名</span>
            <input v-model="form.username" class="input" maxlength="32" autocomplete="off" spellcheck="false" :aria-invalid="!!show('username')" />
            <span :class="show('username') ? 'field-error' : 'field-hint'">{{ show('username') || '3–32 位，字母开头' }}</span>
          </label>
          <div class="field">
            <label class="field-label" for="initial-password">初始密码</label>
            <div class="flex gap-2">
              <input id="initial-password" v-model="form.password" class="input input-mono" autocomplete="new-password" spellcheck="false" :aria-invalid="!!show('password')" />
              <button type="button" class="btn btn-secondary btn-icon" aria-label="重新生成" title="重新生成" @click="form.password = generatePassword()"><Sparkles class="size-4" /></button>
              <button type="button" class="btn btn-secondary btn-icon" aria-label="复制密码" title="复制" @click="copyPassword(form.password)"><Copy class="size-4" /></button>
            </div>
            <span :class="show('password') ? 'field-error' : 'field-hint'">{{ show('password') || '首次登录须修改' }}</span>
          </div>
        </template>

        <div class="field">
          <span class="field-label">端口段</span>
          <div class="flex items-center gap-2">
            <input v-model.number="form.port_start" class="input input-mono" type="number" min="1024" max="65535" aria-label="起始端口" :aria-invalid="!!show('range')" />
            <span class="text-faint">–</span>
            <input v-model.number="form.port_end" class="input input-mono" type="number" min="1024" max="65535" aria-label="结束端口" :aria-invalid="!!show('range')" />
          </div>
          <span :class="show('range') || (overlap && !submitted) ? 'field-error' : 'field-hint'">
            {{ show('range') || (overlap ? `与 ${overlap.username} 的端口段重叠` : form.port_start && form.port_end && form.port_end >= form.port_start ? `${form.port_end - form.port_start + 1} 个端口` : '') }}
          </span>
          <div v-if="user && ports.data.value" class="mt-1.5"><PortRuler :usage="ports.data.value" :statuses="statuses" /></div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <label class="field">
            <span class="field-label">规则上限</span>
            <input v-model.number="form.max_rules" class="input input-mono" type="number" min="0" max="30" :aria-invalid="!!show('maxRules')" />
            <span v-if="show('maxRules')" class="field-error">{{ show('maxRules') }}</span>
          </label>
          <div v-if="user?.role !== 'admin'" class="field">
            <label class="field-label" for="account-expiry">到期日</label>
            <input id="account-expiry" v-model="form.expires" class="input" type="date" :aria-invalid="!!show('expires')" />
            <span v-if="show('expires')" class="field-error">{{ show('expires') }}</span>
            <button v-else-if="form.expires" type="button" class="w-fit text-xs font-medium text-accent hover:underline" @click="form.expires = ''">清除</button>
            <span v-else class="field-hint">留空为长期</span>
          </div>
        </div>

        <div v-if="!isNew && user?.role !== 'admin'" class="flex items-center justify-between gap-4">
          <div>
            <p class="field-label">启用</p>
            <p class="field-hint">停用后无法登录，转发全部停止</p>
          </div>
          <UiSwitch v-model="form.enabled" label="启用账户" />
        </div>

        <p v-if="affected > 0" class="text-xs text-warning" role="status">将停用 {{ affected }} 条超出授权的转发</p>
        <p v-if="!isNew && dirty" class="field-hint">保存后该账户需重新登录</p>
        <p v-if="serverError" class="field-error" role="alert">{{ serverError }}</p>
      </form>
    </div>

    <template v-if="!missing" #footer>
      <span v-if="dirty && !isNew" class="text-xs text-muted max-sm:hidden">未保存</span>
      <button type="button" class="btn btn-secondary ml-auto" @click="requestClose">取消</button>
      <button type="submit" form="account-form" class="btn btn-primary" :disabled="save.isPending.value || (!isNew && !dirty)">
        {{ save.isPending.value ? '保存中…' : isNew ? '创建' : '保存' }}
      </button>
    </template>
  </SideDrawer>

  <ConfirmDialog :open="resetOpen" :title="`重置 ${user?.username ?? ''} 的密码？`" description="该账户会被登出，用临时密码登录后须修改。" confirm-label="重置" :busy="reset.isPending.value" @confirm="confirmReset" @cancel="resetOpen = false">
    <div class="mt-4 field">
      <label class="field-label" for="reset-password">临时密码</label>
      <div class="flex gap-2">
        <input id="reset-password" v-model="resetPassword" class="input input-mono" autocomplete="new-password" spellcheck="false" :aria-invalid="!!validatePassword(resetPassword)" />
        <button type="button" class="btn btn-secondary btn-icon" aria-label="复制密码" @click="copyPassword(resetPassword)"><Copy class="size-4" /></button>
      </div>
      <span :class="validatePassword(resetPassword) ? 'field-error' : 'field-hint'">{{ validatePassword(resetPassword) }}</span>
    </div>
  </ConfirmDialog>
  <ConfirmDialog :open="confirmDiscard" title="放弃修改？" confirm-label="放弃" danger @confirm="discard" @cancel="confirmDiscard = false" />
</template>
