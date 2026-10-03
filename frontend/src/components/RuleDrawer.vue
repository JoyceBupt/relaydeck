<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useSwipe } from '@vueuse/core'
import { TagsInputInput, TagsInputItem, TagsInputItemDelete, TagsInputItemText, TagsInputRoot } from 'reka-ui'
import { RotateCw, Trash2, X } from '@lucide/vue'
import SideDrawer from './SideDrawer.vue'
import StatusMark from './StatusMark.vue'
import PortRuler from './PortRuler.vue'
import Segmented from './Segmented.vue'
import UiSwitch from './UiSwitch.vue'
import ConfirmDialog from './ConfirmDialog.vue'
import { errorMessage, isStaleError } from '../api/client'
import type { Health, Protocol, Rule, RuleInput, User } from '../types'
import { currentUser, isAdmin } from '../lib/session'
import { sharedToggle, useDeleteRule, usePorts, useRetry, useSaveRule } from '../lib/queries'
import { dateTime, expiry, hostText, protocolLabels, relative } from '../lib/format'
import { validateCidr, validatePort, validateRuleName, validateTargetHost } from '../lib/validation'
import { toast } from '../lib/toast'

const props = defineProps<{
  open: boolean
  ruleId: number | null
  rules: Rule[]
  loaded: boolean
  users: User[]
  health: Health | undefined
  sequence: number[]
  presetPort?: number | null
  presetOwner?: number | null
  /** Rule whose settings seed a new one ("复制为新转发"). */
  clone?: Rule | null
}>()
const emit = defineEmits<{ close: [] }>()
const router = useRouter()

const rule = computed(() => (props.ruleId === null ? null : props.rules.find(item => item.id === props.ruleId) ?? null))
const isNew = computed(() => props.ruleId === null)
const missing = computed(() => !isNew.value && props.loaded && !rule.value)

function canCreateFor(user: User) {
  return user.enabled && expiry(user.expires_at).tone !== 'expired' && user.rule_count < user.max_rules
}
const owners = computed(() => (isAdmin.value ? props.users : currentUser.value ? [currentUser.value] : []))
const creatableOwners = computed(() => owners.value.filter(canCreateFor))

interface FormState { name: string; owner_id: number | null; listen_port: number | null; protocol: Protocol; target_host: string; target_port: number | null; sources: string[]; enabled: boolean }
const blank = (): FormState => ({ name: '', owner_id: null, listen_port: null, protocol: 'tcp', target_host: '', target_port: 443, sources: [], enabled: true })
const form = reactive<FormState>(blank())
const baseline = ref('')
const initializedFor = ref<string | null>(null)
const submitted = ref(false)
const serverError = ref('')
const confirmDelete = ref(false)
const confirmDiscard = ref(false)
let pendingNavigation: (() => void) | null = null

const ownerId = computed(() => form.owner_id ?? rule.value?.owner_id ?? null)
const owner = computed(() => owners.value.find(user => user.id === ownerId.value) ?? (rule.value && currentUser.value?.id === rule.value.owner_id ? currentUser.value : null))
const ports = usePorts(ownerId)
const statuses = computed(() => Object.fromEntries(props.rules.map(item => [item.id, { name: item.name, status: item.runtime_status }])))

function snapshot() { return JSON.stringify(form) }
function load() {
  const key = props.ruleId === null ? `new:${props.clone?.id ?? ''}` : `${props.ruleId}`
  if (initializedFor.value === key) return
  if (!isNew.value && !rule.value) return
  Object.assign(form, blank())
  if (rule.value) {
    Object.assign(form, {
      name: rule.value.name, owner_id: rule.value.owner_id, listen_port: rule.value.listen_port, protocol: rule.value.protocol,
      target_host: rule.value.target_host, target_port: rule.value.target_port, sources: [...rule.value.source_cidrs], enabled: rule.value.enabled,
    })
  } else {
    const preferred = creatableOwners.value.find(user => user.id === props.presetOwner)
      ?? creatableOwners.value.find(user => user.id === currentUser.value?.id) ?? creatableOwners.value[0]
    form.owner_id = preferred?.id ?? null
    form.listen_port = props.presetPort ?? null
    if (props.clone) {
      Object.assign(form, {
        name: `${props.clone.name} 副本`, protocol: props.clone.protocol, target_host: props.clone.target_host,
        target_port: props.clone.target_port, sources: [...props.clone.source_cidrs], enabled: props.clone.enabled,
      })
    }
  }
  submitted.value = false
  serverError.value = ''
  initializedFor.value = key
  baseline.value = snapshot()
}
watch(() => [props.open, props.ruleId, rule.value?.id, props.users.length, props.clone?.id], () => { if (props.open) load(); else initializedFor.value = null }, { immediate: true })

// Defaults that depend on data still loading (accounts, port usage) are filled in
// when it arrives, without disturbing anything the viewer already typed.
function fillDefault(apply: () => void) {
  const clean = snapshot() === baseline.value
  apply()
  if (clean) baseline.value = snapshot()
}
watch(creatableOwners, list => {
  if (!props.open || !isNew.value || form.owner_id !== null || !list.length) return
  fillDefault(() => {
    form.owner_id = (list.find(user => user.id === props.presetOwner) ?? list.find(user => user.id === currentUser.value?.id) ?? list[0]).id
  })
})
// New rules start on the first free port of the chosen account once its usage is known.
watch(() => [ports.data.value, form.owner_id] as const, ([usage]) => {
  if (!isNew.value || !usage || usage.owner_id !== form.owner_id || form.listen_port !== null) return
  const taken = new Set([...usage.reserved, 22, 80, 443, ...usage.leases.map(lease => lease.port)])
  fillDefault(() => {
    for (let port = usage.port_start; port <= usage.port_end; port++) if (!taken.has(port)) { form.listen_port = port; break }
  })
})
function changeOwner(event: Event) {
  form.owner_id = Number((event.target as HTMLSelectElement).value)
  form.listen_port = null
}

const dirty = computed(() => initializedFor.value !== null && snapshot() !== baseline.value)

const errors = computed(() => {
  const usage = ports.data.value
  const range = owner.value ? { min: owner.value.port_start, max: owner.value.port_end } : { min: 1024, max: 65535 }
  let port = validatePort(form.listen_port, range.min, range.max)
  if (!port && form.listen_port !== null) {
    if ([22, 80, 443, ...(usage?.reserved ?? [])].includes(form.listen_port)) port = '系统保留端口'
    const lease = usage?.leases.find(item => item.port === form.listen_port)
    if (lease && lease.rule_id !== props.ruleId) {
      const holder = props.rules.find(item => item.id === lease.rule_id)
      port = lease.state === 'releasing' ? '端口释放中，稍后再试' : `已被 ${holder?.name ?? '其他规则'} 占用`
    }
  }
  return {
    name: validateRuleName(form.name),
    owner: isNew.value && !form.owner_id ? '没有可用额度的账户' : '',
    port,
    host: validateTargetHost(form.target_host),
    targetPort: validatePort(form.target_port),
    sources: form.sources.some(value => !validateCidr(value)) ? '网段格式错误' : form.sources.length > 32 ? '最多 32 个网段' : '',
  }
})
const valid = computed(() => Object.values(errors.value).every(message => !message))
const show = (field: keyof typeof errors.value) => (submitted.value ? errors.value[field] : '')


const save = useSaveRule()
const remove = useDeleteRule()
const toggle = sharedToggle()
const retry = useRetry()

async function submit() {
  submitted.value = true
  serverError.value = ''
  if (!valid.value || save.isPending.value) return
  const input: RuleInput = {
    name: form.name.trim(), listen_port: form.listen_port!, target_host: form.target_host.trim(), target_port: form.target_port!,
    // An existing rule's on/off state is switched live (with undo), never through this form.
    protocol: form.protocol, source_cidrs: form.sources, enabled: rule.value ? rule.value.enabled : form.enabled,
  }
  if (isNew.value && isAdmin.value && form.owner_id) input.owner_id = form.owner_id
  try {
    const saved = await save.mutateAsync({ id: props.ruleId, input })
    baseline.value = snapshot()
    toast(isNew.value ? `已创建 ${saved.name}` : `已保存 ${saved.name}`)
    if (isNew.value) {
      initializedFor.value = `${saved.id}`
      await router.replace(`/rules/${saved.id}`)
    }
  } catch (error) {
    if (!isStaleError(error)) serverError.value = errorMessage(error)
  }
}

async function confirmRemoval() {
  if (!rule.value) return
  const target = rule.value
  try {
    await remove.mutateAsync(target)
    confirmDelete.value = false
    baseline.value = snapshot()
    toast(`已删除 ${target.name}`)
    emit('close')
  } catch (error) {
    confirmDelete.value = false
    if (!isStaleError(error)) toast('删除失败', { description: errorMessage(error), tone: 'danger' })
  }
}

function guard(action: () => void) {
  if (dirty.value) { pendingNavigation = action; confirmDiscard.value = true } else action()
}
function discard() {
  confirmDiscard.value = false
  baseline.value = snapshot()
  pendingNavigation?.()
  pendingNavigation = null
}
function requestClose() { guard(() => emit('close')) }
function onBeforeClose(event: Event) { if (dirty.value) { event.preventDefault(); requestClose() } }

const position = computed(() => (props.ruleId === null ? -1 : props.sequence.indexOf(props.ruleId)))
function step(delta: number) {
  const target = props.sequence[position.value + delta]
  if (target !== undefined) guard(() => router.replace(`/rules/${target}`))
}

const body = ref<HTMLElement | null>(null)
const { direction } = useSwipe(body, {
  threshold: 60,
  onSwipeEnd: () => {
    if (window.matchMedia('(min-width: 768px)').matches) return
    if (direction.value === 'left') step(1)
    else if (direction.value === 'right') step(-1)
  },
})
function onKeydown(event: KeyboardEvent) {
  const element = event.target as HTMLElement
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(element.tagName) || element.isContentEditable) return
  if (event.key === 'j') step(1)
  else if (event.key === 'k') step(-1)
}

const runtime = computed(() => {
  const value = rule.value
  if (!value) return null
  switch (value.runtime_status) {
    case 'active': return { title: '运行中', detail: value.runtime_updated_at ? `${relative(value.runtime_updated_at)}同步` : '' }
    case 'stopped': return { title: '已停用', detail: '' }
    case 'failed': return { title: '生效失败', detail: '该账户的转发已暂停' }
    default: return {
      title: '同步中',
      detail: props.health?.executor === 'offline' ? '执行器离线' : props.health?.executor === 'unconfigured' ? '执行器未连接' : '',
    }
  }
})
const resolvedNote = computed(() => (rule.value && rule.value.target_ip !== rule.value.target_host ? rule.value.target_ip : ''))
const protocolOptions = (['tcp', 'udp', 'both'] as Protocol[]).map(option => ({ value: option, label: protocolLabels[option] }))
const portRange = computed(() => (owner.value ? `${owner.value.port_start}–${owner.value.port_end}` : ''))

defineExpose({ dirty })
</script>

<template>
  <SideDrawer :open="open" :title="isNew ? '新建转发' : rule?.name ?? '转发'" :description="rule ? `ID ${rule.id} · ${rule.owner_username}` : undefined" width="lg" @close="requestClose" @before-close="onBeforeClose">

    <div ref="body" class="grid gap-6" @keydown="onKeydown">
      <p v-if="missing" class="py-8 text-center text-muted">转发不存在</p>
      <template v-else>
        <section v-if="rule && runtime" aria-label="运行状态" class="grid gap-1 border-b border-line pb-5">
          <div class="flex min-h-8 items-center gap-2">
            <StatusMark :status="rule.runtime_status" />
            <span class="font-medium" :class="rule.runtime_status === 'failed' ? 'text-danger' : 'text-fg'">{{ runtime.title }}</span>
            <span v-if="runtime.detail" class="text-sm text-muted">{{ runtime.detail }}</span>
            <button v-if="rule.runtime_status === 'failed'" type="button" class="btn btn-secondary btn-sm ml-auto" :disabled="retry.isPending.value" @click="retry.mutate(rule.owner_id)">
              <RotateCw class="size-3.5" :class="retry.isPending.value ? 'anim-spin' : ''" />重试
            </button>
          </div>
          <p v-if="rule.runtime_error" class="font-mono text-xs text-danger [overflow-wrap:anywhere]">{{ rule.runtime_error }}</p>
          <p v-if="rule.dns_error" class="text-xs text-warning [overflow-wrap:anywhere]">目标解析失败：{{ rule.dns_error }}</p>
        </section>

        <form id="rule-form" class="grid gap-5" novalidate @submit.prevent="submit">
          <label class="field">
            <span class="field-label">名称</span>
            <input v-model="form.name" class="input" maxlength="64" :aria-invalid="!!show('name')" autocomplete="off" />
            <span v-if="show('name')" class="field-error">{{ show('name') }}</span>
          </label>

          <label v-if="isNew && isAdmin" class="field">
            <span class="field-label">所属账户</span>
            <select class="input" :value="form.owner_id ?? ''" :aria-invalid="!!show('owner')" @change="changeOwner">
              <option v-if="!creatableOwners.length" value="" disabled>没有可用额度的账户</option>
              <option v-for="user in owners" :key="user.id" :value="user.id" :disabled="!canCreateFor(user)">
                {{ user.username }} · {{ user.port_start }}–{{ user.port_end }} · 已用 {{ user.rule_count }}/{{ user.max_rules }}
              </option>
            </select>
            <span v-if="show('owner')" class="field-error">{{ show('owner') }}</span>
          </label>

          <div class="field">
            <label class="field-label" for="rule-port">入口端口</label>
            <input id="rule-port" v-model.number="form.listen_port" class="input input-mono w-40" type="number" inputmode="numeric" :min="owner?.port_start" :max="owner?.port_end" :aria-invalid="!!show('port')" />
            <span v-if="show('port')" class="field-error">{{ show('port') }}</span>
            <span v-else-if="portRange" class="field-hint tabular">可用 {{ portRange }}</span>
            <div v-if="ports.data.value" class="mt-1.5">
              <PortRuler :usage="ports.data.value" :statuses="statuses" :selected="form.listen_port" :own-rule-id="ruleId" interactive @select="form.listen_port = $event" />
            </div>
            <div v-else-if="ports.isLoading.value" class="skeleton mt-1.5 h-10" />
          </div>

          <div class="field">
            <span id="rule-protocol" class="field-label">协议</span>
            <Segmented v-model="form.protocol" label="协议" :options="protocolOptions" aria-labelledby="rule-protocol" />
          </div>

          <div class="grid grid-cols-[minmax(0,1fr)_7rem] gap-3">
            <label class="field">
              <span class="field-label">落地地址</span>
              <input v-model="form.target_host" class="input input-mono" placeholder="公网 IP 或域名" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="253" :aria-invalid="!!show('host')" />
            </label>
            <label class="field">
              <span class="field-label">落地端口</span>
              <input v-model.number="form.target_port" class="input input-mono" type="number" inputmode="numeric" min="1" max="65535" :aria-invalid="!!show('targetPort')" />
            </label>
          </div>
          <p v-if="show('host') || show('targetPort')" class="field-error -mt-3">{{ show('host') || show('targetPort') }}</p>
          <p v-else-if="resolvedNote && !dirty" class="field-hint -mt-3">解析为 <span class="font-mono">{{ hostText(resolvedNote) }}</span></p>

          <div class="field">
            <span id="rule-sources" class="field-label">来源限制</span>
            <TagsInputRoot
              v-model="form.sources" :add-on-paste="true" :add-on-blur="true" :delimiter="/[\s,]+/" :max="32"
              class="flex min-h-[2.375rem] flex-wrap items-center gap-1.5 rounded-[10px] border border-line bg-surface px-2 py-1.5 transition-[border-color,box-shadow] hover:border-line-strong focus-within:!border-accent focus-within:shadow-[0_0_0_4px_var(--accent-soft)]"
              aria-labelledby="rule-sources"
            >
              <TagsInputItem
                v-for="item in form.sources" :key="item" :value="item"
                class="inline-flex h-6 items-center gap-1 rounded-md pl-2 font-mono text-xs"
                :class="validateCidr(item) ? 'bg-fill text-fg' : 'bg-danger-soft text-danger'"
              >
                <TagsInputItemText />
                <TagsInputItemDelete class="rounded p-0.5 pr-1 text-muted hover:text-fg" :aria-label="`移除 ${item}`"><X class="size-3" /></TagsInputItemDelete>
              </TagsInputItem>
              <TagsInputInput class="h-6 min-w-40 flex-1 bg-transparent font-mono text-sm outline-none max-md:text-base placeholder:font-sans placeholder:text-faint" :placeholder="form.sources.length ? '' : '不限，输入网段后回车'" />
            </TagsInputRoot>
            <span v-if="show('sources')" class="field-error">{{ show('sources') }}</span>
          </div>

          <div class="flex items-center justify-between gap-4">
            <span class="field-label">启用</span>
            <UiSwitch v-if="rule" :model-value="rule.enabled" label="启用转发" :disabled="toggle.isPending.value" @update:model-value="toggle.mutate({ rule, enabled: $event })" />
            <UiSwitch v-else v-model="form.enabled" label="启用转发" />
          </div>

          <p v-if="serverError" class="field-error" role="alert">{{ serverError }}</p>
        </form>

        <dl v-if="rule" class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 border-t border-line pt-5 text-sm">
          <dt class="text-muted">创建于</dt><dd class="tabular">{{ dateTime(rule.created_at) }}</dd>
          <dt class="text-muted">最后修改</dt><dd class="tabular">{{ dateTime(rule.updated_at) }}</dd>
        </dl>
      </template>
    </div>

    <template v-if="!missing" #footer>
      <button v-if="rule" type="button" class="btn btn-danger-ghost -ml-2" @click="confirmDelete = true"><Trash2 class="size-4" />删除</button>
      <span v-if="dirty" class="ml-auto text-xs text-muted max-sm:hidden">未保存</span>
      <button type="button" class="btn btn-secondary" :class="dirty ? '' : 'ml-auto'" @click="requestClose">取消</button>
      <button type="submit" form="rule-form" class="btn btn-primary" :disabled="save.isPending.value || (!isNew && !dirty)">
        {{ save.isPending.value ? '保存中…' : isNew ? '创建' : '保存' }}
      </button>
    </template>
  </SideDrawer>

  <ConfirmDialog
    :open="confirmDelete" danger :title="rule ? `删除 ${rule.name}？` : '删除转发？'" confirm-label="删除" description="删除后无法恢复。"
    :busy="remove.isPending.value" @confirm="confirmRemoval" @cancel="confirmDelete = false"
  />
  <ConfirmDialog :open="confirmDiscard" title="放弃修改？" confirm-label="放弃" danger @confirm="discard" @cancel="confirmDiscard = false" />
</template>
