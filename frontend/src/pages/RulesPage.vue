<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useEventListener } from '@vueuse/core'
import { DropdownMenuContent, DropdownMenuItem, DropdownMenuPortal, DropdownMenuRoot, DropdownMenuSeparator, DropdownMenuTrigger } from 'reka-ui'
import { ArrowRightLeft, Copy, Ellipsis, Plus, RotateCw, Search, Trash2, X } from '@lucide/vue'
import StatusMark from '../components/StatusMark.vue'
import RuleEndpoint from '../components/RuleEndpoint.vue'
import Segmented from '../components/Segmented.vue'
import UiSwitch from '../components/UiSwitch.vue'
import EmptyState from '../components/EmptyState.vue'
import RuleDrawer from '../components/RuleDrawer.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import { api, ruleInput } from '../api/endpoints'
import { errorMessage, isStaleError } from '../api/client'
import type { Rule, RuntimeStatus, ViewMode } from '../types'
import { acceptSession, currentUser, isAdmin, sessionState } from '../lib/session'
import { afterRuleChange, reportError, sharedToggle, useHealth, useRules, useUsers } from '../lib/queries'
import { hostText, protocolLabels, sourcesText, statusLabels } from '../lib/format'
import { toast } from '../lib/toast'

const route = useRoute()
const router = useRouter()
const rules = useRules()
const users = useUsers()
const health = useHealth()
const toggle = sharedToggle()

type Filter = 'all' | RuntimeStatus
const filter = computed<Filter>({
  get: () => (['active', 'pending', 'failed', 'blocked', 'stopped'].includes(String(route.query.status)) ? route.query.status as Filter : 'all'),
  set: value => router.replace({ query: { ...route.query, status: value === 'all' ? undefined : value } }),
})
const ownerFilter = computed<number | null>({
  get: () => (route.query.owner ? Number(route.query.owner) || null : null),
  set: value => router.replace({ query: { ...route.query, owner: value ? String(value) : undefined } }),
})
const search = ref(typeof route.query.q === 'string' ? route.query.q : '')
watch(search, value => router.replace({ query: { ...route.query, q: value.trim() || undefined } }))

const all = computed(() => rules.data.value ?? [])
const scoped = computed(() => all.value.filter(rule => ownerFilter.value === null || rule.owner_id === ownerFilter.value))
const searched = computed(() => {
  const needle = search.value.trim().toLowerCase()
  return needle ? scoped.value.filter(rule => `${rule.name} ${rule.listen_port} ${rule.target_host} ${rule.target_port} ${rule.owner_username}`.toLowerCase().includes(needle)) : scoped.value
})
const visible = computed(() => searched.value.filter(rule => filter.value === 'all' || rule.runtime_status === filter.value))
const counts = computed(() => {
  const result: Record<Filter, number> = { all: searched.value.length, active: 0, pending: 0, failed: 0, blocked: 0, stopped: 0 }
  for (const rule of searched.value) result[rule.runtime_status]++
  return result
})
const filterOptions = computed(() => (['all', 'active', 'pending', 'failed', 'blocked', 'stopped'] as Filter[]).map(value => ({
  value, label: value === 'all' ? '全部' : statusLabels[value], count: counts.value[value],
})))
const ownerOptions = computed(() => (users.data.value ?? []).filter(user => all.value.some(rule => rule.owner_id === user.id) || user.id === ownerFilter.value))
const filtering = computed(() => filter.value !== 'all' || ownerFilter.value !== null || search.value.trim() !== '')
function clearFilters() { search.value = ''; router.replace({ query: {} }) }

const viewMode = computed(() => currentUser.value?.view_mode ?? 'table')
const savingView = ref(false)
async function setView(mode: ViewMode) {
  if (mode === viewMode.value || savingView.value || !sessionState.session) return
  savingView.value = true
  const previous = sessionState.session
  const epoch = sessionState.epoch
  acceptSession({ ...previous, user: { ...previous.user, view_mode: mode } })
  try { await api.setPreference(mode) } catch (error) {
    if (epoch === sessionState.epoch && sessionState.session) acceptSession({ ...sessionState.session, user: { ...sessionState.session.user, view_mode: previous.user.view_mode } })
    reportError(error, '保存失败')
  } finally { savingView.value = false }
}

const subtitle = computed(() => {
  const user = currentUser.value
  if (!user) return ''
  if (isAdmin.value) {
    const owners = new Set(all.value.map(rule => rule.owner_id)).size
    return `${all.value.length} 条 · ${owners} 个账户`
  }
  return `${user.port_start}–${user.port_end} · ${user.rule_count} / ${user.max_rules} 条`
})

// Drawer state lives in the URL so a rule can be linked, refreshed and navigated with Back.
const drawerOpen = computed(() => route.name === 'rule' || route.name === 'rule-new')
const drawerRuleId = computed(() => (route.name === 'rule' ? Number(route.params.id) : null))
const presetPort = computed(() => (route.query.port ? Number(route.query.port) || null : null))
const presetOwner = computed(() => (route.query.owner ? Number(route.query.owner) || null : null))
function closeDrawer() { router.push({ path: '/rules', query: { ...route.query, port: undefined, from: undefined } }) }
function openRule(rule: Rule) { router.push({ path: `/rules/${rule.id}`, query: route.query }) }
function newRule() { router.push({ path: '/rules/new', query: { ...route.query, from: undefined } }) }
function duplicate(rule: Rule) { router.push({ path: '/rules/new', query: { ...route.query, owner: String(rule.owner_id), from: String(rule.id) } }) }

const selected = ref<Set<number>>(new Set())
watch(visible, list => { const ids = new Set(list.map(rule => rule.id)); selected.value = new Set([...selected.value].filter(id => ids.has(id))) })
const allSelected = computed(() => visible.value.length > 0 && visible.value.every(rule => selected.value.has(rule.id)))
function toggleSelected(id: number) { const next = new Set(selected.value); if (next.has(id)) next.delete(id); else next.add(id); selected.value = next }
function toggleAll() { selected.value = allSelected.value ? new Set() : new Set(visible.value.map(rule => rule.id)) }

const bulkBusy = ref(false)
const confirmBulkDelete = ref(false)
async function bulk(action: 'enable' | 'disable' | 'delete') {
  const epoch = sessionState.epoch
  const targets = all.value.filter(rule => selected.value.has(rule.id) && (action === 'delete' || rule.enabled !== (action === 'enable')))
  if (!targets.length) { selected.value = new Set(); return }
  bulkBusy.value = true
  let done = 0
  try {
    for (const rule of targets) {
      if (epoch !== sessionState.epoch) return
      if (action === 'delete') await api.deleteRule(rule.id)
      else await api.updateRule(rule.id, ruleInput(rule, { enabled: action === 'enable' }))
      done++
    }
    toast(`已${action === 'delete' ? '删除' : action === 'enable' ? '启用' : '停用'} ${done} 条`)
    selected.value = new Set()
  } catch (error) {
    if (!isStaleError(error)) toast(`已处理 ${done} 条，其余失败`, { description: errorMessage(error), tone: 'danger' })
  } finally {
    bulkBusy.value = false
    confirmBulkDelete.value = false
    if (epoch === sessionState.epoch) await afterRuleChange()
  }
}

const deleting = ref<Rule | null>(null)
const deleteBusy = ref(false)
async function confirmDelete() {
  const target = deleting.value
  if (!target) return
  deleteBusy.value = true
  try {
    await api.deleteRule(target.id)
    toast(`已删除 ${target.name}`)
    deleting.value = null
  } catch (error) { reportError(error, '删除失败') } finally { deleteBusy.value = false; await afterRuleChange() }
}

const cardTone: Record<RuntimeStatus, string> = { active: 'chip-green', pending: 'chip-amber', failed: 'chip-red', blocked: 'chip-red', stopped: '' }

const searchInput = ref<HTMLInputElement | null>(null)
useEventListener(window, 'relaydeck:focus-search', () => searchInput.value?.focus())
onMounted(async () => {
  if (route.query.focus) { await nextTick(); searchInput.value?.focus(); router.replace({ query: { ...route.query, focus: undefined } }) }
})

const cloneSource = computed(() => (route.name === 'rule-new' && route.query.from ? all.value.find(rule => rule.id === Number(route.query.from)) ?? null : null))
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div class="min-w-0">
        <h1 class="page-title">转发</h1>
        <p class="mt-1 text-muted tabular">{{ rules.isLoading.value ? '正在读取…' : subtitle }}</p>
      </div>
      <button type="button" class="btn btn-primary" @click="newRule">
        <Plus class="size-4" />新建转发
      </button>
    </div>

    <div class="mt-6 flex flex-wrap items-center gap-2">
      <Segmented v-model="filter" label="按运行状态筛选" :options="filterOptions" />
      <select v-if="isAdmin && ownerOptions.length > 1" class="input h-9 w-auto max-w-44 pr-8" aria-label="按账户筛选" :value="ownerFilter ?? ''" @change="ownerFilter = Number(($event.target as HTMLSelectElement).value) || null">
        <option value="">全部账户</option>
        <option v-for="user in ownerOptions" :key="user.id" :value="user.id">{{ user.username }}</option>
      </select>
      <label class="relative ml-auto w-full sm:w-64">
        <span class="sr-only">搜索转发</span>
        <Search class="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-faint" aria-hidden="true" />
        <input ref="searchInput" v-model="search" type="search" class="input pl-9" placeholder="搜索" @keydown.esc="search = ''; ($event.target as HTMLInputElement).blur()" />
      </label>
      <Segmented :model-value="viewMode" label="显示方式" size="sm" :disabled="savingView" :options="[{ value: 'table', label: '列表' }, { value: 'cards', label: '卡片' }]" class="max-md:hidden" @update:model-value="setView($event as ViewMode)" />
    </div>

    <section class="mt-4" aria-label="转发列表">
      <div v-if="rules.isLoading.value" class="panel group-list overflow-hidden" aria-busy="true">
        <div v-for="index in 5" :key="index" class="flex items-center gap-4 px-4 py-4"><span class="skeleton size-3.5 rounded-full" /><span class="skeleton h-4 w-40" /><span class="skeleton h-4 w-56 max-md:hidden" /><span class="skeleton ml-auto h-5 w-9 rounded-full" /></div>
      </div>

      <div v-else-if="rules.isError.value" class="panel px-6 py-10 text-center">
        <p class="font-medium">读取失败</p>
        <p class="mt-1 text-muted">{{ errorMessage(rules.error.value) }}</p>
        <button type="button" class="btn btn-secondary mt-4" @click="rules.refetch()"><RotateCw class="size-4" />重试</button>
      </div>

      <div v-else-if="!all.length" class="panel">
        <EmptyState title="暂无转发">
          <template #icon><ArrowRightLeft class="size-5" /></template>
          <button type="button" class="btn btn-primary" @click="newRule"><Plus class="size-4" />新建转发</button>
        </EmptyState>
      </div>

      <div v-else-if="!visible.length" class="panel">
        <EmptyState title="无匹配结果">
          <button type="button" class="btn btn-secondary" @click="clearFilters"><X class="size-4" />清除筛选</button>
        </EmptyState>
      </div>

      <div v-else-if="viewMode === 'cards'" class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <article v-for="rule in visible" :key="rule.id" class="panel flex min-w-0 flex-col gap-3 p-4 transition-colors duration-200 hover:border-line-strong">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <RouterLink :to="{ path: `/rules/${rule.id}`, query: route.query }" class="block truncate text-base font-semibold hover:text-accent">{{ rule.name }}</RouterLink>
              <div class="mt-1.5 flex flex-wrap gap-1.5">
                <span class="chip" :class="cardTone[rule.runtime_status]"><StatusMark :status="rule.runtime_status" />{{ statusLabels[rule.runtime_status] }}</span>
                <span class="chip chip-blue">{{ protocolLabels[rule.protocol] }}</span>
                <span v-if="isAdmin" class="chip chip-violet">{{ rule.owner_username }}</span>
              </div>
            </div>
            <UiSwitch :model-value="rule.enabled" :label="`${rule.enabled ? '停用' : '启用'}「${rule.name}」`" :disabled="toggle.isPending.value" @update:model-value="toggle.mutate({ rule, enabled: $event })" />
          </div>
          <dl class="well grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 px-3 py-2.5 text-sm">
            <dt class="text-muted">入口</dt><dd class="font-medium tabular">{{ rule.listen_port }}</dd>
            <dt class="text-muted">落地</dt><dd class="truncate tabular" :title="rule.target_ip !== rule.target_host ? rule.target_ip : undefined">{{ hostText(rule.target_host) }}:{{ rule.target_port }}</dd>
            <dt class="text-muted">来源</dt><dd class="truncate">{{ sourcesText(rule.source_cidrs) }}</dd>
          </dl>
          <p v-if="rule.runtime_error" class="line-clamp-2 font-mono text-xs text-danger">{{ rule.runtime_error }}</p>
          <p v-else-if="rule.dns_error" class="line-clamp-2 text-xs text-warning">目标解析失败：{{ rule.dns_error }}</p>
        </article>
      </div>

      <div v-else class="panel overflow-hidden">
        <div class="grid grid-cols-[1.25rem_minmax(9rem,1.1fr)_minmax(13rem,1.6fr)_6rem_minmax(7rem,1fr)_2.25rem_2rem] items-center gap-x-4 border-b border-line px-4 pt-3 pb-2 text-xs text-muted max-md:hidden">
          <input type="checkbox" class="size-4 accent-[var(--accent)]" :checked="allSelected" :indeterminate="selected.size > 0 && !allSelected" aria-label="全选当前列表" @change="toggleAll" />
          <span>名称</span><span>入口 → 落地</span><span>协议</span><span>来源</span><span class="sr-only">启用</span><span class="sr-only">操作</span>
        </div>
        <ul class="group-list">
          <li
            v-for="rule in visible" :key="rule.id"
            class="group relative grid cursor-pointer items-center gap-x-4 px-4 py-3 transition-colors duration-150 hover:bg-fill/60 md:grid-cols-[1.25rem_minmax(9rem,1.1fr)_minmax(13rem,1.6fr)_6rem_minmax(7rem,1fr)_2.25rem_2rem] max-md:grid-cols-[minmax(0,1fr)_auto] max-md:gap-y-1"
            :class="selected.has(rule.id) ? 'bg-accent-soft/50' : ''" @click="openRule(rule)"
          >
            <input type="checkbox" class="size-4 accent-[var(--accent)] max-md:hidden" :checked="selected.has(rule.id)" :aria-label="`选择「${rule.name}」`" @click.stop @change="toggleSelected(rule.id)" />
            <div class="flex min-w-0 items-center gap-2.5">
              <StatusMark :status="rule.runtime_status" />
              <div class="min-w-0">
                <RouterLink :to="{ path: `/rules/${rule.id}`, query: route.query }" class="block truncate font-medium text-fg" @click.stop>{{ rule.name }}</RouterLink>
                <p class="truncate text-xs" :class="rule.runtime_error ? 'text-danger' : rule.dns_error ? 'text-warning' : 'text-muted'">
                  <template v-if="rule.runtime_status === 'failed'">失败{{ rule.runtime_error ? `：${rule.runtime_error}` : '' }}</template>
                  <template v-else-if="rule.runtime_status === 'blocked'">已阻断{{ rule.dns_error ? `：${rule.dns_error}` : '' }}</template>
                  <template v-else-if="rule.dns_error">{{ rule.enabled ? '解析失败' : '解析失败，已停用' }}{{ isAdmin ? ` · ${rule.owner_username}` : '' }}</template>
                  <template v-else>{{ statusLabels[rule.runtime_status] }}{{ isAdmin ? ` · ${rule.owner_username}` : '' }}</template>
                </p>
              </div>
            </div>
            <RuleEndpoint class="min-w-0 max-md:col-start-1 max-md:row-start-2 max-md:pl-6" :port="rule.listen_port" :host="rule.target_host" :target-port="rule.target_port" :resolved="rule.target_ip" />
            <span class="text-sm text-muted max-md:hidden">{{ protocolLabels[rule.protocol] }}</span>
            <span class="truncate text-sm text-muted max-md:hidden" :title="rule.source_cidrs.join('\n') || undefined">{{ sourcesText(rule.source_cidrs) }}</span>
            <div class="flex justify-end max-md:col-start-2 max-md:row-start-1" @click.stop>
              <UiSwitch :model-value="rule.enabled" :label="`${rule.enabled ? '停用' : '启用'}「${rule.name}」`" :disabled="toggle.isPending.value" @update:model-value="toggle.mutate({ rule, enabled: $event })" />
            </div>
            <div class="flex justify-end max-md:hidden" @click.stop>
              <DropdownMenuRoot>
                <DropdownMenuTrigger class="btn btn-ghost btn-sm btn-icon opacity-70 group-hover:opacity-100 data-[state=open]:opacity-100" :aria-label="`「${rule.name}」的更多操作`"><Ellipsis class="size-4" /></DropdownMenuTrigger>
                <DropdownMenuPortal>
                  <DropdownMenuContent align="end" :side-offset="4" class="anim-pop pop">
                    <DropdownMenuItem class="pop-item" @select="duplicate(rule)"><Copy class="size-4 text-muted" />复制为新转发</DropdownMenuItem>
                    <DropdownMenuSeparator class="pop-sep" />
                    <DropdownMenuItem class="pop-item is-danger" @select="deleting = rule"><Trash2 class="size-4" />删除</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenuPortal>
              </DropdownMenuRoot>
            </div>
          </li>
        </ul>
      </div>
    </section>

    <Transition enter-from-class="opacity-0 translate-y-2" leave-to-class="opacity-0 translate-y-2" enter-active-class="transition duration-200 ease-[var(--ease-out)]" leave-active-class="transition duration-150">
      <div v-if="selected.size" class="pop fixed bottom-[calc(1rem+env(safe-area-inset-bottom))] left-1/2 z-30 flex -translate-x-1/2 items-center gap-1 !p-1.5 max-md:hidden" role="toolbar" aria-label="批量操作">
        <span class="px-2 text-sm font-medium tabular">已选 {{ selected.size }} 条</span>
        <button type="button" class="btn btn-ghost btn-sm" :disabled="bulkBusy" @click="bulk('enable')">启用</button>
        <button type="button" class="btn btn-ghost btn-sm" :disabled="bulkBusy" @click="bulk('disable')">停用</button>
        <button type="button" class="btn btn-danger-ghost btn-sm" :disabled="bulkBusy" @click="confirmBulkDelete = true">删除</button>
        <span class="mx-1 h-5 w-px bg-line" />
        <button type="button" class="btn btn-ghost btn-sm btn-icon" aria-label="取消选择" @click="selected = new Set()"><X class="size-4" /></button>
      </div>
    </Transition>

    <RuleDrawer
      :open="drawerOpen" :rule-id="drawerRuleId" :rules="all" :loaded="rules.isSuccess.value"
      :users="users.data.value ?? []" :health="health.data.value" :sequence="visible.map(rule => rule.id)"
      :preset-port="presetPort" :preset-owner="presetOwner" :clone="cloneSource" @close="closeDrawer"
    />
    <ConfirmDialog
      :open="!!deleting" danger :title="deleting ? `删除 ${deleting.name}？` : '删除转发？'" confirm-label="删除" :busy="deleteBusy" description="删除后无法恢复。"
      @confirm="confirmDelete" @cancel="deleting = null"
    />
    <ConfirmDialog
      :open="confirmBulkDelete" danger :title="`删除 ${selected.size} 条转发？`" confirm-label="删除" :busy="bulkBusy"
      description="删除后无法恢复。" @confirm="bulk('delete')" @cancel="confirmBulkDelete = false"
    />
  </div>
</template>
