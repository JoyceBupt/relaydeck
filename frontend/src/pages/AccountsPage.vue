<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ChevronRight, Plus, RotateCw, ShieldCheck, Users } from '@lucide/vue'
import AccountDrawer from '../components/AccountDrawer.vue'
import EmptyState from '../components/EmptyState.vue'
import { errorMessage } from '../api/client'
import type { User } from '../types'
import { useRules, useUsers } from '../lib/queries'
import { expiry, MAX_TENANTS } from '../lib/format'

const route = useRoute()
const router = useRouter()
const users = useUsers()
const rules = useRules()

const list = computed(() => [...(users.data.value ?? [])].sort((a, b) => (a.role === b.role ? a.id - b.id : a.role === 'admin' ? -1 : 1)))
const tenants = computed(() => list.value.filter(user => user.role === 'user'))
const failedBy = computed(() => {
  const map = new Map<number, number>()
  for (const rule of rules.data.value ?? []) if (rule.runtime_status === 'failed') map.set(rule.owner_id, (map.get(rule.owner_id) ?? 0) + 1)
  return map
})

function state(user: User) {
  if (user.deletion_requested_at != null) return { text: user.deletion_error ? '删除待重试' : '删除中', tone: 'text-warning' }
  const info = expiry(user.expires_at)
  if (!user.enabled) return { text: '已停用', tone: 'text-faint' }
  if (info.tone === 'expired') return { text: '已到期', tone: 'text-danger' }
  if (info.tone === 'soon') return { text: info.text, tone: 'text-warning' }
  return { text: info.tone === 'none' ? '长期有效' : info.text, tone: 'text-muted' }
}
function quotaWidth(user: User) { return `${user.max_rules ? Math.min(100, (user.rule_count / user.max_rules) * 100) : 0}%` }

function open(user: User) { router.push(`/accounts/${user.id}`) }
const drawerOpen = computed(() => route.name === 'account' || route.name === 'account-new')
const drawerUserId = computed(() => (route.name === 'account' ? Number(route.params.id) : null))
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="page-title">账户</h1>
        <p class="mt-1 text-muted tabular">{{ users.isLoading.value ? '' : `${tenants.length} / ${MAX_TENANTS} 个租户` }}</p>
      </div>
      <RouterLink v-if="tenants.length < MAX_TENANTS" to="/accounts/new" class="btn btn-primary"><Plus class="size-4" />新建账户</RouterLink>
      <span v-else class="text-sm text-muted">租户已满</span>
    </div>

    <section class="mt-6" aria-label="账户列表">
      <div v-if="users.isLoading.value" class="panel group-list">
        <div v-for="index in 4" :key="index" class="flex items-center gap-4 px-4 py-4"><span class="skeleton size-8 rounded-full" /><span class="skeleton h-4 w-32" /><span class="skeleton ml-auto h-4 w-24" /></div>
      </div>
      <div v-else-if="users.isError.value" class="panel px-6 py-10 text-center">
        <p class="font-medium">读取失败</p>
        <p class="mt-1 text-muted">{{ errorMessage(users.error.value) }}</p>
        <button type="button" class="btn btn-secondary mt-4" @click="users.refetch()"><RotateCw class="size-4" />重试</button>
      </div>
      <div v-else class="panel overflow-hidden">
        <div class="grid grid-cols-[minmax(10rem,1.3fr)_minmax(9rem,1fr)_minmax(8rem,1fr)_minmax(7rem,0.8fr)_1rem] items-center gap-x-4 border-b border-line px-4 pt-3 pb-2 text-xs text-muted max-md:hidden">
          <span>账户</span><span>端口额度</span><span>有效期</span><span>运行</span><span />
        </div>
        <ul class="group-list">
          <li v-for="user in list" :key="user.id">
            <button
              type="button" class="grid w-full items-center gap-x-4 px-4 py-3 text-left transition-colors duration-150 hover:bg-fill/60 md:grid-cols-[minmax(10rem,1.3fr)_minmax(9rem,1fr)_minmax(8rem,1fr)_minmax(7rem,0.8fr)_1rem] max-md:grid-cols-[minmax(0,1fr)_auto] max-md:gap-y-1.5"
              :aria-label="`编辑 ${user.username}`" @click="open(user)"
            >
              <span class="flex min-w-0 items-center gap-3">
                <span class="flex size-8 shrink-0 items-center justify-center rounded-full bg-accent-soft text-xs font-semibold text-accent">{{ user.username.slice(0, 2).toUpperCase() }}</span>
                <span class="min-w-0">
                  <span class="flex items-center gap-1.5">
                    <span class="truncate font-medium">{{ user.username }}</span>
                    <ShieldCheck v-if="user.mfa_enabled" class="size-3.5 text-accent" aria-label="已开启两步验证" role="img" />
                  </span>
                  <span class="block text-xs text-muted">{{ user.role === 'admin' ? '管理员' : user.must_change_password ? '租户 · 未改初始密码' : '租户' }}</span>
                </span>
              </span>
              <span class="flex items-center gap-2.5 max-md:col-start-1 max-md:row-start-2 max-md:pl-11">
                <span class="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3" aria-hidden="true"><span class="block h-full rounded-full" :class="user.rule_count >= user.max_rules && user.max_rules > 0 ? 'bg-[var(--meter-warn)]' : 'bg-accent'" :style="{ width: quotaWidth(user) }" /></span>
                <span class="text-sm tabular">{{ user.rule_count }} / {{ user.max_rules }}</span>
              </span>
              <span class="text-sm max-md:col-start-2 max-md:row-start-1 max-md:text-right" :class="state(user).tone">{{ state(user).text }}</span>
              <span class="text-sm max-md:hidden">
                <span v-if="failedBy.get(user.id)" class="font-medium text-danger">{{ failedBy.get(user.id) }} 条失败</span>
                <span v-else class="text-muted">{{ user.rule_count ? '正常' : '—' }}</span>
              </span>
              <ChevronRight class="size-4 text-faint max-md:hidden" aria-hidden="true" />
            </button>
          </li>
        </ul>
        <div v-if="!tenants.length" class="border-t border-line">
          <EmptyState title="暂无租户">
            <template #icon><Users class="size-5" /></template>
            <RouterLink to="/accounts/new" class="btn btn-primary"><Plus class="size-4" />新建账户</RouterLink>
          </EmptyState>
        </div>
      </div>
    </section>

    <AccountDrawer :open="drawerOpen" :user-id="drawerUserId" :users="users.data.value ?? []" :rules="rules.data.value ?? []" :loaded="users.isSuccess.value" @close="router.push('/accounts')" />
  </div>
</template>
