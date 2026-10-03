<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ChevronRight, Plus, RotateCw, ShieldCheck, Users } from '@lucide/vue'
import AccountDrawer from '../components/AccountDrawer.vue'
import EmptyState from '../components/EmptyState.vue'
import { errorMessage } from '../api/client'
import type { User } from '../types'
import { useRules, useUsers } from '../lib/queries'
import { expiry } from '../lib/format'

const MAX_TENANTS = 10
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
  const info = expiry(user.expires_at)
  if (!user.enabled) return { text: '已停用', tone: 'text-faint' }
  if (info.tone === 'expired') return { text: '已到期', tone: 'text-danger' }
  if (info.tone === 'soon') return { text: info.text, tone: 'text-warning' }
  return { text: info.tone === 'none' ? '长期有效' : info.text, tone: 'text-muted' }
}
function quotaWidth(user: User) { return `${user.max_rules ? Math.min(100, (user.rule_count / user.max_rules) * 100) : 0}%` }

function open(user: User) { router.push(user.role === 'admin' ? '/settings' : `/accounts/${user.id}`) }
const drawerOpen = computed(() => route.name === 'account' || route.name === 'account-new')
const drawerUserId = computed(() => (route.name === 'account' ? Number(route.params.id) : null))
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-[-0.02em]">账户</h1>
        <p class="mt-1 text-muted tabular">{{ users.isLoading.value ? '正在读取…' : `${tenants.length} / ${MAX_TENANTS} 个租户` }}</p>
      </div>
      <RouterLink v-if="tenants.length < MAX_TENANTS" to="/accounts/new" class="btn btn-primary"><Plus class="size-4" />新建账户</RouterLink>
      <span v-else class="text-sm text-muted">已达到 {{ MAX_TENANTS }} 个租户上限</span>
    </div>

    <section class="mt-6" aria-label="账户列表">
      <div v-if="users.isLoading.value" class="panel divide-y divide-line">
        <div v-for="index in 4" :key="index" class="flex items-center gap-4 px-4 py-4"><span class="skeleton size-8 rounded-full" /><span class="skeleton h-4 w-32" /><span class="skeleton ml-auto h-4 w-24" /></div>
      </div>
      <div v-else-if="users.isError.value" class="panel px-6 py-10 text-center">
        <p class="font-medium">没能读取账户</p>
        <p class="mt-1 text-muted">{{ errorMessage(users.error.value) }}</p>
        <button type="button" class="btn btn-secondary mt-4" @click="users.refetch()"><RotateCw class="size-4" />重试</button>
      </div>
      <div v-else class="panel overflow-hidden">
        <div class="grid grid-cols-[minmax(10rem,1.3fr)_minmax(8rem,1fr)_minmax(9rem,1fr)_minmax(8rem,1fr)_minmax(7rem,0.8fr)_1rem] items-center gap-x-4 border-b border-line bg-surface-2/60 px-4 py-2 text-xs font-medium text-muted max-md:hidden">
          <span>账户</span><span>端口段</span><span>规则额度</span><span>有效期</span><span>运行</span><span />
        </div>
        <ul class="divide-y divide-line">
          <li v-for="user in list" :key="user.id">
            <button
              type="button" class="grid w-full items-center gap-x-4 px-4 py-3 text-left transition-colors duration-150 hover:bg-surface-2/60 md:grid-cols-[minmax(10rem,1.3fr)_minmax(8rem,1fr)_minmax(9rem,1fr)_minmax(8rem,1fr)_minmax(7rem,0.8fr)_1rem] max-md:grid-cols-[minmax(0,1fr)_auto] max-md:gap-y-1.5"
              :aria-label="user.role === 'admin' ? `${user.username}（管理员），打开设置` : `编辑 ${user.username}`" @click="open(user)"
            >
              <span class="flex min-w-0 items-center gap-3">
                <span class="flex size-8 shrink-0 items-center justify-center rounded-full border border-line bg-surface-2 text-xs font-semibold">{{ user.username.slice(0, 2).toUpperCase() }}</span>
                <span class="min-w-0">
                  <span class="flex items-center gap-1.5">
                    <span class="truncate font-medium">{{ user.username }}</span>
                    <ShieldCheck v-if="user.mfa_enabled" class="size-3.5 text-accent" aria-label="已开双因素" role="img" />
                  </span>
                  <span class="block text-xs text-muted">{{ user.role === 'admin' ? '管理员' : user.must_change_password ? '租户 · 待修改初始密码' : '租户' }}</span>
                </span>
              </span>
              <span class="font-mono text-sm tabular max-md:col-start-1 max-md:row-start-2 max-md:pl-11">{{ user.port_start }}–{{ user.port_end }}</span>
              <span class="flex items-center gap-2.5 max-md:hidden">
                <span class="h-1.5 w-16 overflow-hidden rounded-full bg-surface-3" aria-hidden="true"><span class="block h-full rounded-full" :class="user.rule_count >= user.max_rules && user.max_rules > 0 ? 'bg-warning' : 'bg-fg'" :style="{ width: quotaWidth(user) }" /></span>
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
          <EmptyState title="还没有租户" description="新建账户后，对方就能在分配的端口段里自助管理转发。">
            <template #icon><Users class="size-5" /></template>
            <RouterLink to="/accounts/new" class="btn btn-primary"><Plus class="size-4" />新建账户</RouterLink>
          </EmptyState>
        </div>
      </div>
    </section>

    <AccountDrawer :open="drawerOpen" :user-id="drawerUserId" :users="users.data.value ?? []" :rules="rules.data.value ?? []" :loaded="users.isSuccess.value" @close="router.push('/accounts')" />
  </div>
</template>
