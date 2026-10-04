<script setup lang="ts">
import { computed } from 'vue'
import { ArrowRight, Clock, Gauge, Plus, RotateCw, ServerOff } from '@lucide/vue'
import StatusMark from '../components/StatusMark.vue'
import RelayTopology from '../components/RelayTopology.vue'
import PortRuler from '../components/PortRuler.vue'
import type { RuntimeStatus } from '../types'
import { currentUser, isAdmin } from '../lib/session'
import { useAudit, useHealth, usePorts, useRetry, useRules, useUsers } from '../lib/queries'
import { expiry, MAX_TENANTS, relative, statusLabels } from '../lib/format'
import { describeAudit } from '../lib/audit'

const rules = useRules()
const users = useUsers()
const health = useHealth()
const audit = useAudit()
const retry = useRetry()
const ports = usePorts(computed(() => (isAdmin.value ? null : currentUser.value?.id)))

const all = computed(() => rules.data.value ?? [])
const statusOrder: RuntimeStatus[] = ['active', 'pending', 'failed', 'blocked', 'stopped']
const counts = computed(() => statusOrder.map(status => ({ status, count: all.value.filter(rule => rule.runtime_status === status).length })))
const statuses = computed(() => Object.fromEntries(all.value.map(rule => [rule.id, { name: rule.name, status: rule.runtime_status }])))

const failedOwners = computed(() => {
  const map = new Map<number, { owner: string; ownerId: number; rules: typeof all.value }>()
  for (const rule of all.value) if (rule.runtime_status === 'failed') {
    const entry = map.get(rule.owner_id) ?? { owner: rule.owner_username, ownerId: rule.owner_id, rules: [] }
    entry.rules.push(rule)
    map.set(rule.owner_id, entry)
  }
  return [...map.values()]
})
const expiring = computed(() => (users.data.value ?? []).filter(user => user.role === 'user' && user.enabled && ['soon', 'expired'].includes(expiry(user.expires_at).tone)))
const full = computed(() => (users.data.value ?? []).filter(user => user.role === 'user' && user.enabled && user.max_rules > 0 && user.rule_count >= user.max_rules))
const executor = computed(() => health.data.value?.executor)
const attentionCount = computed(() => failedOwners.value.length + (isAdmin.value ? expiring.value.length + full.value.length : 0) + (executor.value && executor.value !== 'running' ? 1 : 0))
const tenants = computed(() => (users.data.value ?? []).filter(user => user.role === 'user'))
function tenantTone(index: number) {
  const user = tenants.value[index]
  if (!user) return ''
  if (!user.enabled || expiry(user.expires_at).tone === 'expired') return 'is-bad'
  return expiry(user.expires_at).tone === 'soon' ? 'is-warn' : 'is-on'
}
const myExpiry = computed(() => (currentUser.value ? expiry(currentUser.value.expires_at) : null))
const recent = computed(() => (audit.data.value ?? []).slice(0, 5).map(entry => ({ entry, ...describeAudit(entry) })))
</script>

<template>
  <div class="grid grid-cols-[minmax(0,1fr)] gap-8">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <h1 class="page-title">总览</h1>
      <RouterLink to="/rules/new" class="btn btn-primary"><Plus class="size-4" />新建转发</RouterLink>
    </div>

    <div class="grid grid-cols-[minmax(0,1fr)] gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
      <section class="panel p-4 md:p-5" aria-labelledby="topology-title">
        <div class="mb-4 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <h2 id="topology-title" class="flex items-baseline gap-2">
            <span class="stat-label">转发</span>
            <span v-if="rules.isLoading.value" class="skeleton inline-block h-7 w-16 align-middle" />
            <span v-else-if="rules.data.value"><span class="stat-value">{{ counts[0].count }}</span><span class="stat-unit">/ {{ all.length }} 运行中</span></span>
          </h2>
          <span v-if="rules.data.value" class="flex flex-wrap gap-x-3 text-xs text-muted">
            <template v-for="item in counts.slice(1)" :key="item.status">
              <RouterLink v-if="item.count" :to="{ path: '/rules', query: { status: item.status } }" class="tabular hover:text-fg">{{ statusLabels[item.status] }} <span class="font-medium" :class="['failed', 'blocked'].includes(item.status) ? 'text-danger' : 'text-fg'">{{ item.count }}</span></RouterLink>
            </template>
          </span>
        </div>
        <div v-if="rules.isLoading.value" class="grid gap-2"><div v-for="index in 4" :key="index" class="skeleton h-6" /></div>
        <p v-if="rules.isError.value" class="flex items-center justify-between gap-3 py-3 text-sm text-danger">转发加载失败<button type="button" class="btn btn-secondary btn-sm" :disabled="rules.isFetching.value" @click="rules.refetch()">重试</button></p>
        <RelayTopology v-if="rules.data.value" :rules="all" :admin="isAdmin" />
      </section>

      <div class="grid content-start gap-3">
        <RouterLink v-if="isAdmin" to="/accounts" class="panel flex flex-col gap-3 p-4 transition-colors duration-200 hover:border-line-strong">
          <span class="stat-label">租户</span>
          <span v-if="users.isLoading.value" class="skeleton h-9 w-20" />
          <span v-else-if="users.data.value"><span class="stat-value">{{ tenants.length }}</span><span class="stat-unit">/ {{ MAX_TENANTS }} 个</span></span>
          <span v-else class="text-sm text-danger">账户加载失败</span>
          <span class="meter" aria-hidden="true">
            <span v-for="index in MAX_TENANTS" :key="index" :class="tenantTone(index - 1)" />
          </span>
          <span v-if="expiring.length" class="text-xs text-warning">{{ expiring.length }} 个即将到期</span>
        </RouterLink>
        <section v-if="isAdmin" class="panel p-4" aria-labelledby="activity-title">
          <div class="mb-2 flex items-center justify-between">
            <h2 id="activity-title" class="stat-label">最近操作</h2>
            <RouterLink to="/audit" class="flex items-center gap-0.5 text-xs text-accent hover:opacity-80">审计<ArrowRight class="size-3" /></RouterLink>
          </div>
          <ol v-if="recent.length" class="grid gap-2.5">
            <li v-for="item in recent" :key="item.entry.id" class="text-sm">
              <p class="truncate"><span class="font-medium">{{ item.entry.actor_username }}</span><span class="mx-1 text-muted">{{ item.verb }}</span><span v-if="item.object" class="font-medium">{{ item.object.name }}</span></p>
              <p class="text-xs text-faint">{{ relative(item.entry.created_at) }}</p>
            </li>
          </ol>
          <div v-else-if="audit.isLoading.value" class="grid gap-2"><span v-for="index in 3" :key="index" class="skeleton h-6" /></div>
          <p v-else-if="audit.isError.value" class="py-4 text-center text-sm text-danger">审计加载失败</p>
          <p v-else class="py-4 text-center text-sm text-muted">暂无记录</p>
        </section>
        <template v-else>
          <div class="panel flex flex-col gap-3 p-4">
            <span class="stat-label">端口额度</span>
            <span><span class="stat-value">{{ currentUser?.rule_count ?? 0 }}</span><span class="stat-unit">/ {{ currentUser?.max_rules ?? 0 }} 个</span></span>
            <span class="meter" aria-hidden="true">
              <span v-for="index in Math.max(currentUser?.max_rules ?? 0, 1)" :key="index" :class="index <= (currentUser?.rule_count ?? 0) ? 'is-on' : ''" />
            </span>
            <span class="text-xs" :class="myExpiry?.tone === 'soon' ? 'text-warning' : myExpiry?.tone === 'expired' ? 'text-danger' : 'text-muted'">{{ myExpiry?.text }}</span>
          </div>
          <div v-if="ports.data.value?.leases.length" class="panel p-4">
            <p class="stat-label mb-3">已用端口</p>
            <PortRuler :usage="ports.data.value" :statuses="statuses" />
          </div>
        </template>
      </div>
    </div>

    <section v-if="attentionCount" aria-labelledby="attention-title">
      <h2 id="attention-title" class="group-title">待处理 <span class="font-normal text-muted tabular">{{ attentionCount }}</span></h2>
      <ul class="panel group-list">
        <li v-if="executor && executor !== 'running'" class="flex items-start gap-3 px-4 py-3.5">
          <ServerOff class="mt-0.5 size-4 text-danger" aria-hidden="true" />
          <div class="min-w-0 flex-1">
            <p class="font-medium">{{ executor === 'offline' ? '执行器离线' : '执行器未连接' }}</p>
            <p class="text-sm text-muted">{{ executor === 'offline' ? '新变更暂不生效，运行中的转发不受影响' : '启动 relaydeck worker 后规则才会生效' }}</p>
          </div>
        </li>
        <li v-for="group in failedOwners" :key="group.ownerId" class="flex items-start gap-3 px-4 py-3.5">
          <StatusMark status="failed" class="mt-0.5" />
          <div class="min-w-0 flex-1">
            <p class="font-medium">{{ isAdmin ? `${group.owner} 的 ` : '' }}{{ group.rules.length }} 条生效失败</p>
            <p v-if="group.rules[0].runtime_error" class="mt-0.5 truncate font-mono text-xs text-muted" :title="group.rules[0].runtime_error">{{ group.rules[0].runtime_error }}</p>
            <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              <RouterLink v-for="rule in group.rules" :key="rule.id" :to="`/rules/${rule.id}`" class="text-sm font-medium hover:underline hover:underline-offset-4">{{ rule.name }} <span class="font-mono text-xs text-muted">{{ rule.listen_port }}</span></RouterLink>
            </div>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" :disabled="retry.isPending.value" @click="retry.mutate(group.ownerId)"><RotateCw class="size-3.5" />重试</button>
        </li>
        <template v-if="isAdmin">
          <li v-for="user in expiring" :key="`expiring-${user.id}`" class="flex items-start gap-3 px-4 py-3.5">
            <Clock class="mt-0.5 size-4 text-warning" aria-hidden="true" />
            <div class="min-w-0 flex-1">
              <p class="font-medium">{{ user.username }} {{ expiry(user.expires_at).text }}</p>
            </div>
            <RouterLink :to="`/accounts/${user.id}`" class="btn btn-secondary btn-sm">续期</RouterLink>
          </li>
          <li v-for="user in full" :key="`full-${user.id}`" class="flex items-start gap-3 px-4 py-3.5">
            <Gauge class="mt-0.5 size-4 text-warning" aria-hidden="true" />
            <div class="min-w-0 flex-1">
              <p class="font-medium">{{ user.username }} 额度已满 <span class="font-normal text-muted tabular">{{ user.rule_count }} / {{ user.max_rules }}</span></p>
            </div>
            <RouterLink :to="`/accounts/${user.id}`" class="btn btn-secondary btn-sm">调整额度</RouterLink>
          </li>
        </template>
      </ul>
    </section>

  </div>
</template>
