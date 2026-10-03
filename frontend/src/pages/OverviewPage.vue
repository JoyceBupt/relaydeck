<script setup lang="ts">
import { computed } from 'vue'
import { ArrowRight, CircleCheck, Clock, Gauge, Plus, RotateCw, ServerOff } from '@lucide/vue'
import StatusMark from '../components/StatusMark.vue'
import RuleEndpoint from '../components/RuleEndpoint.vue'
import PortRuler from '../components/PortRuler.vue'
import type { RuntimeStatus } from '../types'
import { currentUser, isAdmin } from '../lib/session'
import { useAudit, useHealth, usePorts, useRetry, useRules, useUsers } from '../lib/queries'
import { expiry, relative, statusLabels } from '../lib/format'
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
const myExpiry = computed(() => (currentUser.value ? expiry(currentUser.value.expires_at) : null))
const recent = computed(() => (audit.data.value ?? []).slice(0, 6).map(entry => ({ entry, ...describeAudit(entry) })))
const greeting = computed(() => {
  const hour = new Date().getHours()
  return hour < 6 ? '夜深了' : hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好'
})
</script>

<template>
  <div class="grid grid-cols-[minmax(0,1fr)] gap-8">
    <div class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-[-0.02em]">{{ greeting }}，{{ currentUser?.username }}</h1>
        <p class="mt-1 text-muted">
          <template v-if="rules.isLoading.value">正在读取状态…</template>
          <template v-else-if="attentionCount">有 {{ attentionCount }} 件事需要处理。</template>
          <template v-else-if="all.length">一切正常，{{ all.length }} 条转发都已按配置运行。</template>
          <template v-else>还没有转发。</template>
        </p>
      </div>
      <RouterLink to="/rules/new" class="btn btn-primary"><Plus class="size-4" />新建转发</RouterLink>
    </div>

    <!-- One horizontal status strip rather than a wall of metric tiles. -->
    <section aria-label="转发状态" class="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-4">
      <RouterLink
        v-for="item in counts" :key="item.status" :to="{ path: '/rules', query: { status: item.status } }"
        class="flex items-center justify-between gap-3 bg-surface px-4 py-3.5 transition-colors duration-150 hover:bg-surface-2"
      >
        <StatusMark :status="item.status" label :text="statusLabels[item.status]" />
        <span class="font-mono text-sm font-medium tabular" :class="item.status === 'failed' && item.count ? 'text-danger' : 'text-fg'">{{ item.count }}</span>
      </RouterLink>
    </section>

    <section aria-labelledby="attention-title">
      <h2 id="attention-title" class="mb-3 text-sm font-semibold">需要处理</h2>
      <div v-if="rules.isLoading.value" class="panel p-4"><div class="skeleton h-5 w-1/2" /></div>
      <ul v-else-if="attentionCount" class="panel divide-y divide-line">
        <li v-if="executor && executor !== 'running'" class="flex items-start gap-3 px-4 py-3.5">
          <ServerOff class="mt-0.5 size-4 text-danger" aria-hidden="true" />
          <div class="min-w-0 flex-1">
            <p class="font-medium">{{ executor === 'offline' ? '执行器离线' : '执行器未接入' }}</p>
            <p class="text-sm text-muted">{{ executor === 'offline' ? '新的变更会在执行器恢复后生效，已在运行的转发不受影响。' : '规则目前只会保存，不会生效。请在服务器上启动 relaydeck worker。' }}</p>
          </div>
        </li>
        <li v-for="group in failedOwners" :key="group.ownerId" class="flex items-start gap-3 px-4 py-3.5">
          <StatusMark status="failed" class="mt-0.5" />
          <div class="min-w-0 flex-1">
            <p class="font-medium">{{ isAdmin ? `${group.owner} 的 ` : '' }}{{ group.rules.length }} 条转发生效失败</p>
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
              <p class="text-sm text-muted">到期后该账户无法登录，名下转发会自动停止。</p>
            </div>
            <RouterLink :to="`/accounts/${user.id}`" class="btn btn-secondary btn-sm">续期</RouterLink>
          </li>
          <li v-for="user in full" :key="`full-${user.id}`" class="flex items-start gap-3 px-4 py-3.5">
            <Gauge class="mt-0.5 size-4 text-warning" aria-hidden="true" />
            <div class="min-w-0 flex-1">
              <p class="font-medium">{{ user.username }} 的规则额度已用完</p>
              <p class="text-sm text-muted">已用 {{ user.rule_count }} / {{ user.max_rules }} 条，对方无法再新建转发。</p>
            </div>
            <RouterLink :to="`/accounts/${user.id}`" class="btn btn-secondary btn-sm">调整额度</RouterLink>
          </li>
        </template>
      </ul>
      <div v-else class="panel flex items-center gap-3 px-4 py-3.5 text-muted">
        <CircleCheck class="size-4 text-success" aria-hidden="true" />没有需要处理的事项。
      </div>
    </section>

    <div class="grid grid-cols-[minmax(0,1fr)] gap-8 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <section v-if="!isAdmin && currentUser" aria-labelledby="grant-title">
        <h2 id="grant-title" class="mb-3 text-sm font-semibold">我的授权</h2>
        <div class="panel grid gap-4 p-4">
          <dl class="grid grid-cols-3 gap-4 text-sm max-sm:grid-cols-1">
            <div><dt class="text-muted">端口段</dt><dd class="mt-0.5 font-mono font-medium tabular">{{ currentUser.port_start }}–{{ currentUser.port_end }}</dd></div>
            <div><dt class="text-muted">规则额度</dt><dd class="mt-0.5 font-medium tabular">{{ currentUser.rule_count }} / {{ currentUser.max_rules }}</dd></div>
            <div><dt class="text-muted">有效期</dt><dd class="mt-0.5 font-medium" :class="myExpiry?.tone === 'soon' ? 'text-warning' : myExpiry?.tone === 'expired' ? 'text-danger' : ''">{{ myExpiry?.text }}</dd></div>
          </dl>
          <PortRuler v-if="ports.data.value" :usage="ports.data.value" :statuses="statuses" />
        </div>
      </section>

      <section aria-labelledby="rules-title">
        <div class="mb-3 flex items-center justify-between">
          <h2 id="rules-title" class="text-sm font-semibold">{{ isAdmin ? '最近更新的转发' : '我的转发' }}</h2>
          <RouterLink to="/rules" class="flex items-center gap-1 text-sm font-medium text-muted hover:text-fg">全部<ArrowRight class="size-3.5" /></RouterLink>
        </div>
        <ul v-if="all.length" class="panel divide-y divide-line">
          <li v-for="rule in [...all].sort((a, b) => b.updated_at - a.updated_at).slice(0, 6)" :key="rule.id">
            <RouterLink :to="`/rules/${rule.id}`" class="flex items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-surface-2/60">
              <StatusMark :status="rule.runtime_status" />
              <span class="min-w-0 flex-1">
                <span class="block truncate font-medium">{{ rule.name }}</span>
                <RuleEndpoint class="max-w-full text-muted" :port="rule.listen_port" :host="rule.target_host" :target-port="rule.target_port" />
              </span>
              <span class="shrink-0 text-xs text-muted">{{ relative(rule.updated_at) }}</span>
            </RouterLink>
          </li>
        </ul>
        <div v-else-if="!rules.isLoading.value" class="panel px-4 py-8 text-center text-muted">还没有转发。<RouterLink to="/rules/new" class="font-medium text-accent hover:underline">新建一条</RouterLink></div>
      </section>

      <section v-if="isAdmin" aria-labelledby="activity-title">
        <div class="mb-3 flex items-center justify-between">
          <h2 id="activity-title" class="text-sm font-semibold">最近操作</h2>
          <RouterLink to="/audit" class="flex items-center gap-1 text-sm font-medium text-muted hover:text-fg">审计<ArrowRight class="size-3.5" /></RouterLink>
        </div>
        <ol v-if="recent.length" class="panel divide-y divide-line">
          <li v-for="item in recent" :key="item.entry.id" class="px-4 py-3 text-sm">
            <p class="[overflow-wrap:anywhere]"><span class="font-medium">{{ item.entry.actor_username }}</span><span class="mx-1 text-muted">{{ item.verb }}</span><span v-if="item.object" class="font-medium">「{{ item.object.name }}」</span></p>
            <p class="mt-0.5 text-xs text-muted">{{ relative(item.entry.created_at) }}</p>
          </li>
        </ol>
        <div v-else-if="!audit.isLoading.value" class="panel px-4 py-8 text-center text-muted">还没有操作记录。</div>
      </section>
    </div>
  </div>
</template>
