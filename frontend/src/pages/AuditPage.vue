<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowRightLeft, KeyRound, RotateCw, ScrollText, Search, UserCog } from '@lucide/vue'
import Segmented from '../components/Segmented.vue'
import EmptyState from '../components/EmptyState.vue'
import { errorMessage } from '../api/client'
import { useAudit } from '../lib/queries'
import { clock, dateOnly, dateTime, nowSeconds } from '../lib/format'
import { describeAudit, type AuditCategory } from '../lib/audit'

const audit = useAudit()
const category = ref<'all' | AuditCategory>('all')
const search = ref('')
const icons = { rule: ArrowRightLeft, account: UserCog, security: KeyRound }

const entries = computed(() => (audit.data.value ?? []).map(entry => ({ entry, ...describeAudit(entry) })))
const filtered = computed(() => {
  const needle = search.value.trim().toLowerCase()
  return entries.value.filter(item => (category.value === 'all' || item.category === category.value)
    && (!needle || `${item.entry.actor_username} ${item.verb} ${item.object?.name ?? ''} ${item.object?.port ?? ''}`.toLowerCase().includes(needle)))
})
const groups = computed(() => {
  const today = dateOnly(nowSeconds())
  const yesterday = dateOnly(nowSeconds() - 86_400)
  const map = new Map<string, typeof filtered.value>()
  for (const item of filtered.value) {
    const day = dateOnly(item.entry.created_at)
    const label = day === today ? '今天' : day === yesterday ? '昨天' : day
    map.set(label, [...(map.get(label) ?? []), item])
  }
  return [...map.entries()]
})
const options = computed(() => [
  { value: 'all' as const, label: '全部' },
  { value: 'rule' as const, label: '转发' },
  { value: 'account' as const, label: '账户' },
  { value: 'security' as const, label: '登录与安全' },
])
</script>

<template>
  <div>
    <h1 class="text-2xl font-semibold tracking-[-0.02em]">审计</h1>
    <p class="mt-1 text-muted">最近 200 条操作记录，只有管理员可见。</p>

    <div class="mt-6 flex flex-wrap items-center gap-2">
      <Segmented v-model="category" label="按类别筛选" :options="options" />
      <label class="relative ml-auto w-full sm:w-64">
        <span class="sr-only">搜索记录</span>
        <Search class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-faint" aria-hidden="true" />
        <input v-model="search" type="search" class="input pl-8" placeholder="搜索账户、对象或端口" />
      </label>
    </div>

    <section class="mt-4" aria-label="操作记录">
      <div v-if="audit.isLoading.value" class="panel divide-y divide-line">
        <div v-for="index in 6" :key="index" class="flex items-center gap-4 px-4 py-3.5"><span class="skeleton h-4 w-10" /><span class="skeleton h-4 w-72" /></div>
      </div>
      <div v-else-if="audit.isError.value" class="panel px-6 py-10 text-center">
        <p class="font-medium">没能读取操作记录</p>
        <p class="mt-1 text-muted">{{ errorMessage(audit.error.value) }}</p>
        <button type="button" class="btn btn-secondary mt-4" @click="audit.refetch()"><RotateCw class="size-4" />重试</button>
      </div>
      <div v-else-if="!filtered.length" class="panel">
        <EmptyState :title="entries.length ? '没有匹配的记录' : '还没有操作记录'">
          <template #icon><ScrollText class="size-5" /></template>
        </EmptyState>
      </div>
      <div v-else class="grid gap-6">
        <div v-for="[day, items] in groups" :key="day">
          <h2 class="mb-2 text-xs font-medium text-muted">{{ day }}</h2>
          <ol class="panel divide-y divide-line">
            <li v-for="item in items" :key="item.entry.id" class="flex items-start gap-3 px-4 py-3">
              <time class="w-11 shrink-0 pt-px font-mono text-xs text-muted tabular" :datetime="new Date(item.entry.created_at * 1000).toISOString()" :title="dateTime(item.entry.created_at)">{{ clock(item.entry.created_at) }}</time>
              <component :is="icons[item.category]" class="mt-0.5 size-4 text-faint" aria-hidden="true" />
              <p class="min-w-0 flex-1 [overflow-wrap:anywhere]">
                <span class="font-medium">{{ item.entry.actor_username }}</span>
                <span class="mx-1 text-muted">{{ item.verb }}</span>
                <template v-if="item.object">
                  <RouterLink v-if="item.object.to" :to="item.object.to" class="font-medium hover:underline hover:underline-offset-4">「{{ item.object.name }}」</RouterLink>
                  <span v-else class="font-medium">「{{ item.object.name }}」</span>
                  <span v-if="item.object.port" class="ml-1 font-mono text-xs text-muted tabular">{{ item.object.port }}</span>
                </template>
              </p>
            </li>
          </ol>
        </div>
      </div>
    </section>
  </div>
</template>
