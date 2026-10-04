<script setup lang="ts">
import { computed, ref } from 'vue'
import BrandMark from './BrandMark.vue'
import StatusMark from './StatusMark.vue'
import type { Rule, RuntimeStatus } from '../types'
import { hostText, statusLabels } from '../lib/format'

// Every forward passes through this host: entry port on the left, target on
// the right, one stream each through the hub. The login backdrop's language,
// drawn from live rules.
const props = defineProps<{ rules: Rule[]; admin?: boolean; limit?: number }>()

const ROW = 32
const order: RuntimeStatus[] = ['failed', 'blocked', 'pending', 'active', 'stopped']
const expanded = ref(new Set<number>())
type Row = { key: string; rule: Rule; bundle?: Rule[] }
const sorted = computed(() => [...props.rules]
  .sort((a, b) => order.indexOf(a.runtime_status) - order.indexOf(b.runtime_status) || a.listen_port - b.listen_port))
const rows = computed<Row[]>(() => {
  const single = (rule: Rule): Row => ({ key: `rule-${rule.id}`, rule })
  if (props.rules.length <= (props.limit ?? 12)) return sorted.value.map(single)
  const groups = new Map<number, Rule[]>()
  for (const rule of sorted.value) groups.set(rule.owner_id, [...(groups.get(rule.owner_id) ?? []), rule])
  return [...groups.values()].flatMap(bundle => [
    { key: `owner-${bundle[0].owner_id}`, rule: bundle[0], bundle },
    ...(expanded.value.has(bundle[0].owner_id) ? bundle.map(single) : []),
  ])
})
function toggle(owner: number) {
  const next = new Set(expanded.value)
  if (next.has(owner)) next.delete(owner)
  else next.add(owner)
  expanded.value = next
}
const height = computed(() => Math.max(rows.value.length, 1) * ROW)

const streams = computed(() => {
  const hub = height.value / 2
  return rows.value.map((row, index) => {
    const y = index * ROW + ROW / 2
    return { ...row, d: `M0 ${y} C 26 ${y}, 30 ${hub}, 50 ${hub} C 70 ${hub}, 74 ${y}, 100 ${y}` }
  })
})

const stroke: Record<RuntimeStatus, string> = {
  active: 'stroke-[var(--accent)] [stroke-opacity:0.45]',
  pending: 'stroke-[var(--meter-warn)] [stroke-opacity:0.7] [stroke-dasharray:6_8]',
  failed: 'stroke-[var(--meter-bad)] [stroke-opacity:0.7]',
  blocked: 'stroke-[var(--meter-bad)] [stroke-opacity:0.7] [stroke-dasharray:6_8]',
  stopped: 'stroke-[var(--border-strong)]',
}
// Static class strings so Tailwind generates them; packets are staggered per stream.
const pulses = [
  'animate-[flow_6s_linear_infinite]', 'animate-[flow_7s_linear_infinite] [animation-delay:-3s]', 'animate-[flow_5.5s_linear_infinite] [animation-delay:-1s]',
  'animate-[flow_8s_linear_infinite] [animation-delay:-5s]', 'animate-[flow_6.5s_linear_infinite] [animation-delay:-2s]', 'animate-[flow_7.5s_linear_infinite] [animation-delay:-4s]',
]
</script>

<template>
  <div v-if="rows.length" class="grid grid-cols-[minmax(0,1fr)_minmax(3rem,1fr)_minmax(0,1.5fr)] items-stretch gap-x-2 md:gap-x-5">
    <ul class="grid content-start" aria-label="入口">
      <li v-for="row in rows" :key="row.key" class="min-w-0 h-8">
        <button v-if="row.bundle" type="button" class="flex h-8 w-full items-center gap-1.5 rounded-lg text-left text-sm hover:text-accent" :aria-expanded="expanded.has(row.rule.owner_id)" :aria-label="`${row.rule.owner_username}，${row.bundle.length} 条转发，${expanded.has(row.rule.owner_id) ? '收起' : '展开'}`" @click="toggle(row.rule.owner_id)">
          <StatusMark :status="row.rule.runtime_status" />
          <span class="truncate font-medium">{{ row.rule.owner_username }}</span>
          <span class="shrink-0 text-xs text-muted" aria-hidden="true">{{ expanded.has(row.rule.owner_id) ? '−' : '+' }}</span>
        </button>
        <RouterLink v-else :to="`/rules/${row.rule.id}`" class="flex h-8 items-center gap-1.5 rounded-lg pr-1 text-sm hover:text-accent" :aria-label="`${row.rule.name}，${row.rule.listen_port}，${statusLabels[row.rule.runtime_status]}`" :title="row.rule.name">
          <StatusMark :status="row.rule.runtime_status" />
          <span class="shrink-0 font-medium tabular">{{ row.rule.listen_port }}</span>
          <span class="truncate text-xs text-muted max-sm:hidden">{{ row.rule.name }}</span>
        </RouterLink>
      </li>
    </ul>

    <div class="relative" :style="{ height: `${height}px` }" aria-hidden="true">
      <svg class="absolute inset-0 size-full overflow-visible" :viewBox="`0 0 100 ${height}`" preserveAspectRatio="none">
        <g fill="none" stroke-linecap="round">
          <g v-for="stream in streams" :key="stream.key">
            <path v-if="stream.bundle" :d="stream.d" stroke="transparent" stroke-width="14" vector-effect="non-scaling-stroke" class="cursor-pointer [pointer-events:stroke]" @click="toggle(stream.rule.owner_id)" />
            <RouterLink v-else v-slot="{ href, navigate }" :to="`/rules/${stream.rule.id}`" custom>
              <a :href="href" tabindex="-1" @click="navigate"><path :d="stream.d" stroke="transparent" stroke-width="14" vector-effect="non-scaling-stroke" class="cursor-pointer [pointer-events:stroke]" /></a>
            </RouterLink>
            <path :d="stream.d" :stroke-width="stream.bundle ? 3 : 1.5" vector-effect="non-scaling-stroke" class="pointer-events-none" :class="stroke[stream.rule.runtime_status]" />
          </g>
          <template v-for="(stream, index) in streams" :key="`pulse-${stream.key}`">
            <path
              v-if="stream.rule.runtime_status === 'active'" :d="stream.d" pathLength="1000" stroke-dasharray="22 978" stroke-width="2.5"
              vector-effect="non-scaling-stroke" class="pointer-events-none stroke-[var(--accent)] [stroke-dashoffset:1000]" :class="pulses[index % pulses.length]"
            />
          </template>
        </g>
      </svg>
      <span class="pointer-events-none absolute top-1/2 left-1/2 flex size-10 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-line bg-surface shadow-[var(--shadow-card)]">
        <BrandMark />
      </span>
    </div>

    <ul class="grid content-start" aria-label="落地">
      <li v-for="row in rows" :key="row.key" class="flex min-w-0 h-8 items-center justify-end text-sm text-muted tabular">
        <button v-if="row.bundle" type="button" class="h-8 rounded-lg text-xs hover:text-accent" :aria-expanded="expanded.has(row.rule.owner_id)" @click="toggle(row.rule.owner_id)">{{ row.bundle.length }} 条转发</button>
        <RouterLink v-else :to="`/rules/${row.rule.id}`" class="truncate rounded-lg hover:text-accent" :title="`${hostText(row.rule.target_host)}:${row.rule.target_port}`">{{ hostText(row.rule.target_host) }}:{{ row.rule.target_port }}</RouterLink>
      </li>
    </ul>
  </div>
  <p v-else class="py-8 text-center text-sm text-muted">暂无转发</p>
</template>
