<script setup lang="ts">
import { computed } from 'vue'
import BrandMark from './BrandMark.vue'
import StatusMark from './StatusMark.vue'
import type { Rule, RuntimeStatus } from '../types'
import { hostText } from '../lib/format'

// Every forward passes through this host: entry port on the left, target on
// the right, one stream each through the hub. The login backdrop's language,
// drawn from live rules.
const props = defineProps<{ rules: Rule[]; admin?: boolean; limit?: number }>()

const ROW = 32
const order: RuntimeStatus[] = ['failed', 'blocked', 'pending', 'active', 'stopped']
const shown = computed(() => [...props.rules]
  .sort((a, b) => order.indexOf(a.runtime_status) - order.indexOf(b.runtime_status) || a.listen_port - b.listen_port)
  .slice(0, props.limit ?? 12))
const hidden = computed(() => props.rules.length - shown.value.length)
const height = computed(() => Math.max(shown.value.length, 1) * ROW)

const streams = computed(() => {
  const hub = height.value / 2
  return shown.value.map((rule, index) => {
    const y = index * ROW + ROW / 2
    return { rule, d: `M0 ${y} C 26 ${y}, 30 ${hub}, 50 ${hub} C 70 ${hub}, 74 ${y}, 100 ${y}` }
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
  <div class="grid grid-cols-[minmax(0,auto)_minmax(4rem,1fr)_minmax(0,auto)] items-stretch gap-x-3 md:gap-x-5">
    <ul class="grid content-start" aria-label="入口">
      <li v-for="item in shown" :key="item.id" class="h-8">
        <RouterLink :to="`/rules/${item.id}`" class="flex h-8 items-center gap-2 rounded-lg pr-1 text-sm hover:text-accent" :title="item.name">
          <StatusMark :status="item.runtime_status" />
          <span class="font-medium tabular">{{ item.listen_port }}</span>
          <span class="truncate text-xs text-muted max-sm:hidden">{{ admin ? item.owner_username : item.name }}</span>
        </RouterLink>
      </li>
    </ul>

    <div class="relative" :style="{ height: `${height}px` }" aria-hidden="true">
      <svg class="absolute inset-0 size-full overflow-visible" :viewBox="`0 0 100 ${height}`" preserveAspectRatio="none">
        <g fill="none" stroke-linecap="round">
          <path v-for="stream in streams" :key="`line-${stream.rule.id}`" :d="stream.d" stroke-width="1.5" vector-effect="non-scaling-stroke" :class="stroke[stream.rule.runtime_status]" />
          <template v-for="(stream, index) in streams" :key="`pulse-${stream.rule.id}`">
            <path
              v-if="stream.rule.runtime_status === 'active'" :d="stream.d" pathLength="1000" stroke-dasharray="22 978" stroke-width="2.5"
              vector-effect="non-scaling-stroke" class="stroke-[var(--accent)] [stroke-dashoffset:1000]" :class="pulses[index % pulses.length]"
            />
          </template>
        </g>
      </svg>
      <span class="absolute top-1/2 left-1/2 flex size-10 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-line bg-surface shadow-[var(--shadow-card)]">
        <BrandMark />
      </span>
    </div>

    <ul class="grid content-start" aria-label="落地">
      <li v-for="item in shown" :key="item.id" class="flex h-8 items-center justify-end text-sm text-muted tabular">
        <span class="max-w-[11rem] truncate" :title="item.target_ip !== item.target_host ? item.target_ip : undefined">{{ hostText(item.target_host) }}:{{ item.target_port }}</span>
      </li>
    </ul>
  </div>
  <p v-if="!shown.length" class="-mt-5 text-center text-sm text-muted">暂无转发</p>
  <RouterLink v-if="hidden > 0" to="/rules" class="mt-2 block text-center text-xs text-muted hover:text-accent">另有 {{ hidden }} 条</RouterLink>
</template>
