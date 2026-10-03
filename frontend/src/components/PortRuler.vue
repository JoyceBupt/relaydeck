<script setup lang="ts">
import { computed } from 'vue'
import type { PortUsage, RuntimeStatus } from '../types'

const props = defineProps<{
  usage: PortUsage
  /** Status per rule id, so occupied ports show what is really running there. */
  statuses?: Record<number, { name: string; status: RuntimeStatus }>
  selected?: number | null
  /** The rule being edited may keep (or return to) any of its own ports. */
  ownRuleId?: number | null
  interactive?: boolean
}>()
const emit = defineEmits<{ select: [port: number] }>()

const GLOBAL_RESERVED = [22, 80, 443]
const span = computed(() => props.usage.port_end - props.usage.port_start + 1)
const discrete = computed(() => span.value <= 120)
const reserved = computed(() => new Set([...props.usage.reserved, ...GLOBAL_RESERVED]))
const leases = computed(() => new Map(props.usage.leases.map(lease => [lease.port, lease])))

type Cell = { port: number; kind: 'free' | 'reserved' | 'releasing' | 'own' | RuntimeStatus; title: string }
function describe(port: number): Cell {
  if (reserved.value.has(port)) return { port, kind: 'reserved', title: `${port} · 系统保留` }
  const lease = leases.value.get(port)
  if (!lease) return { port, kind: 'free', title: `${port} · 空闲` }
  const rule = props.statuses?.[lease.rule_id]
  if (lease.rule_id === props.ownRuleId) return { port, kind: 'own', title: `${port} · 当前规则` }
  if (lease.state === 'releasing') return { port, kind: 'releasing', title: `${port} · 释放中` }
  return { port, kind: rule?.status ?? 'active', title: `${port} · ${rule?.name ?? '已占用'}` }
}

const cells = computed(() => discrete.value
  ? Array.from({ length: span.value }, (_, index) => describe(props.usage.port_start + index))
  : [])
const markers = computed(() => discrete.value ? [] : [
  ...props.usage.leases.map(lease => describe(lease.port)),
  ...[...reserved.value].filter(port => port >= props.usage.port_start && port <= props.usage.port_end).map(describe),
].map(cell => ({ ...cell, left: span.value > 1 ? ((cell.port - props.usage.port_start) / (span.value - 1)) * 100 : 0 })))

function available(port: number) {
  if (reserved.value.has(port)) return false
  const lease = leases.value.get(port)
  return !lease || lease.rule_id === props.ownRuleId
}
const free = computed(() => {
  let count = 0
  for (let port = props.usage.port_start; port <= props.usage.port_end && count < 100_000; port++) if (available(port)) count++
  return count
})
const nextFree = computed(() => {
  for (let port = props.usage.port_start; port <= props.usage.port_end; port++) if (available(port) && port !== props.selected) return port
  return null
})

function pickFromTrack(event: MouseEvent) {
  if (!props.interactive) return
  const box = (event.currentTarget as HTMLElement).getBoundingClientRect()
  const guess = Math.round(props.usage.port_start + ((event.clientX - box.left) / box.width) * (span.value - 1))
  for (let offset = 0; offset < span.value; offset++) {
    for (const port of [guess + offset, guess - offset]) {
      if (port >= props.usage.port_start && port <= props.usage.port_end && available(port)) { emit('select', port); return }
    }
  }
}

const tone: Record<Cell['kind'], string> = {
  free: 'bg-[var(--meter-off)] hover:bg-line-strong',
  reserved: 'bg-transparent border border-dashed border-line-strong',
  releasing: 'bg-warning-soft border border-warning/60',
  own: 'bg-accent-soft border border-accent/60',
  active: 'bg-[var(--meter-ok)]',
  pending: 'bg-[var(--meter-warn)]',
  failed: 'bg-[var(--meter-bad)]',
  blocked: 'bg-[var(--meter-bad)] border border-dashed border-surface',
  stopped: 'bg-faint/50',
}
</script>

<template>
  <div class="grid gap-2">
    <div v-if="discrete" class="grid grid-cols-[repeat(auto-fill,minmax(0.875rem,1fr))] gap-[3px]" role="group" :aria-label="`端口 ${usage.port_start}–${usage.port_end} 的占用情况`">
      <button
        v-for="cell in cells" :key="cell.port" type="button"
        class="h-3.5 rounded-[3.5px] transition-colors duration-150 disabled:cursor-default"
        :class="[tone[cell.kind], selected === cell.port ? '!bg-accent ring-2 ring-accent/30' : '']"
        :title="cell.title" :aria-label="cell.title" :aria-pressed="selected === cell.port"
        :disabled="!interactive || !available(cell.port)"
        @click="emit('select', cell.port)"
      />
    </div>
    <div
      v-else class="relative h-7 rounded-lg bg-[var(--meter-off)]" :class="interactive ? 'cursor-crosshair' : ''"
      role="img" :aria-label="`端口 ${usage.port_start}–${usage.port_end}，已占用 ${usage.leases.length} 个`" @click="pickFromTrack"
    >
      <span
        v-for="marker in markers" :key="marker.port" class="absolute top-1 bottom-1 w-[3px] -translate-x-1/2 rounded-full"
        :class="tone[marker.kind]" :style="{ left: `${marker.left}%` }" :title="marker.title"
      />
      <span
        v-if="selected && selected >= usage.port_start && selected <= usage.port_end"
        class="absolute -top-0.5 -bottom-0.5 w-[3px] -translate-x-1/2 rounded-full bg-accent ring-2 ring-accent/30"
        :style="{ left: `${span > 1 ? ((selected - usage.port_start) / (span - 1)) * 100 : 0}%` }"
      />
    </div>
    <div class="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-xs text-muted">
      <span class="font-mono tabular">{{ usage.port_start }} – {{ usage.port_end }}</span>
      <span class="flex items-center gap-3">
        <span class="tabular">空闲 {{ free }}</span>
        <button v-if="interactive && nextFree !== null" type="button" class="font-medium text-accent hover:underline" @click="emit('select', nextFree)">
          下一个空闲 {{ nextFree }}
        </button>
      </span>
    </div>
  </div>
</template>
