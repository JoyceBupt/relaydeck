<script setup lang="ts">
import { computed } from 'vue'
import type { PortUsage, RuntimeStatus } from '../types'

const props = defineProps<{
  usage: PortUsage
  statuses?: Record<number, { name: string; status: RuntimeStatus }>
  selected?: number | null
  ownRuleId?: number | null
}>()
const ports = computed(() => props.usage.leases.map(lease => ({
  ...lease,
  label: lease.state === 'releasing' ? '释放中' : props.statuses?.[lease.rule_id]?.name ?? '已占用',
})))
</script>

<template>
  <div v-if="ports.length" class="flex flex-wrap gap-1.5" aria-label="已用端口">
    <span v-for="port in ports" :key="port.port" class="chip tabular"
      :class="port.state === 'releasing' ? 'chip-amber' : port.rule_id === ownRuleId ? 'chip-blue' : ''"
      :title="`${port.port} · ${port.label}`">
      {{ port.port }}<span v-if="port.state === 'releasing'">释放中</span>
    </span>
  </div>
</template>
