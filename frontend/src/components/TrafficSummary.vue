<script setup lang="ts">
import { computed } from 'vue'
import type { TrafficView } from '../types'
import { trafficModes, trafficText } from '../lib/traffic'
import { dateTime } from '../lib/format'
const props = defineProps<{ traffic?: TrafficView; loading?: boolean; error?: boolean; showPeriod?: boolean }>()
const observed = computed(() => props.traffic?.observed_at != null && props.traffic.ready)
const percent = computed(() => props.traffic?.limit_bytes ? Math.min(100, Math.max(0, 100 * props.traffic.used_bytes / props.traffic.limit_bytes)) : 0)
</script>

<template>
  <section aria-label="本期流量" class="grid gap-3">
    <div class="flex items-center justify-between gap-3"><h3 class="text-sm font-medium">本期流量</h3><span v-if="traffic?.blocked" class="chip chip-red">已阻断</span><span v-else-if="traffic" class="text-xs text-muted">{{ trafficModes[traffic.mode] }}</span></div>
    <div v-if="loading && !traffic" class="skeleton h-8" />
    <p v-else-if="error && !observed" class="text-sm text-warning">统计暂不可用</p>
    <template v-else-if="traffic">
      <p class="font-mono text-base tabular"><span v-if="observed">{{ trafficText(traffic.used_bytes) }}</span><span v-else class="text-muted">—</span><span class="ml-2 text-sm text-muted">/ {{ traffic.limit_bytes === null ? '不限量' : trafficText(traffic.limit_bytes) }}</span></p>
      <div v-if="traffic.limit_bytes !== null && observed" class="h-1.5 overflow-hidden rounded-full bg-fill" role="progressbar" aria-label="流量用量" :aria-valuenow="Math.round(percent)" :aria-valuemin="0" :aria-valuemax="100"><div class="h-full rounded-full transition-[width]" :class="traffic.blocked ? 'bg-danger' : percent >= 80 ? 'bg-warning' : 'bg-accent'" :style="{ width: `${percent}%` }" /></div>
      <div v-if="observed" class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted"><span>入站 {{ trafficText(traffic.in_bytes) }}</span><span>出站 {{ trafficText(traffic.out_bytes) }}</span></div>
      <p v-if="traffic.error" class="field-error">{{ traffic.error }}</p><p v-else-if="!observed" class="field-hint">统计待同步</p>
      <p v-if="showPeriod !== false && traffic.reset_at" class="field-hint">周期到期 {{ dateTime(traffic.reset_at) }}</p>
    </template>
  </section>
</template>
