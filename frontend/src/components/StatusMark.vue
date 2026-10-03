<script setup lang="ts">
import { computed } from 'vue'
import type { RuntimeStatus } from '../types'
import { statusLabels } from '../lib/format'

const props = withDefaults(defineProps<{ status: RuntimeStatus; label?: boolean; text?: string }>(), { label: false })
const tone = computed(() => ({ active: 'text-success', pending: 'text-warning', failed: 'text-danger', stopped: 'text-faint' })[props.status])
</script>

<template>
  <!-- Every state has its own shape, so status never depends on color alone. -->
  <span class="inline-flex items-center gap-1.5 whitespace-nowrap" :class="tone">
    <svg viewBox="0 0 16 16" class="size-3.5" aria-hidden="true">
      <circle v-if="status === 'active'" cx="8" cy="8" r="4" fill="currentColor" />
      <g v-else-if="status === 'pending'" class="anim-spin origin-center [transform-box:fill-box]">
        <circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" stroke-opacity=".25" stroke-width="2" />
        <path d="M8 3a5 5 0 0 1 5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
      </g>
      <g v-else-if="status === 'failed'">
        <circle cx="8" cy="8" r="6" fill="currentColor" />
        <path d="M5.75 5.75l4.5 4.5m0-4.5l-4.5 4.5" class="stroke-surface" stroke-width="1.6" stroke-linecap="round" />
      </g>
      <circle v-else cx="8" cy="8" r="4.25" fill="none" stroke="currentColor" stroke-width="1.5" />
    </svg>
    <span v-if="label" class="text-xs font-medium">{{ text ?? statusLabels[status] }}</span>
    <span v-else class="sr-only">{{ text ?? statusLabels[status] }}</span>
  </span>
</template>
