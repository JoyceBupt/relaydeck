<script setup lang="ts">
import { MoveRight } from '@lucide/vue'
import { hostText } from '../lib/format'

defineProps<{ port: number; host: string; targetPort: number; resolved?: string }>()
</script>

<template>
  <span class="inline-flex min-w-0 items-center gap-1.5 text-sm tabular">
    <span class="font-medium text-fg">{{ port }}</span>
    <MoveRight class="size-3.5 text-faint" aria-label="转发到" role="img" />
    <span class="min-w-0 truncate text-fg" :title="resolved && resolved !== host ? `${host} → ${resolved}` : undefined">{{ hostText(host) }}:{{ targetPort }}</span>
  </span>
</template>
