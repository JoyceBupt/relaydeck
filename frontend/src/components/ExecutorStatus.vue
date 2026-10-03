<script setup lang="ts">
import { computed } from 'vue'
import { TooltipContent, TooltipPortal, TooltipRoot, TooltipTrigger } from 'reka-ui'
import { useHealth } from '../lib/queries'

const props = defineProps<{ compact?: boolean }>()
const health = useHealth()
const state = computed(() => {
  if (health.isError.value) return { tone: 'bg-danger', text: '无法连接', help: '面板暂时连不上服务器，正在重试。' }
  switch (health.data.value?.executor) {
    case 'running': return { tone: 'bg-success', text: '执行器在线', help: '执行器每 2 秒同步一次，规则变更会很快生效。' }
    case 'offline': return { tone: 'bg-danger', text: '执行器离线', help: '执行器 10 秒内没有心跳。新的变更会在它恢复后生效，已在运行的转发不受影响。' }
    case 'unconfigured': return { tone: 'bg-faint', text: '执行器未接入', help: '还没有执行器连接到这个面板，规则只会保存，不会生效。' }
    default: return { tone: 'bg-surface-3', text: '正在检查', help: '正在检查执行器状态。' }
  }
})
</script>

<template>
  <TooltipRoot>
    <TooltipTrigger as-child>
      <span :class="props.compact ? 'px-2 py-1' : 'border border-line bg-surface px-2.5 py-1 shadow-[var(--shadow-card)]'" class="inline-flex items-center gap-2 rounded-full text-xs text-muted" tabindex="0" :aria-label="`${state.text}。${state.help}`">
        <span class="size-2 rounded-full" :class="state.tone" />
        <span v-if="!props.compact">{{ state.text }}</span>
      </span>
    </TooltipTrigger>
    <TooltipPortal>
      <TooltipContent side="bottom" :side-offset="6" class="anim-pop pop z-[90] max-w-64 !px-3 !py-2 text-xs leading-5 text-muted">
        <span class="font-medium text-fg">{{ state.text }}</span> · {{ state.help }}
      </TooltipContent>
    </TooltipPortal>
  </TooltipRoot>
</template>
