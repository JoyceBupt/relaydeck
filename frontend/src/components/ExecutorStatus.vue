<script setup lang="ts">
import { computed } from 'vue'
import { TooltipContent, TooltipPortal, TooltipRoot, TooltipTrigger } from 'reka-ui'
import { useHealth } from '../lib/queries'

const props = defineProps<{ compact?: boolean }>()
const health = useHealth()
const state = computed(() => {
  if (health.isError.value) return { tone: 'bg-danger', text: '无法连接', help: '重试中' }
  switch (health.data.value?.executor) {
    case 'running': return { tone: 'bg-success', text: '执行器在线', help: '变更会自动应用' }
    case 'recovering': return { tone: 'bg-warning', text: '转发恢复中', help: '等待运行确认' }
    case 'offline': return { tone: 'bg-danger', text: '执行器离线', help: '超过 10 秒无心跳，新变更暂不生效' }
    case 'unconfigured': return { tone: 'bg-faint', text: '执行器未连接', help: '规则只保存，不生效' }
    default: return { tone: 'bg-surface-3', text: '检查中', help: '' }
  }
})
</script>

<template>
  <span v-if="health.isLoading.value" class="skeleton inline-block rounded-full" :class="props.compact ? 'h-6 w-6' : 'h-6 w-24'" role="status" aria-label="加载中" />
  <TooltipRoot v-else>
    <TooltipTrigger as-child>
      <span :class="props.compact ? 'px-2 py-1' : 'h-8 px-3 hover:bg-fill/60'" class="inline-flex items-center gap-2 rounded-lg text-xs text-muted transition-colors duration-200" tabindex="0" :aria-label="state.help ? `${state.text}，${state.help}` : state.text">
        <span class="size-2 rounded-full" :class="state.tone" />
        <span v-if="!props.compact">{{ state.text }}</span>
      </span>
    </TooltipTrigger>
    <TooltipPortal>
      <TooltipContent side="bottom" :side-offset="6" class="anim-pop pop z-[90] max-w-64 !px-3 !py-2 text-xs leading-5 text-muted">
        <span class="font-medium text-fg">{{ state.text }}</span><template v-if="state.help"> · {{ state.help }}</template>
      </TooltipContent>
    </TooltipPortal>
  </TooltipRoot>
</template>
