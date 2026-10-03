<script setup lang="ts" generic="T extends string">
import { ToggleGroupItem, ToggleGroupRoot } from 'reka-ui'

defineProps<{ options: { value: T; label: string; count?: number }[]; label: string; disabled?: boolean; size?: 'sm' | 'md' }>()
const model = defineModel<T>({ required: true })

function update(value: unknown) { if (typeof value === 'string' && value) model.value = value as T }
</script>

<template>
  <ToggleGroupRoot
    type="single" :model-value="model" :aria-label="label" :disabled="disabled"
    class="inline-flex max-w-full items-center gap-0.5 overflow-x-auto rounded-xl border border-line bg-surface p-[3px] shadow-[var(--shadow-card)] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
    @update:model-value="update"
  >
    <ToggleGroupItem
      v-for="option in options" :key="option.value" :value="option.value"
      class="inline-flex shrink-0 items-center gap-1.5 rounded-[9px] border border-transparent px-3 font-medium whitespace-nowrap text-muted transition-[color,background-color,border-color] duration-200 hover:text-fg data-[state=on]:border-line-strong data-[state=on]:bg-surface-2 data-[state=on]:text-fg data-[state=on]:shadow-[0_1px_2px_rgb(0_0_0/0.06)]"
      :class="size === 'sm' ? 'h-7 text-xs' : 'h-8 text-sm'"
    >
      {{ option.label }}
      <span v-if="option.count !== undefined" class="tabular text-xs text-faint">{{ option.count }}</span>
    </ToggleGroupItem>
  </ToggleGroupRoot>
</template>
