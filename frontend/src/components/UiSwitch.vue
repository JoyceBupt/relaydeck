<script setup lang="ts">
import { SwitchRoot, SwitchThumb } from 'reka-ui'

defineProps<{ label: string; disabled?: boolean }>()
const model = defineModel<boolean>({ required: true })
</script>

<template>
  <SwitchRoot
    v-model="model" :aria-label="label" :disabled="disabled"
    class="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-transparent bg-surface-3 transition-colors duration-150 data-[state=checked]:bg-accent disabled:opacity-50"
    @click.stop
  >
    <SwitchThumb class="block size-4 translate-x-0.5 rounded-full bg-white shadow-[0_1px_2px_rgb(0_0_0/0.3)] transition-transform duration-150 data-[state=checked]:translate-x-[1.125rem]" />
  </SwitchRoot>
</template>
