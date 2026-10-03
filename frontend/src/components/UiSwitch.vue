<script setup lang="ts">
import { SwitchRoot, SwitchThumb } from 'reka-ui'

defineProps<{ label: string; disabled?: boolean }>()
const model = defineModel<boolean>({ required: true })
</script>

<template>
  <SwitchRoot
    v-model="model" :aria-label="label" :disabled="disabled"
    class="relative inline-flex h-[1.625rem] w-11 shrink-0 items-center rounded-full bg-surface-3 p-0.5 transition-colors duration-200 data-[state=checked]:bg-[var(--switch-on)] disabled:opacity-50"
    @click.stop
  >
    <SwitchThumb class="block size-[1.375rem] rounded-full bg-white shadow-[0_2px_4px_rgb(0_0_0/0.2),0_0_0_0.5px_rgb(0_0_0/0.04)] transition-transform duration-200 ease-[var(--ease-out)] data-[state=checked]:translate-x-[1.125rem]" />
  </SwitchRoot>
</template>
