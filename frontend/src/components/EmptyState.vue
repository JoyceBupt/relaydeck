<script setup lang="ts">
defineProps<{ title: string; description?: string }>()
</script>

<template>
  <div class="flex flex-col items-center justify-center px-6 py-14 text-center">
    <div v-if="$slots.icon" class="mb-4 flex size-12 items-center justify-center rounded-full bg-fill text-muted"><slot name="icon" /></div>
    <p class="text-base font-semibold text-fg">{{ title }}</p>
    <p v-if="description" class="mt-1.5 max-w-sm text-muted">{{ description }}</p>
    <div v-if="$slots.default" class="mt-5 flex flex-wrap justify-center gap-2"><slot /></div>
  </div>
</template>
