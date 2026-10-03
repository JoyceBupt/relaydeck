<script setup lang="ts">
import BrandMark from './BrandMark.vue'
import { useHealth } from '../lib/queries'

defineProps<{ title: string; description?: string; wide?: boolean }>()
const health = useHealth()
</script>

<template>
  <div class="flex min-h-dvh flex-col px-4 pt-[max(1.5rem,env(safe-area-inset-top))] pb-[max(1.5rem,env(safe-area-inset-bottom))]">
    <div class="flex items-center gap-2.5 font-semibold tracking-[-0.01em] md:px-4 md:pt-2"><BrandMark />RelayDeck</div>
    <main class="flex flex-1 items-center justify-center py-10">
      <section class="w-full" :class="wide ? 'max-w-md' : 'max-w-[22rem]'" :aria-labelledby="'auth-title'">
        <h1 id="auth-title" class="text-2xl font-semibold tracking-[-0.02em] text-fg">{{ title }}</h1>
        <p v-if="description" class="mt-2 text-muted">{{ description }}</p>
        <div class="mt-7"><slot /></div>
      </section>
    </main>
    <p class="text-center text-xs text-faint md:text-left md:px-4">{{ health.data.value ? `RelayDeck ${health.data.value.version}` : ' ' }}</p>
  </div>
</template>
