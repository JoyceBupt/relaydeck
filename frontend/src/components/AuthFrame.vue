<script setup lang="ts">
import BrandMark from './BrandMark.vue'
import LoginBackdrop from './LoginBackdrop.vue'

defineProps<{ title: string; description?: string; wide?: boolean }>()
</script>

<template>
  <div class="relative isolate flex min-h-dvh flex-col px-4 pt-[max(1.25rem,env(safe-area-inset-top))] pb-[max(1.25rem,env(safe-area-inset-bottom))] md:px-8">
    <LoginBackdrop class="-z-10" />
    <div class="flex items-center gap-2.5 text-base font-semibold text-fg"><BrandMark />RelayDeck</div>
    <main class="flex flex-1 items-center justify-center py-10 lg:justify-end lg:pr-[8vw]">
      <section
        class="w-full rounded-[22px] border border-line bg-[var(--material)] p-7 shadow-[var(--shadow-pop)] backdrop-blur-2xl backdrop-saturate-150 md:p-8"
        :class="wide ? 'max-w-[30rem]' : 'max-w-[24rem]'" aria-labelledby="auth-title"
      >
        <h1 id="auth-title" class="text-xl leading-7 font-semibold text-fg">{{ title }}</h1>
        <p v-if="description" class="mt-1.5 text-sm text-muted">{{ description }}</p>
        <div class="mt-6"><slot /></div>
      </section>
    </main>
  </div>
</template>
