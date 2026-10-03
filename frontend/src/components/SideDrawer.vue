<script setup lang="ts">
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { X } from '@lucide/vue'

defineProps<{ open: boolean; title: string; description?: string; width?: 'md' | 'lg' }>()
const emit = defineEmits<{ close: []; 'before-close': [event: Event] }>()

function onOpen(value: boolean) { if (!value) emit('close') }
</script>

<template>
  <DialogRoot :open="open" @update:open="onOpen">
    <DialogPortal>
      <DialogOverlay class="anim-fade fixed inset-0 z-50 bg-[var(--overlay)]" />
      <!-- A floating sheet on desktop; a bottom sheet that leaves the page peeking above it on phones. -->
      <DialogContent
        class="anim-drawer fixed z-50 flex flex-col overflow-hidden bg-surface shadow-[var(--shadow-drawer)] outline-none max-md:inset-x-0 max-md:bottom-0 max-md:top-[calc(env(safe-area-inset-top)+2.5rem)] max-md:rounded-t-[20px] md:inset-y-3 md:right-3 md:rounded-[20px]"
        :class="width === 'lg' ? 'md:w-[34rem]' : 'md:w-[30rem]'"
        @escape-key-down="emit('before-close', $event)"
        @pointer-down-outside="emit('before-close', $event)"
      >
        <div class="mx-auto mt-2 h-1 w-9 rounded-full bg-surface-3 md:hidden" aria-hidden="true" />
        <header class="flex items-start gap-3 px-5 pt-4 pb-3 md:pt-5">
          <div class="min-w-0 flex-1">
            <slot name="title-prefix" />
            <DialogTitle class="truncate text-base font-semibold text-fg">{{ title }}</DialogTitle>
            <DialogDescription v-if="description" class="mt-0.5 text-xs text-muted">{{ description }}</DialogDescription>
          </div>
          <slot name="header-actions" />
          <DialogClose class="btn btn-secondary btn-sm btn-icon -mr-1 !size-7 text-muted" aria-label="关闭"><X class="size-4" /></DialogClose>
        </header>
        <div class="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 pt-2 pb-6">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="flex items-center gap-2 border-t border-line bg-[var(--material)] px-5 pt-3 pb-[max(0.875rem,env(safe-area-inset-bottom))] backdrop-blur-xl">
          <slot name="footer" />
        </footer>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>
