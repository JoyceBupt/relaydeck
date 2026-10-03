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
      <DialogContent
        class="anim-drawer fixed z-50 flex flex-col bg-surface outline-none max-md:inset-0 md:inset-y-2 md:right-2 md:rounded-xl md:border md:border-line md:shadow-[var(--shadow-drawer)]"
        :class="width === 'lg' ? 'md:w-[34rem]' : 'md:w-[30rem]'"
        @escape-key-down="emit('before-close', $event)"
        @pointer-down-outside="emit('before-close', $event)"
      >
        <header class="flex items-start gap-3 border-b border-line px-5 pt-[max(1rem,env(safe-area-inset-top))] pb-4">
          <div class="min-w-0 flex-1">
            <slot name="title-prefix" />
            <DialogTitle class="truncate text-sm font-semibold text-fg">{{ title }}</DialogTitle>
            <DialogDescription v-if="description" class="mt-0.5 text-xs text-muted">{{ description }}</DialogDescription>
          </div>
          <slot name="header-actions" />
          <DialogClose class="btn btn-ghost btn-sm btn-icon -mr-1.5" aria-label="关闭"><X class="size-4" /></DialogClose>
        </header>
        <div class="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-5">
          <slot />
        </div>
        <footer v-if="$slots.footer" class="flex items-center gap-2 border-t border-line px-5 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
          <slot name="footer" />
        </footer>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>
