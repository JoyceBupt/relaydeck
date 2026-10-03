<script setup lang="ts">
import { AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogOverlay, AlertDialogPortal, AlertDialogRoot, AlertDialogTitle } from 'reka-ui'

defineProps<{ open: boolean; title: string; description: string; confirmLabel: string; busy?: boolean; danger?: boolean }>()
const emit = defineEmits<{ confirm: []; cancel: [] }>()
</script>

<template>
  <AlertDialogRoot :open="open" @update:open="value => { if (!value) emit('cancel') }">
    <AlertDialogPortal>
      <AlertDialogOverlay class="anim-fade fixed inset-0 z-[70] bg-[var(--overlay)]" />
      <AlertDialogContent class="anim-dialog pop fixed top-1/2 left-1/2 z-[70] w-[min(24rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 !rounded-[20px] !p-6">
        <AlertDialogTitle class="text-base font-semibold">{{ title }}</AlertDialogTitle>
        <AlertDialogDescription class="mt-2 text-muted [overflow-wrap:anywhere]">{{ description }}</AlertDialogDescription>
        <slot />
        <div class="mt-6 grid grid-cols-2 gap-2">
          <AlertDialogCancel class="btn btn-secondary" :disabled="busy">取消</AlertDialogCancel>
          <AlertDialogAction class="btn" :class="danger ? 'btn-danger' : 'btn-primary'" :disabled="busy" @click.prevent="emit('confirm')">
            {{ busy ? '处理中…' : confirmLabel }}
          </AlertDialogAction>
        </div>
      </AlertDialogContent>
    </AlertDialogPortal>
  </AlertDialogRoot>
</template>
