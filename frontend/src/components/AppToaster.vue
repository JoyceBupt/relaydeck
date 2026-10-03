<script setup lang="ts">
import { ToastAction, ToastClose, ToastDescription, ToastProvider, ToastRoot, ToastTitle, ToastViewport } from 'reka-ui'
import { CircleAlert, CircleCheck, X } from '@lucide/vue'
import { dismissToast, toasts } from '../lib/toast'

function onOpen(id: number, open: boolean) { if (!open) dismissToast(id) }
</script>

<template>
  <ToastProvider :duration="5000" swipe-direction="right" label="通知">
    <ToastRoot
      v-for="item in toasts" :key="item.id" :open="item.open" :type="item.tone === 'danger' ? 'foreground' : 'background'" :duration="item.action ? 9000 : 5000"
      class="anim-toast pop pointer-events-auto flex w-full items-start gap-3 px-3.5 py-3"
      @update:open="onOpen(item.id, $event)"
    >
      <CircleAlert v-if="item.tone === 'danger'" class="mt-0.5 size-4 text-danger" aria-hidden="true" />
      <CircleCheck v-else-if="item.tone === 'success'" class="mt-0.5 size-4 text-success" aria-hidden="true" />
      <div class="min-w-0 flex-1">
        <ToastTitle class="font-medium text-fg">{{ item.title }}</ToastTitle>
        <ToastDescription v-if="item.description" class="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">{{ item.description }}</ToastDescription>
      </div>
      <ToastAction v-if="item.action" :alt-text="item.action.label" as-child>
        <button class="btn btn-secondary btn-sm" type="button" @click="item.action.run(); dismissToast(item.id)">{{ item.action.label }}</button>
      </ToastAction>
      <ToastClose class="btn btn-ghost btn-sm btn-icon -my-1 -mr-1.5" aria-label="关闭通知"><X class="size-4" /></ToastClose>
    </ToastRoot>
    <ToastViewport class="fixed right-0 bottom-0 z-[80] m-0 flex w-full max-w-sm list-none flex-col gap-2 p-4 outline-none max-md:bottom-[calc(4rem+env(safe-area-inset-bottom))]" />
  </ToastProvider>
</template>
