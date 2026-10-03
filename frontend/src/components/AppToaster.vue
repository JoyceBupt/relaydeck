<script setup lang="ts">
import { ToastAction, ToastClose, ToastDescription, ToastProvider, ToastRoot, ToastTitle, ToastViewport } from 'reka-ui'
import { X } from '@lucide/vue'
import { dismissToast, toasts } from '../lib/toast'

function onOpen(id: number, open: boolean) { if (!open) dismissToast(id) }
</script>

<template>
  <ToastProvider :duration="5000" swipe-direction="right" label="通知">
    <ToastRoot
      v-for="item in toasts" :key="item.id" :open="item.open" :type="item.tone === 'danger' ? 'foreground' : 'background'" :duration="item.action ? 9000 : 5000"
      class="anim-toast pop pointer-events-auto flex w-full items-center gap-3 !rounded-xl py-2 pr-2 pl-4"
      @update:open="onOpen(item.id, $event)"
    >
      <div class="min-w-0 flex-1">
        <ToastTitle class="font-medium" :class="item.tone === 'danger' ? 'text-danger' : 'text-fg'">{{ item.title }}</ToastTitle>
        <ToastDescription v-if="item.description" class="mt-0.5 text-xs text-muted [overflow-wrap:anywhere]">{{ item.description }}</ToastDescription>
      </div>
      <ToastAction v-if="item.action" :alt-text="item.action.label" as-child>
        <button class="rounded-lg px-2 py-1 text-sm font-medium text-accent hover:bg-fill" type="button" @click="item.action.run(); dismissToast(item.id)">{{ item.action.label }}</button>
      </ToastAction>
      <ToastClose class="btn btn-ghost btn-sm btn-icon" aria-label="关闭"><X class="size-4" /></ToastClose>
    </ToastRoot>
    <ToastViewport class="fixed right-0 bottom-0 z-[80] m-0 flex w-full max-w-sm list-none flex-col gap-2 p-4 outline-none max-md:bottom-[calc(4.5rem+env(safe-area-inset-bottom))]" />
  </ToastProvider>
</template>
