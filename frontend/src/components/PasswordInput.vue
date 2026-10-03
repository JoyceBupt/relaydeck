<script setup lang="ts">
import { ref } from 'vue'
import { Eye, EyeOff } from '@lucide/vue'

// Attributes such as autocomplete, required and aria-invalid belong on the field, not the wrapper.
defineOptions({ inheritAttrs: false })
const model = defineModel<string>({ required: true })
const visible = ref(false)
const capsLock = ref(false)
const input = ref<HTMLInputElement | null>(null)

function readCapsLock(event: KeyboardEvent) {
  if (typeof event.getModifierState === 'function') capsLock.value = event.getModifierState('CapsLock')
}
defineExpose({ focus: () => input.value?.focus() })
</script>

<template>
  <span class="grid gap-1.5">
    <span class="relative block">
      <input
        ref="input" v-model="model" v-bind="$attrs" class="input pr-10" :type="visible ? 'text' : 'password'"
        spellcheck="false" autocapitalize="off" @keydown="readCapsLock" @keyup="readCapsLock" @blur="capsLock = false"
      />
      <button
        type="button" class="absolute top-1/2 right-1.5 flex size-7 -translate-y-1/2 items-center justify-center rounded-lg text-faint transition-colors hover:bg-fill hover:text-fg"
        :aria-label="visible ? '隐藏密码' : '显示密码'" :aria-pressed="visible" @click="visible = !visible"
      >
        <EyeOff v-if="visible" class="size-4" aria-hidden="true" />
        <Eye v-else class="size-4" aria-hidden="true" />
      </button>
    </span>
    <span v-if="capsLock" class="field-hint !text-warning" role="status">大写锁定已开启</span>
  </span>
</template>
