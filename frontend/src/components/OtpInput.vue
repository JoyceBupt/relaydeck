<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { PinInputInput, PinInputRoot } from 'reka-ui'

const props = defineProps<{ disabled?: boolean; invalid?: boolean; label: string }>()
const model = defineModel<string>({ required: true })
const emit = defineEmits<{ complete: [code: string] }>()

// Keep empty positions when a digit is edited or cleared in the middle.
const digits = ref<(number | undefined)[]>([])
watch(model, value => {
  if (value !== digits.value.join('')) digits.value = [...value].filter(char => /\d/.test(char)).map(Number)
}, { immediate: true })
function updateDigits(value: (number | undefined)[]) {
  digits.value = value
  model.value = value.join('')
}

// Restart the shake each time a new failure arrives.
const shaking = ref(false)
watch(() => props.invalid, async invalid => {
  if (!invalid) return
  shaking.value = false
  await nextTick()
  shaking.value = true
})

const root = ref<HTMLElement | null>(null)
defineExpose({ focus: () => root.value?.querySelector('input')?.focus() })
</script>

<template>
  <div ref="root" :class="shaking ? 'anim-shake' : ''" @animationend="shaking = false">
    <PinInputRoot
      :model-value="digits" type="number" otp :disabled="disabled" placeholder="" :aria-label="label"
      class="grid grid-cols-6 gap-2" @update:model-value="updateDigits" @complete="emit('complete', ($event as (number | undefined)[]).join(''))"
    >
      <PinInputInput
        v-for="(_, index) in 6" :key="index" :index="index"
        class="input h-14 !px-0 text-center !text-2xl font-semibold tabular caret-transparent"
        :aria-invalid="invalid ? 'true' : undefined" :aria-label="`第 ${index + 1} 位`"
      />
    </PinInputRoot>
  </div>
</template>
