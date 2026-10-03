<script setup lang="ts">
import { computed } from 'vue'
import { encode } from 'uqr'

// Rendered locally as SVG geometry: the enrollment secret never leaves the page.
const props = defineProps<{ value: string; label: string }>()
const matrix = computed(() => encode(props.value, { ecc: 'M', border: 2 }))
const path = computed(() => {
  const parts: string[] = []
  matrix.value.data.forEach((row, y) => row.forEach((dark, x) => { if (dark) parts.push(`M${x} ${y}h1v1h-1z`) }))
  return parts.join('')
})
</script>

<template>
  <svg :viewBox="`0 0 ${matrix.size} ${matrix.size}`" role="img" :aria-label="label" shape-rendering="crispEdges" class="block rounded-lg bg-white p-1 text-black">
    <path :d="path" fill="currentColor" />
  </svg>
</template>
