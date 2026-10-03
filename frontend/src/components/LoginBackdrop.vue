<script setup lang="ts">
// Traffic arriving from the left converges on one relay point and fans out to the
// right: the product drawn as light. Colors come from --art-* tokens so the piece
// follows the theme; motion stops under prefers-reduced-motion.
const relay = { x: 430, y: 520 }
const inbound = [110, 250, 400, 640, 800, 930].map(y => `M-40 ${y} C 170 ${y}, 290 ${relay.y}, ${relay.x} ${relay.y}`)
const outbound = [80, 220, 370, 590, 740, 900].map(y => `M${relay.x} ${relay.y} C 760 ${relay.y}, 1040 ${y}, 1660 ${y}`)
const paths = [...inbound, ...outbound]
// Static class strings so Tailwind can see them; one packet per stream, staggered.
const pulses = [
  'animate-[flow_9s_linear_infinite]', 'animate-[flow_11s_linear_infinite] [animation-delay:-4s]', 'animate-[flow_8s_linear_infinite] [animation-delay:-2s]',
  'animate-[flow_12s_linear_infinite] [animation-delay:-7s]', 'animate-[flow_10s_linear_infinite] [animation-delay:-5s]', 'animate-[flow_13s_linear_infinite] [animation-delay:-9s]',
  'animate-[flow_10s_linear_infinite] [animation-delay:-1s]', 'animate-[flow_12s_linear_infinite] [animation-delay:-6s]', 'animate-[flow_9s_linear_infinite] [animation-delay:-3s]',
  'animate-[flow_11s_linear_infinite] [animation-delay:-8s]', 'animate-[flow_8s_linear_infinite] [animation-delay:-5s]', 'animate-[flow_13s_linear_infinite] [animation-delay:-2s]',
]
</script>

<template>
  <div class="absolute inset-0 overflow-hidden bg-[linear-gradient(160deg,var(--art-top),var(--art-bottom))]" aria-hidden="true">
    <svg class="size-full" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <pattern id="art-dots" width="28" height="28" patternUnits="userSpaceOnUse">
          <circle cx="2" cy="2" r="1.1" class="fill-[var(--art-dot)]" />
        </pattern>
        <radialGradient id="art-fade" cx="0.35" cy="0.5" r="0.75">
          <stop offset="0" stop-color="#fff" />
          <stop offset="1" stop-color="#fff" stop-opacity="0" />
        </radialGradient>
        <mask id="art-mask"><rect width="1600" height="1000" fill="url(#art-fade)" /></mask>
        <radialGradient id="art-glow">
          <stop offset="0" class="[stop-color:var(--art-glow)]" />
          <stop offset="1" class="[stop-color:var(--art-glow)]" stop-opacity="0" />
        </radialGradient>
        <linearGradient id="art-stream" x1="0" x2="1">
          <stop offset="0" class="[stop-color:var(--art-line)]" stop-opacity="0" />
          <stop offset="0.3" class="[stop-color:var(--art-line)]" />
          <stop offset="0.7" class="[stop-color:var(--art-line-2)]" />
          <stop offset="1" class="[stop-color:var(--art-line-2)]" stop-opacity="0" />
        </linearGradient>
      </defs>
      <rect width="1600" height="1000" fill="url(#art-dots)" mask="url(#art-mask)" />
      <circle :cx="relay.x" :cy="relay.y" r="320" fill="url(#art-glow)" />
      <g fill="none" stroke-linecap="round">
        <path v-for="(d, index) in paths" :key="`line-${index}`" :d="d" stroke="url(#art-stream)" stroke-width="1.4" />
        <path
          v-for="(d, index) in paths" :key="`pulse-${index}`" :d="d" pathLength="1000" stroke-dasharray="26 974"
          class="stroke-[var(--art-pulse)] [stroke-dashoffset:1000]" :class="pulses[index]" stroke-width="2.2"
        />
      </g>
      <circle :cx="relay.x" :cy="relay.y" r="7" class="fill-[var(--art-pulse)]" />
      <circle :cx="relay.x" :cy="relay.y" r="18" fill="none" class="stroke-[var(--art-pulse)]" stroke-opacity="0.35" stroke-width="1.2" />
    </svg>
  </div>
</template>
