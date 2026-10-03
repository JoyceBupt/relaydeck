<script setup lang="ts">
import { ConfigProvider, TooltipProvider } from 'reka-ui'
import AppToaster from './components/AppToaster.vue'
</script>

<template>
  <ConfigProvider dir="ltr" locale="zh-CN">
    <TooltipProvider :delay-duration="300">
      <RouterView />
      <AppToaster />
    </TooltipProvider>
  </ConfigProvider>
</template>
