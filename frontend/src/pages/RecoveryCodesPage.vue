<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Copy, Download } from '@lucide/vue'
import AuthFrame from '../components/AuthFrame.vue'
import { clearRecoveryCodes, sessionState } from '../lib/session'
import { toast } from '../lib/toast'

const router = useRouter()
const saved = ref(false)
const codes = sessionState.recoveryCodes

async function copy() {
  try {
    await navigator.clipboard.writeText(codes.join('\n'))
    toast('已复制')
  } catch { toast('复制失败', { tone: 'danger' }) }
}

function download() {
  const url = URL.createObjectURL(new Blob([codes.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'relaydeck-recovery-codes.txt'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

async function finish() {
  clearRecoveryCodes()
  sessionState.notice = '两步验证已开启'
  await router.replace({ name: 'login' })
}
</script>

<template>
  <AuthFrame title="恢复码" description="每组只能用一次，仅显示这一次" wide>
    <ol class="grid grid-cols-2 gap-x-6 gap-y-2 well p-4 font-mono text-sm tabular max-sm:grid-cols-1" aria-label="恢复码">
      <li v-for="(code, index) in codes" :key="code" class="flex gap-2 [overflow-wrap:anywhere]"><span class="w-4 text-right text-faint">{{ index + 1 }}</span>{{ code }}</li>
    </ol>
    <div class="mt-3 flex gap-2">
      <button type="button" class="btn btn-secondary btn-sm" @click="copy"><Copy class="size-4" />复制</button>
      <button type="button" class="btn btn-secondary btn-sm" @click="download"><Download class="size-4" />下载 .txt</button>
    </div>
    <label class="mt-6 flex cursor-pointer items-center gap-2.5">
      <input v-model="saved" type="checkbox" class="size-4 accent-[var(--accent)]" />
      <span>已保存</span>
    </label>
    <button class="btn btn-primary mt-4 w-full" type="button" :disabled="!saved" @click="finish">完成</button>
  </AuthFrame>
</template>
