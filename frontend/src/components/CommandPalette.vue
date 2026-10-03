<script setup lang="ts">
import { computed, nextTick, ref, watch, type Component } from 'vue'
import { useRouter } from 'vue-router'
import { DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { ArrowRightLeft, CornerDownLeft, LayoutGrid, Moon, Plus, ScrollText, Search, Settings, Sun, SunMoon, UserPlus, Users } from '@lucide/vue'
import { useRules, useUsers } from '../lib/queries'
import { isAdmin } from '../lib/session'
import { theme } from '../lib/theme'
import { targetText } from '../lib/format'

const open = defineModel<boolean>('open', { required: true })
const router = useRouter()
const rules = useRules()
const users = useUsers()
const query = ref('')
const active = ref(0)
const input = ref<HTMLInputElement | null>(null)

interface Item { id: string; group: string; label: string; detail?: string; icon: Component; keywords: string; run: () => void }

const items = computed<Item[]>(() => {
  const go = (path: string) => () => router.push(path)
  const list: Item[] = [
    { id: 'new-rule', group: '操作', label: '新建转发', icon: Plus, keywords: 'new rule xinjian zhuanfa', run: go('/rules/new') },
    ...(isAdmin.value ? [{ id: 'new-user', group: '操作', label: '新建账户', icon: UserPlus, keywords: 'new user account kaihu', run: go('/accounts/new') }] : []),
    { id: 'theme-light', group: '操作', label: '切换到浅色主题', icon: Sun, keywords: 'theme light zhuti', run: () => { theme.value = 'light' } },
    { id: 'theme-dark', group: '操作', label: '切换到深色主题', icon: Moon, keywords: 'theme dark zhuti', run: () => { theme.value = 'dark' } },
    { id: 'theme-system', group: '操作', label: '主题跟随系统', icon: SunMoon, keywords: 'theme system zhuti', run: () => { theme.value = 'system' } },
    { id: 'go-overview', group: '前往', label: '总览', icon: LayoutGrid, keywords: 'overview home zonglan', run: go('/') },
    { id: 'go-rules', group: '前往', label: '转发', icon: ArrowRightLeft, keywords: 'rules forwards zhuanfa', run: go('/rules') },
    ...(isAdmin.value ? [
      { id: 'go-accounts', group: '前往', label: '账户', icon: Users, keywords: 'accounts users zhanghu', run: go('/accounts') },
      { id: 'go-audit', group: '前往', label: '审计', icon: ScrollText, keywords: 'audit log shenji', run: go('/audit') },
    ] : []),
    { id: 'go-settings', group: '前往', label: '设置', icon: Settings, keywords: 'settings security shezhi', run: go('/settings') },
    ...(rules.data.value ?? []).map(rule => ({
      id: `rule-${rule.id}`, group: '转发', label: rule.name, detail: `${rule.listen_port} → ${targetText(rule)}`, icon: ArrowRightLeft,
      keywords: `${rule.listen_port} ${rule.target_host} ${rule.owner_username}`, run: go(`/rules/${rule.id}`),
    })),
    ...(isAdmin.value ? (users.data.value ?? []).filter(user => user.role === 'user').map(user => ({
      id: `user-${user.id}`, group: '账户', label: user.username, detail: `${user.port_start}–${user.port_end}`, icon: Users,
      keywords: `${user.port_start} ${user.port_end}`, run: go(`/accounts/${user.id}`),
    })) : []),
  ]
  return list
})

const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const result = needle ? items.value.filter(item => `${item.label} ${item.detail ?? ''} ${item.keywords}`.toLowerCase().includes(needle)) : items.value.filter(item => item.group !== '转发' && item.group !== '账户')
  return result.slice(0, 40)
})
const groups = computed(() => {
  const map = new Map<string, Item[]>()
  for (const item of filtered.value) map.set(item.group, [...(map.get(item.group) ?? []), item])
  return [...map.entries()]
})

watch(query, () => { active.value = 0 })
watch(open, async value => {
  if (!value) return
  query.value = ''
  active.value = 0
  await nextTick()
  input.value?.focus()
})

function run(item: Item | undefined) {
  if (!item) return
  open.value = false
  item.run()
}

function onKey(event: KeyboardEvent) {
  const count = filtered.value.length
  if (!count) return
  if (event.key === 'ArrowDown') { event.preventDefault(); active.value = (active.value + 1) % count }
  else if (event.key === 'ArrowUp') { event.preventDefault(); active.value = (active.value - 1 + count) % count }
  else if (event.key === 'Enter') { event.preventDefault(); run(filtered.value[active.value]) }
}
watch(active, async () => {
  await nextTick()
  document.getElementById(`cmd-${filtered.value[active.value]?.id}`)?.scrollIntoView({ block: 'nearest' })
})
</script>

<template>
  <DialogRoot v-model:open="open">
    <DialogPortal>
      <DialogOverlay class="anim-fade fixed inset-0 z-[75] bg-[var(--overlay)]" />
      <DialogContent class="anim-pop pop fixed top-[12vh] left-1/2 z-[75] flex max-h-[min(30rem,76vh)] w-[min(36rem,calc(100vw-1.5rem))] -translate-x-1/2 flex-col !p-0" @open-auto-focus.prevent>
        <DialogTitle class="sr-only">命令面板</DialogTitle>
        <DialogDescription class="sr-only">输入以搜索页面、转发或操作，用方向键选择，回车执行。</DialogDescription>
        <div class="flex items-center gap-2.5 border-b border-line px-3.5">
          <Search class="size-4 text-faint" aria-hidden="true" />
          <input
            ref="input" v-model="query" class="h-12 min-w-0 flex-1 bg-transparent text-base text-fg outline-none placeholder:text-faint md:text-sm"
            placeholder="搜索端口、名称，或输入命令…" role="combobox" aria-expanded="true" aria-controls="command-list" aria-autocomplete="list"
            :aria-activedescendant="filtered[active] ? `cmd-${filtered[active].id}` : undefined" @keydown="onKey"
          />
          <span class="kbd">Esc</span>
        </div>
        <div id="command-list" role="listbox" aria-label="结果" class="min-h-0 flex-1 overflow-y-auto p-1.5">
          <p v-if="!filtered.length" class="px-3 py-8 text-center text-muted">没有匹配的结果</p>
          <div v-for="[group, entries] in groups" :key="group" role="group" :aria-label="group">
            <p class="pop-label">{{ group }}</p>
            <div
              v-for="item in entries" :id="`cmd-${item.id}`" :key="item.id" role="option" :aria-selected="filtered[active]?.id === item.id"
              class="pop-item h-9" :data-highlighted="filtered[active]?.id === item.id ? '' : undefined"
              @mousemove="active = filtered.indexOf(item)" @click="run(item)"
            >
              <component :is="item.icon" class="size-4 text-muted" aria-hidden="true" />
              <span class="truncate">{{ item.label }}</span>
              <span v-if="item.detail" class="ml-auto truncate font-mono text-xs text-muted tabular">{{ item.detail }}</span>
              <CornerDownLeft v-if="filtered[active]?.id === item.id && !item.detail" class="ml-auto size-3.5 text-faint" aria-hidden="true" />
            </div>
          </div>
        </div>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>
