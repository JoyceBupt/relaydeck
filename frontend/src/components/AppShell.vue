<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useEventListener } from '@vueuse/core'
import { DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuPortal, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuItemIndicator, DropdownMenuRoot, DropdownMenuSeparator, DropdownMenuTrigger } from 'reka-ui'
import { ArrowRightLeft, Check, LayoutGrid, LogOut, ScrollText, Search, Settings, ShieldAlert, Users } from '@lucide/vue'
import BrandMark from './BrandMark.vue'
import ExecutorStatus from './ExecutorStatus.vue'
import CommandPalette from './CommandPalette.vue'
import { api } from '../api/endpoints'
import { errorMessage, securityMutationPending } from '../api/client'
import { clearSession, currentUser, forcedMfa, isAdmin } from '../lib/session'
import { provideToggle } from '../lib/queries'
import { theme, themeLabels, type ThemePreference } from '../lib/theme'
import { toast } from '../lib/toast'

provideToggle()
const route = useRoute()
const router = useRouter()
const palette = ref(false)
const signingOut = ref(false)
const isMac = /Mac|iPhone|iPad/.test(navigator.platform)

const nav = computed(() => [
  { to: '/', label: '总览', icon: LayoutGrid, match: (name: unknown) => name === 'overview' },
  { to: '/rules', label: '转发', icon: ArrowRightLeft, match: (name: unknown) => typeof name === 'string' && name.startsWith('rule') },
  ...(isAdmin.value ? [
    { to: '/accounts', label: '账户', icon: Users, match: (name: unknown) => typeof name === 'string' && name.startsWith('account') },
    { to: '/audit', label: '审计', icon: ScrollText, match: (name: unknown) => name === 'audit' },
  ] : []),
].filter(() => !forcedMfa.value))
const mobileNav = computed(() => [...nav.value, { to: '/settings', label: '设置', icon: Settings, match: (name: unknown) => name === 'settings' }])
const initials = computed(() => (currentUser.value?.username ?? '?').slice(0, 2).toUpperCase())

async function signOut() {
  if (signingOut.value || securityMutationPending.value) return
  signingOut.value = true
  try {
    await api.logout()
    clearSession()
    await router.replace({ name: 'login' })
  } catch (error) {
    toast('退出失败', { description: errorMessage(error), tone: 'danger' })
  } finally { signingOut.value = false }
}

function typing(target: EventTarget | null) {
  const element = target as HTMLElement | null
  return !!element && (element.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(element.tagName))
}
useEventListener(window, 'keydown', (event: KeyboardEvent) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    if (!forcedMfa.value) palette.value = !palette.value
    return
  }
  if (event.metaKey || event.ctrlKey || event.altKey || typing(event.target) || document.querySelector('[role="dialog"]')) return
  if (forcedMfa.value) return
  if (event.key === 'n') { event.preventDefault(); router.push('/rules/new') }
  else if (event.key === '/') {
    event.preventDefault()
    if (route.name === 'rules') window.dispatchEvent(new Event('relaydeck:focus-search'))
    else router.push({ path: '/rules', query: { focus: '1' } })
  }
})
</script>

<template>
  <div class="min-h-dvh">
    <a href="#main" class="sr-only z-[100] rounded-md bg-surface px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2">跳至内容</a>
    <header class="sticky top-0 z-40 border-b border-line bg-surface/85 pt-[env(safe-area-inset-top)] backdrop-blur-md backdrop-saturate-150">
      <div class="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 md:px-6">
        <RouterLink to="/" class="flex items-center gap-2.5 rounded-md font-semibold tracking-[-0.01em] text-fg" aria-label="RelayDeck 总览">
          <BrandMark />
          <span class="max-sm:hidden">RelayDeck</span>
        </RouterLink>
        <nav aria-label="主导航" class="flex h-full items-stretch gap-1 max-md:hidden">
          <RouterLink
            v-for="item in nav" :key="item.to" :to="item.to"
            class="relative flex items-center px-2.5 text-muted transition-colors duration-150 hover:text-fg"
            :class="item.match(route.name) ? 'font-medium !text-fg after:absolute after:inset-x-2.5 after:-bottom-px after:h-0.5 after:rounded-full after:bg-fg' : ''"
            :aria-current="item.match(route.name) ? 'page' : undefined"
          >{{ item.label }}</RouterLink>
        </nav>
        <div class="ml-auto flex items-center gap-2">
          <span class="max-sm:hidden"><ExecutorStatus /></span>
          <span class="sm:hidden"><ExecutorStatus compact /></span>
          <button
            v-if="!forcedMfa" type="button" class="btn btn-secondary btn-sm text-muted max-md:w-8 max-md:px-0 md:w-52 md:justify-start" aria-label="搜索或执行命令"
            @click="palette = true"
          >
            <Search class="size-4" aria-hidden="true" />
            <span class="max-md:hidden">搜索或跳转…</span>
            <span class="ml-auto flex gap-0.5 max-md:hidden"><span class="kbd">{{ isMac ? '⌘' : 'Ctrl' }}</span><span class="kbd">K</span></span>
          </button>
          <DropdownMenuRoot>
            <DropdownMenuTrigger class="flex size-8 items-center justify-center rounded-full border border-line bg-surface-2 text-xs font-semibold text-fg hover:border-line-strong" aria-label="账户菜单">
              {{ initials }}
            </DropdownMenuTrigger>
            <DropdownMenuPortal>
              <DropdownMenuContent align="end" :side-offset="8" class="anim-pop pop w-56">
                <DropdownMenuLabel class="px-2 py-1.5">
                  <span class="block truncate font-medium text-fg">{{ currentUser?.username }}</span>
                  <span class="text-xs text-muted">{{ isAdmin ? '管理员' : '租户' }}</span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator class="pop-sep" />
                <DropdownMenuItem class="pop-item" @select="router.push('/settings')"><Settings class="size-4 text-muted" />设置</DropdownMenuItem>
                <DropdownMenuSeparator class="pop-sep" />
                <DropdownMenuLabel class="pop-label">主题</DropdownMenuLabel>
                <DropdownMenuRadioGroup v-model="theme">
                  <DropdownMenuRadioItem v-for="(label, value) in themeLabels" :key="value" :value="value as ThemePreference" class="pop-item pl-8 relative" @select.prevent>
                    <DropdownMenuItemIndicator class="absolute left-2"><Check class="size-4" /></DropdownMenuItemIndicator>
                    {{ label }}
                  </DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
                <DropdownMenuSeparator class="pop-sep" />
                <DropdownMenuItem class="pop-item" :disabled="signingOut || securityMutationPending" @select="signOut"><LogOut class="size-4 text-muted" />退出登录</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenuPortal>
          </DropdownMenuRoot>
        </div>
      </div>
    </header>

    <div v-if="forcedMfa" class="border-b border-warning/30 bg-warning-soft">
      <p class="mx-auto flex max-w-6xl items-center gap-2 px-4 py-2.5 text-sm text-fg md:px-6">
        <ShieldAlert class="size-4 text-warning" aria-hidden="true" />
        管理员必须先启用双因素验证，完成后才能使用其他功能。
      </p>
    </div>

    <main id="main" tabindex="-1" class="mx-auto max-w-6xl px-4 pt-6 pb-[calc(5.5rem+env(safe-area-inset-bottom))] outline-none md:px-6 md:pt-8 md:pb-16">
      <RouterView />
    </main>

    <nav aria-label="主导航" class="fixed inset-x-0 bottom-0 z-40 border-t border-line bg-surface/90 pb-[env(safe-area-inset-bottom)] backdrop-blur-md md:hidden">
      <div class="grid h-14" :style="{ gridTemplateColumns: `repeat(${mobileNav.length}, minmax(0, 1fr))` }">
        <RouterLink
          v-for="item in mobileNav" :key="item.to" :to="item.to"
          class="flex flex-col items-center justify-center gap-0.5 text-xs text-muted"
          :class="item.match(route.name) ? '!text-fg font-medium' : ''" :aria-current="item.match(route.name) ? 'page' : undefined"
        >
          <component :is="item.icon" class="size-5" aria-hidden="true" />
          {{ item.label }}
        </RouterLink>
      </div>
    </nav>

    <CommandPalette v-model:open="palette" />
  </div>
</template>
