<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useEventListener } from '@vueuse/core'
import { DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuPortal, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuItemIndicator, DropdownMenuRoot, DropdownMenuSeparator, DropdownMenuTrigger } from 'reka-ui'
import { ArrowRightLeft, Check, LayoutGrid, LogOut, ScrollText, Settings, Users } from '@lucide/vue'
import BrandMark from './BrandMark.vue'
import ExecutorStatus from './ExecutorStatus.vue'
import { api } from '../api/endpoints'
import { errorMessage, securityMutationPending } from '../api/client'
import { clearSession, currentUser, forcedMfa, isAdmin } from '../lib/session'
import { provideToggle } from '../lib/queries'
import { theme, themeLabels, type ThemePreference } from '../lib/theme'
import { toast } from '../lib/toast'

provideToggle()
const route = useRoute()
const router = useRouter()
const signingOut = ref(false)
// The main pane, not the window, scrolls. Start each section at the top, but keep
// the list in place while its drawer opens (/rules -> /rules/4).
const scroller = ref<HTMLElement | null>(null)
watch(() => route.path.split('/')[1], () => scroller.value?.scrollTo({ top: 0 }))

const nav = computed(() => (forcedMfa.value ? [] : [
  { to: '/', label: '总览', icon: LayoutGrid, match: (name: unknown) => name === 'overview' },
  { to: '/rules', label: '转发', icon: ArrowRightLeft, match: (name: unknown) => typeof name === 'string' && name.startsWith('rule') },
  ...(isAdmin.value ? [
    { to: '/accounts', label: '账户', icon: Users, match: (name: unknown) => typeof name === 'string' && name.startsWith('account') },
    { to: '/audit', label: '审计', icon: ScrollText, match: (name: unknown) => name === 'audit' },
  ] : []),
  { to: '/settings', label: '设置', icon: Settings, match: (name: unknown) => name === 'settings' },
]))
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
// N opens a new rule, / jumps to the rule search. Nothing else is bound globally.
useEventListener(window, 'keydown', (event: KeyboardEvent) => {
  if (event.metaKey || event.ctrlKey || event.altKey || typing(event.target) || document.querySelector('[role="dialog"]') || forcedMfa.value) return
  if (event.key === 'n') { event.preventDefault(); router.push('/rules/new') }
  else if (event.key === '/') {
    event.preventDefault()
    if (route.name === 'rules') window.dispatchEvent(new Event('relaydeck:focus-search'))
    else router.push({ path: '/rules', query: { focus: '1' } })
  }
})
</script>

<template>
  <!-- VS Code style frame: rounded, outlined panes with the canvas showing through the gaps. -->
  <div class="flex h-dvh flex-col gap-2 p-2 pt-[max(0.5rem,env(safe-area-inset-top))] md:gap-3 md:p-3">
    <a href="#main" class="sr-only z-[100] rounded-lg bg-surface px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2">跳至内容</a>

    <header class="pane flex h-14 shrink-0 items-center gap-4 px-3 md:px-4">
      <RouterLink to="/" class="flex items-center gap-2.5 rounded-lg font-semibold text-fg" aria-label="RelayDeck 总览">
        <BrandMark /><span class="max-sm:hidden">RelayDeck</span>
      </RouterLink>
      <nav v-if="nav.length" aria-label="主导航" class="flex items-center gap-1 max-md:hidden">
        <RouterLink
          v-for="item in nav" :key="item.to" :to="item.to"
          class="flex h-8 items-center gap-2 rounded-lg px-3 text-muted transition-colors duration-200 hover:text-fg"
          :class="item.match(route.name) ? 'bg-fill font-medium !text-fg' : 'hover:bg-fill/60'"
          :aria-current="item.match(route.name) ? 'page' : undefined"
        >
          <component :is="item.icon" class="size-4" :class="item.match(route.name) ? 'text-accent' : ''" aria-hidden="true" />
          {{ item.label }}
        </RouterLink>
      </nav>
      <div class="ml-auto flex items-center gap-2">
        <span class="max-sm:hidden"><ExecutorStatus /></span>
        <span class="sm:hidden"><ExecutorStatus compact /></span>
        <DropdownMenuRoot>
          <DropdownMenuTrigger class="flex size-8 items-center justify-center rounded-full bg-accent-soft text-xs font-semibold text-accent transition-colors hover:bg-fill-hover data-[state=open]:bg-fill-hover" aria-label="账户菜单">
            {{ initials }}
          </DropdownMenuTrigger>
          <DropdownMenuPortal>
            <DropdownMenuContent align="end" :side-offset="8" class="anim-pop pop w-56">
              <DropdownMenuLabel class="px-2.5 py-1.5">
                <span class="block truncate font-medium text-fg">{{ currentUser?.username }}</span>
                <span class="text-xs text-muted">{{ isAdmin ? '管理员' : '租户' }}</span>
              </DropdownMenuLabel>
              <DropdownMenuSeparator class="pop-sep" />
              <DropdownMenuLabel class="pop-label">外观</DropdownMenuLabel>
              <DropdownMenuRadioGroup v-model="theme">
                <DropdownMenuRadioItem v-for="(label, value) in themeLabels" :key="value" :value="value as ThemePreference" class="pop-item relative pl-8" @select.prevent>
                  <DropdownMenuItemIndicator class="absolute left-2.5"><Check class="size-4 text-accent" /></DropdownMenuItemIndicator>
                  {{ label }}
                </DropdownMenuRadioItem>
              </DropdownMenuRadioGroup>
              <DropdownMenuSeparator class="pop-sep" />
              <DropdownMenuItem class="pop-item is-danger" :disabled="signingOut || securityMutationPending" @select="signOut"><LogOut class="size-4" />退出登录</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenuPortal>
        </DropdownMenuRoot>
      </div>
    </header>

    <div ref="scroller" class="pane min-h-0 flex-1 overflow-y-auto overscroll-contain">
      <main id="main" tabindex="-1" class="mx-auto max-w-6xl px-4 pt-5 pb-24 outline-none md:px-8 md:pt-8 md:pb-12">
        <RouterView />
      </main>
    </div>

    <!-- Phone: a floating tab bar pane. -->
    <nav v-if="nav.length" aria-label="主导航" class="fixed inset-x-2 bottom-[max(0.5rem,env(safe-area-inset-bottom))] z-40 rounded-2xl border border-line bg-[var(--material)] shadow-[var(--shadow-pop)] backdrop-blur-xl backdrop-saturate-150 md:hidden">
      <div class="grid h-14" :class="nav.length === 5 ? 'grid-cols-5' : 'grid-cols-3'">
        <RouterLink
          v-for="item in nav" :key="item.to" :to="item.to"
          class="flex flex-col items-center justify-center gap-0.5 text-[0.6875rem] text-muted"
          :class="item.match(route.name) ? '!text-accent font-medium' : ''" :aria-current="item.match(route.name) ? 'page' : undefined"
        >
          <component :is="item.icon" class="size-5" aria-hidden="true" />
          {{ item.label }}
        </RouterLink>
      </div>
    </nav>
  </div>
</template>
