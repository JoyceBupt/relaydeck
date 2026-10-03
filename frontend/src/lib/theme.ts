import { ref, watch } from 'vue'

export type ThemePreference = 'system' | 'light' | 'dark'
const KEY = 'relaydeck-theme'

function read(): ThemePreference {
  try {
    const value = localStorage.getItem(KEY)
    return value === 'light' || value === 'dark' ? value : 'system'
  } catch { return 'system' }
}

export const theme = ref<ThemePreference>(read())

function apply(value: ThemePreference) {
  const root = document.documentElement
  if (value === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', value)
}

apply(theme.value)
watch(theme, value => {
  apply(value)
  try { if (value === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, value) } catch { /* per-viewer convenience only */ }
})

export const themeLabels: Record<ThemePreference, string> = { system: '跟随系统', light: '浅色', dark: '深色' }
