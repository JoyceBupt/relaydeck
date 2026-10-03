import { createApp } from 'vue'
import { VueQueryPlugin } from '@tanstack/vue-query'
import App from './App.vue'
import { router } from './router'
import { queryClient } from './lib/queryClient'
import { clearSession, sessionState } from './lib/session'
import './lib/theme'
import './styles.css'

window.addEventListener('relaydeck:session-expired', () => {
  if (!sessionState.session) return
  clearSession('登录已过期', false)
  router.replace({ name: 'login' })
})
window.addEventListener('relaydeck:session-changed', () => router.replace({ name: 'login' }))

createApp(App).use(VueQueryPlugin, { queryClient }).use(router).mount('#app')
