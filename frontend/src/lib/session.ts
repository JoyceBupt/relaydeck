import { computed, reactive } from 'vue'
import { ApiError, setCsrfToken } from '../api/client'
import { api } from '../api/endpoints'
import type { Session } from '../types'
import { queryClient } from './queryClient'
import { toasts } from './toast'

interface SessionState {
  session: Session | null
  loaded: boolean
  /** Message shown on the sign-in page after a forced sign-out. */
  notice: string
  /** One-time recovery codes; held in memory only until the viewer confirms saving them. */
  recoveryCodes: string[]
  epoch: number
}

export const sessionState = reactive<SessionState>({ session: null, loaded: false, notice: '', recoveryCodes: [], epoch: 0 })

export const currentUser = computed(() => sessionState.session?.user ?? null)
export const isAdmin = computed(() => currentUser.value?.role === 'admin')
export const mustChangePassword = computed(() => !!currentUser.value?.must_change_password)
export const forcedMfa = computed(() => !!sessionState.session?.mfa_required && !sessionState.session.user.mfa_enabled)

export function acceptSession(session: Session) {
  sessionState.session = session
  sessionState.notice = ''
  setCsrfToken(session.csrf_token)
}

/** Drop every trace of the session: identity, CSRF token and all cached server data. */
export function clearSession(notice = '') {
  sessionState.epoch += 1
  sessionState.session = null
  sessionState.notice = notice
  setCsrfToken('')
  queryClient.cancelQueries()
  queryClient.clear()
  // Notifications can name rules and accounts; never carry them into the next session.
  toasts.splice(0)
}

export async function loadSession() {
  if (sessionState.loaded) return
  try {
    acceptSession(await api.session())
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) sessionState.notice = error instanceof Error ? error.message : ''
  } finally {
    sessionState.loaded = true
  }
}

/** Re-read identity (quota counts, revisions) without letting a stale answer revive an old session. */
export async function refreshIdentity() {
  const epoch = sessionState.epoch
  try {
    const identity = await api.session()
    if (epoch === sessionState.epoch && sessionState.session) acceptSession(identity)
  } catch { /* the request layer already handles expiry */ }
}
