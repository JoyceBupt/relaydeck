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
  recoveryOwner: number | null
  epoch: number
}

export const sessionState = reactive<SessionState>({ session: null, loaded: false, notice: '', recoveryCodes: [], recoveryOwner: null, epoch: 0 })

export const currentUser = computed(() => sessionState.session?.user ?? null)
export const isAdmin = computed(() => currentUser.value?.role === 'admin')
export const mustChangePassword = computed(() => !!currentUser.value?.must_change_password)
export const forcedMfa = computed(() => !!sessionState.session?.mfa_required && !sessionState.session.user.mfa_enabled)

const channel = typeof window !== 'undefined' && window.document && 'BroadcastChannel' in window ? new BroadcastChannel('relaydeck-session') : null
channel?.addEventListener('message', event => {
  if (event.data?.type !== 'changed' || event.data.ref === sessionState.session?.session_ref) return
  if (!sessionState.session && !sessionState.recoveryCodes.length) return
  clearSession('其他标签页切换了账户', false)
  window.dispatchEvent(new Event('relaydeck:session-changed'))
})

export function acceptSession(session: Session, login = false) {
  const previous = sessionState.session
  if (previous && previous.user.id !== session.user.id && !login) {
    clearSession('账户已切换', false)
    window.dispatchEvent(new Event('relaydeck:session-changed'))
    return
  }
  if (previous?.csrf_token !== session.csrf_token) clearSession('', false)
  sessionState.session = session
  sessionState.notice = ''
  setCsrfToken(session.csrf_token)
  if (login || (previous && previous.session_ref !== session.session_ref)) channel?.postMessage({ type: 'changed', ref: session.session_ref })
}

/** Drop every trace of the session: identity, CSRF token and all cached server data. */
export function clearSession(notice = '', broadcast = true) {
  sessionState.epoch += 1
  sessionState.session = null
  sessionState.notice = notice
  clearRecoveryCodes()
  setCsrfToken('')
  queryClient.cancelQueries()
  queryClient.clear()
  // Notifications can name rules and accounts; never carry them into the next session.
  toasts.splice(0)
  if (broadcast) channel?.postMessage({ type: 'changed', ref: null })
}

export function clearRecoveryCodes() {
  sessionState.recoveryCodes = []
  sessionState.recoveryOwner = null
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
