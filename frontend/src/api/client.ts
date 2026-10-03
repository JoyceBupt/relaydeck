import { ref } from 'vue'

export const securityMutationPending = ref(false)
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message) }
}

let csrfToken = ''
let sessionGeneration = 0
let mutationGeneration = 0

export function setCsrfToken(token: string) {
  if (token !== csrfToken) sessionGeneration += 1
  csrfToken = token
}

/** Errors that only mean "this response belongs to an older state"; never shown to people. */
export function isStaleError(error: unknown) {
  return error instanceof ApiError && (error.code === 'stale_session' || error.code === 'stale_read')
}

export async function request<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  if (securityMutationPending.value && path !== '/health') {
    throw new ApiError(409, method === 'GET' ? 'stale_read' : 'security_pending', '安全设置正在保存')
  }
  const security = method !== 'GET' && ['/password', '/mfa/confirm', '/mfa/disable'].includes(path)
  if (security) securityMutationPending.value = true
  try {
  if (method !== 'GET') mutationGeneration += 1
  const generation = sessionGeneration
  const mutation = mutationGeneration
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (data !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      method, headers, credentials: 'same-origin',
      body: data === undefined ? undefined : JSON.stringify(data),
    })
  } catch {
    throw new ApiError(0, 'network_error', '连接失败，请检查网络后重试')
  }
  const text = await response.text()
  // A delayed response from an earlier session must neither restore its data
  // nor revoke a newer session after logout or reauthentication.
  if (generation !== sessionGeneration) throw new ApiError(0, 'stale_session', '会话已变更')
  // A read that began before an MFA/password mutation cannot expire the UI
  // before that mutation's response delivers recovery codes or final state.
  if (method === 'GET' && mutation !== mutationGeneration) throw new ApiError(0, 'stale_read', '数据已变更')
  if (response.status === 401 && path !== '/login' && !securityMutationPending.value) {
    window.dispatchEvent(new Event('relaydeck:session-expired'))
  }
  let value: unknown
  if (text) {
    try { value = JSON.parse(text) } catch { throw new ApiError(response.status, 'invalid_response', '服务器响应异常，请稍后重试') }
  }
  if (!response.ok) {
    const error = value as { error?: { code?: string; message?: string } } | undefined
    throw new ApiError(response.status, error?.error?.code || 'request_error', error?.error?.message || '操作失败，请重试')
  }
  return value as T
  } finally {
    if (security) securityMutationPending.value = false
  }
}

export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : '操作失败，请重试'
}
