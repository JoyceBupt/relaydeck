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
  const generation = sessionGeneration
  const changesCookie = method !== 'GET' && ['/login', '/logout', '/password', '/mfa/confirm', '/mfa/disable'].includes(path)
  const execute = () => {
    if (generation !== sessionGeneration) throw new ApiError(0, 'stale_session', '会话已变更')
    return performRequest<T>(path, method, data)
  }
  if (changesCookie && typeof window !== 'undefined' && window.document && typeof navigator !== 'undefined' && navigator.locks) {
    return navigator.locks.request('relaydeck-authentication', execute)
  }
  return execute()
}

async function performRequest<T>(path: string, method: string, data?: unknown): Promise<T> {
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
  if (method === 'GET' && path !== '/session' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  if (data !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken
  const controller = new AbortController()
  const deadline = setTimeout(() => controller.abort(), 30_000)
  let response: Response
  let text: string
  try {
    response = await fetch(`/api${path}`, {
      method, headers, credentials: 'same-origin', signal: controller.signal,
      body: data === undefined ? undefined : JSON.stringify(data),
    })
    text = await response.text()
  } catch {
    if (generation !== sessionGeneration) throw new ApiError(0, 'stale_session', '会话已变更')
    if (controller.signal.aborted) throw new ApiError(0, 'request_timeout', '请求超时')
    throw new ApiError(0, 'network_error', '无法连接服务器')
  } finally { clearTimeout(deadline) }
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
    try { value = JSON.parse(text) } catch { throw new ApiError(response.status, 'invalid_response', '服务器响应异常') }
  }
  if (!response.ok) {
    const error = value as { error?: { code?: string; message?: string } } | undefined
    throw new ApiError(response.status, error?.error?.code || 'request_error', error?.error?.message || '操作失败')
  }
  return value as T
  } finally {
    if (security) securityMutationPending.value = false
  }
}

export function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : '操作失败'
}
