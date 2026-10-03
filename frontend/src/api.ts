export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message) }
}

let csrfToken = ''
let sessionGeneration = 0
export function setCsrfToken(token: string) {
  if (token !== csrfToken) sessionGeneration += 1
  csrfToken = token
}

export async function request<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const generation = sessionGeneration
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
    throw new ApiError(0, 'network_error', '连接失败，请重试')
  }
  const text = await response.text()
  // A delayed response from an earlier session must neither restore its data
  // nor revoke a newer session after logout or reauthentication.
  if (generation !== sessionGeneration) throw new ApiError(0, 'stale_session', '会话已变更')
  if (response.status === 401 && path !== '/login') {
    window.dispatchEvent(new Event('relaydeck:session-expired'))
  }
  let value: unknown
  if (text) {
    try { value = JSON.parse(text) } catch { throw new ApiError(response.status, 'invalid_response', '响应异常，请重试') }
  }
  if (!response.ok) {
    const error = value as { error?: { code?: string; message?: string } } | undefined
    throw new ApiError(response.status, error?.error?.code || 'request_error', error?.error?.message || '操作失败，请重试')
  }
  return value as T
}
