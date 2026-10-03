/** The executor provisions a fixed pool of runtime identities; one is the administrator. */
export const MAX_TENANTS = 10

import type { Protocol, Rule, RuntimeStatus } from '../types'

const DAY = 86_400

export function nowSeconds() { return Math.floor(Date.now() / 1000) }

export function hostText(host: string) { return host.includes(':') ? `[${host}]` : host }
export function targetText(rule: Pick<Rule, 'target_host' | 'target_port'>) { return `${hostText(rule.target_host)}:${rule.target_port}` }

export const protocolLabels: Record<Protocol, string> = { tcp: 'TCP', udp: 'UDP', both: 'TCP + UDP' }

export const statusLabels: Record<RuntimeStatus, string> = { active: '运行中', pending: '同步中', failed: '失败', stopped: '已停用', blocked: '已阻断' }

export function dateTime(value: number) {
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(value * 1000))
}

export function clock(value: number) {
  return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(value * 1000))
}

export function dateOnly(value: number) {
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' }).format(new Date(value * 1000))
}

export function relative(value: number, now = nowSeconds()) {
  const delta = now - value
  if (delta < 45) return '刚刚'
  if (delta < 3600) return `${Math.round(delta / 60)} 分钟前`
  if (delta < DAY) return `${Math.round(delta / 3600)} 小时前`
  if (delta < 30 * DAY) return `${Math.round(delta / DAY)} 天前`
  return dateOnly(value)
}

export type ExpiryTone = 'none' | 'ok' | 'soon' | 'expired'
export function expiry(expiresAt: number | null, now = nowSeconds()): { text: string; tone: ExpiryTone; days: number | null } {
  if (expiresAt === null) return { text: '长期有效', tone: 'none', days: null }
  const days = Math.ceil((expiresAt - now) / DAY)
  if (expiresAt <= now) return { text: '已到期', tone: 'expired', days: 0 }
  if (days <= 7) return { text: days <= 1 ? '今天到期' : `${days} 天后到期`, tone: 'soon', days }
  return { text: `${dateOnly(expiresAt)} 到期`, tone: 'ok', days }
}

/** Local date input (YYYY-MM-DD) for a Unix timestamp. */
export function dateInputValue(value: number | null) {
  if (value === null) return ''
  const date = new Date(value * 1000)
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
}

/** End of the chosen local day, so "到期日" includes that whole day. */
export function expiryFromDateInput(value: string) {
  return value ? Math.floor(new Date(`${value}T23:59:59`).getTime() / 1000) : null
}

export function sourcesText(cidrs: string[]) {
  if (!cidrs.length) return '不限来源'
  return cidrs.length === 1 ? cidrs[0] : `${cidrs[0]} 等 ${cidrs.length} 个网段`
}
