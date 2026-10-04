import { request } from './client'
import type { Audit, UpgradeStatus, Health, MfaEnrollment, NewUserInput, PortUsage, Rule, RuleCheck, RuleInput, Session, TrafficView, User, UserGrantInput, ViewMode } from '../types'

export const api = {
  session: () => request<Session>('/session'),
  login: (username: string, password: string, code?: string) =>
    request<Session>('/login', 'POST', { username, password, code: code || undefined }),
  logout: () => request<void>('/logout', 'POST'),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('/password', 'PUT', { current_password, new_password }),
  setPreference: (view_mode: ViewMode) => request<{ view_mode: ViewMode }>('/preferences', 'PUT', { view_mode }),

  beginMfa: (password: string) => request<MfaEnrollment>('/mfa/setup', 'POST', { password }),
  confirmMfa: (code: string) => request<{ recovery_codes: string[] }>('/mfa/confirm', 'POST', { code }),
  disableMfa: (password: string, code: string) => request<void>('/mfa/disable', 'POST', { password, code }),

  upgradeStatus: () => request<UpgradeStatus>('/system/update'),
  checkUpgrade: () => request<UpgradeStatus>('/system/update/check', 'POST'),
  startUpgrade: (input: { offer: string; password: string; code: string; acknowledge: boolean }) => request<UpgradeStatus>('/system/update', 'POST', input),

  health: () => request<Health>('/health'),
  rules: () => request<Rule[]>('/rules'),
  createRule: (input: RuleInput) => request<Rule>('/rules', 'POST', input),
  updateRule: (id: number, input: RuleInput) => request<Rule>(`/rules/${id}`, 'PUT', input),
  deleteRule: (id: number) => request<{ status: string }>(`/rules/${id}`, 'DELETE'),
  checkRule: (id: number) => request<RuleCheck>(`/rules/${id}/check`, 'POST'),
  retryApply: (ownerId: number) => request<void>(`/users/${ownerId}/apply`, 'POST'),
  ports: (ownerId: number) => request<PortUsage>(`/users/${ownerId}/ports`),
  traffic: (ownerId: number) => request<TrafficView>(`/users/${ownerId}/traffic`),

  users: () => request<User[]>('/users'),
  createUser: (input: NewUserInput) => request<User>('/users', 'POST', input),
  updateUser: (id: number, input: UserGrantInput) => request<User>(`/users/${id}`, 'PUT', input),
  resetPassword: (id: number, password: string) => request<void>(`/users/${id}/password`, 'POST', { password }),
  audit: () => request<Audit[]>('/audit'),
}

export function ruleInput(rule: Rule, patch: Partial<RuleInput> = {}): RuleInput {
  return {
    name: rule.name, listen_port: rule.listen_port, target_host: rule.target_host, target_port: rule.target_port,
    protocol: rule.protocol, source_cidrs: rule.source_cidrs, enabled: rule.enabled, ...patch,
  }
}
