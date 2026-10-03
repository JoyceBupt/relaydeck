export type ViewMode = 'table' | 'cards'
export interface User {
  id: number
  username: string
  role: 'admin' | 'user'
  enabled: boolean
  must_change_password: boolean
  expires_at: number | null
  port_start: number
  port_end: number
  max_rules: number
  rule_count: number
  view_mode: ViewMode
  desired_revision: number
  applied_revision: number
  mfa_enabled: boolean
}
export interface Session { user: User; csrf_token: string; mfa_required: boolean }
export interface MfaEnrollment { secret: string; otpauth_uri: string }
export interface Health { status: string; name: string; version: string; executor: string }
export interface Rule {
  id: number
  owner_id: number
  owner_username: string
  name: string
  listen_port: number
  target_host: string
  target_ip: string
  target_port: number
  protocol: 'tcp' | 'udp' | 'both'
  source_cidrs: string[]
  enabled: boolean
  runtime_status: 'pending' | 'active' | 'stopped' | 'failed'
  created_at: number
  updated_at: number
}
export interface Audit {
  id: number
  actor_username: string
  action: string
  resource_id: number | null
  created_at: number
}
export interface RuleInput {
  owner_id?: number
  name: string
  listen_port: number
  target_host: string
  target_port: number
  protocol: Rule['protocol']
  source_cidrs: string[]
  enabled: boolean
}
