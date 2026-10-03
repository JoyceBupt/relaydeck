export type ViewMode = 'table' | 'cards'
export type Protocol = 'tcp' | 'udp' | 'both'
export type RuntimeStatus = 'pending' | 'active' | 'stopped' | 'failed' | 'blocked'
export type ExecutorState = 'unconfigured' | 'running' | 'offline'

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

export interface Session { user: User; csrf_token: string; session_ref: string; mfa_required: boolean }
export interface MfaEnrollment { secret: string; otpauth_uri: string }
export interface Health { status: string; name: string; version: string; executor: ExecutorState }

export interface Rule {
  id: number
  owner_id: number
  owner_username: string
  name: string
  listen_port: number
  target_host: string
  target_ip: string
  target_port: number
  protocol: Protocol
  source_cidrs: string[]
  enabled: boolean
  runtime_status: RuntimeStatus
  dns_error: string | null
  runtime_error: string | null
  runtime_updated_at: number | null
  created_at: number
  updated_at: number
}

export interface RuleInput {
  owner_id?: number
  name: string
  listen_port: number
  target_host: string
  target_port: number
  protocol: Protocol
  source_cidrs: string[]
  enabled: boolean
}

export interface Audit {
  failure_count: number
  id: number
  actor_username: string
  action: string
  resource_id: number | null
  resource_kind: 'rule' | 'user' | null
  resource_name: string | null
  resource_port: number | null
  created_at: number
}

export interface PortUsage {
  owner_id: number
  port_start: number
  port_end: number
  reserved: number[]
  leases: { port: number; rule_id: number; state: 'active' | 'releasing' }[]
}

export interface UserGrantInput {
  enabled: boolean
  port_start: number
  port_end: number
  max_rules: number
  expires_at: number | null
}

export interface NewUserInput {
  username: string
  password: string
  port_start: number
  port_end: number
  max_rules: number
  expires_at: number | null
}
