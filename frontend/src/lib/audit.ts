import type { Audit } from '../types'

export type AuditCategory = 'rule' | 'account' | 'security'

const phrases: Record<string, { verb: string; category: AuditCategory; self?: boolean }> = {
  panel_upgrade_requested: { verb: '申请了面板升级', category: 'security', self: true },
  panel_upgrade_password_failed: { verb: '升级密码验证失败', category: 'security', self: true },
  panel_upgrade_mfa_failed: { verb: '升级验证失败', category: 'security', self: true },
  login: { verb: '登录了控制台', category: 'security', self: true },
  login_failed: { verb: '登录失败', category: 'security', self: true },
  login_mfa_failed: { verb: '两步验证失败', category: 'security', self: true },
  mfa_confirmation_failed: { verb: '绑定两步验证失败', category: 'security', self: true },
  mfa_disable_failed: { verb: '关闭两步验证失败', category: 'security', self: true },
  password_changed: { verb: '修改了自己的密码', category: 'security', self: true },
  mfa_setup: { verb: '开始设置两步验证', category: 'security', self: true },
  mfa_enabled: { verb: '开启了两步验证', category: 'security', self: true },
  mfa_disabled: { verb: '关闭了两步验证', category: 'security', self: true },
  rule_created: { verb: '创建了转发', category: 'rule' },
  rule_updated: { verb: '修改了转发', category: 'rule' },
  rule_deleted: { verb: '删除了转发', category: 'rule' },
  rule_dns_updated: { verb: '目标地址已刷新', category: 'rule' },
  rule_dns_restored: { verb: '目标已恢复', category: 'rule' },
  rule_dns_blocked: { verb: '目标已阻断', category: 'rule' },
  user_traffic_blocked: { verb: '已阻断流量', category: 'account' },
  user_traffic_restored: { verb: '已恢复流量', category: 'account' },
  user_created: { verb: '创建了账户', category: 'account' },
  user_updated: { verb: '调整了账户授权', category: 'account' },
  password_reset: { verb: '重置了账户密码', category: 'account' },
  apply_retry: { verb: '重试了生效', category: 'rule' },
}

export function describeAudit(entry: Audit) {
  const phrase = phrases[entry.action] ?? { verb: `执行了 ${entry.action}`, category: 'security' as AuditCategory }
  const object = phrase.self || entry.resource_id === null ? null : {
    name: entry.resource_name ?? `#${entry.resource_id}`,
    port: entry.resource_port,
    to: entry.resource_kind === 'rule' && entry.action !== 'rule_deleted' ? `/rules/${entry.resource_id}` : entry.resource_kind === 'user' ? `/accounts/${entry.resource_id}` : null,
  }
  return { verb: entry.failure_count > 0 ? `${phrase.verb}（${entry.failure_count} 次）` : phrase.verb, category: phrase.category, object }
}
