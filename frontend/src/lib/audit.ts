import type { Audit } from '../types'

export type AuditCategory = 'rule' | 'account' | 'security'

const phrases: Record<string, { verb: string; category: AuditCategory; self?: boolean }> = {
  login: { verb: '登录了控制台', category: 'security', self: true },
  login_failed: { verb: '密码登录失败', category: 'security', self: true },
  login_mfa_failed: { verb: '双因素登录失败', category: 'security', self: true },
  mfa_confirmation_failed: { verb: '绑定验证失败', category: 'security', self: true },
  mfa_disable_failed: { verb: '停用验证失败', category: 'security', self: true },
  password_changed: { verb: '修改了自己的密码', category: 'security', self: true },
  mfa_setup: { verb: '开始设置双因素验证', category: 'security', self: true },
  mfa_enabled: { verb: '启用了双因素验证', category: 'security', self: true },
  mfa_disabled: { verb: '停用了双因素验证', category: 'security', self: true },
  rule_created: { verb: '创建了转发', category: 'rule' },
  rule_updated: { verb: '修改了转发', category: 'rule' },
  rule_deleted: { verb: '删除了转发', category: 'rule' },
  rule_dns_updated: { verb: '目标地址已刷新', category: 'rule' },
  rule_dns_restored: { verb: '目标已恢复', category: 'rule' },
  rule_dns_blocked: { verb: '目标已阻断', category: 'rule' },
  user_created: { verb: '创建了账户', category: 'account' },
  user_updated: { verb: '调整了账户授权', category: 'account' },
  password_reset: { verb: '重置了账户密码', category: 'account' },
  apply_retry: { verb: '为账户重新提交生效', category: 'rule' },
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
