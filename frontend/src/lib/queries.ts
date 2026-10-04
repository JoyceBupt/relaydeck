import { computed, type MaybeRefOrGetter, toValue } from 'vue'
import { useDocumentVisibility } from '@vueuse/core'
import { useMutation, useQuery } from '@tanstack/vue-query'
import { api, ruleInput } from '../api/endpoints'
import type { Rule, RuleInput } from '../types'
import { ApiError, errorMessage, isStaleError, securityMutationPending } from '../api/client'
import { isAdmin, refreshIdentity, sessionState } from './session'
import { queryClient } from './queryClient'
import { toast } from './toast'

export const keys = {
  rules: ['rules'] as const,
  users: ['users'] as const,
  health: ['health'] as const,
  audit: ['audit'] as const,
  ports: (id: number) => ['ports', id] as const,
}

const visibility = useDocumentVisibility()
const signedIn = computed(() => !!sessionState.session && !securityMutationPending.value)
const poll = (ms: number) => () => (visibility.value === 'visible' ? ms : false)

export function useHealth() {
  return useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: poll(10_000) })
}

export function useRules() {
  return useQuery({ queryKey: keys.rules, queryFn: api.rules, enabled: signedIn, refetchInterval: poll(5_000) })
}

export function useUsers() {
  return useQuery({ queryKey: keys.users, queryFn: api.users, enabled: computed(() => signedIn.value && isAdmin.value), refetchInterval: poll(15_000) })
}

export function useAudit() {
  return useQuery({ queryKey: keys.audit, queryFn: api.audit, enabled: computed(() => signedIn.value && isAdmin.value), refetchInterval: poll(30_000) })
}

export function usePorts(ownerId: MaybeRefOrGetter<number | null | undefined>) {
  return useQuery({
    queryKey: computed(() => ['ports', toValue(ownerId) ?? 0]),
    queryFn: () => api.ports(toValue(ownerId)!),
    enabled: computed(() => signedIn.value && !!toValue(ownerId)),
  })
}

export function useTraffic(ownerId: MaybeRefOrGetter<number | null | undefined>) {
  return useQuery({ queryKey: computed(() => ['traffic', toValue(ownerId) ?? 0]), queryFn: () => api.traffic(toValue(ownerId)!), enabled: computed(() => signedIn.value && !!toValue(ownerId)), refetchInterval: poll(5_000) })
}

/** Everything a rule or grant change can move: lists, quota counts, port leases, history. */
export async function afterRuleChange() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: keys.rules }),
    queryClient.invalidateQueries({ queryKey: ['ports'] }),
    queryClient.invalidateQueries({ queryKey: ['traffic'] }),
    queryClient.invalidateQueries({ queryKey: keys.users }),
    queryClient.invalidateQueries({ queryKey: keys.audit }),
    refreshIdentity(),
  ])
}

export function reportError(error: unknown, title = '操作失败') {
  if (!isStaleError(error)) toast(title, { description: errorMessage(error), tone: 'danger' })
}

/** Optimistic enable/disable with an undo affordance; the server answer replaces the guess. */
export function useToggleRule() {
  return useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) => api.updateRule(rule.id, ruleInput(rule, { enabled })),
    onMutate: async ({ rule, enabled }) => {
      const epoch = sessionState.epoch
      await queryClient.cancelQueries({ queryKey: keys.rules })
      if (epoch !== sessionState.epoch) throw new ApiError(0, 'stale_session', '会话已变更')
      const previous = queryClient.getQueryData<Rule[]>(keys.rules)
      queryClient.setQueryData<Rule[]>(keys.rules, list => list?.map(item => item.id === rule.id ? { ...item, enabled, runtime_status: 'pending', runtime_error: null } : item))
      return { previous, epoch }
    },
    onError: (error, _vars, context) => {
      if (context?.previous && context.epoch === sessionState.epoch && !isStaleError(error)) queryClient.setQueryData(keys.rules, context.previous)
      reportError(error, '保存失败')
    },
    onSuccess: (_data, { rule, enabled }) => {
      toast(enabled ? `已启用 ${rule.name}` : `已停用 ${rule.name}`, {
        action: { label: '撤销', run: () => toggleRule.mutate({ rule: { ...rule, enabled }, enabled: !enabled }) },
      })
    },
    onSettled: (_data, _error, _variables, context) => {
      if (context?.epoch === sessionState.epoch) return afterRuleChange()
    },
  })
}
// A single shared instance lets the undo action reuse the same optimistic path.
let toggleRule: ReturnType<typeof useToggleRule>
/** Call once from the app shell's setup; pages then use sharedToggle(). */
export function provideToggle() { toggleRule = useToggleRule(); return toggleRule }
export function sharedToggle() { return toggleRule }

export function useSaveRule() {
  return useMutation({
    mutationFn: ({ id, input }: { id: number | null; input: RuleInput }) => (id === null ? api.createRule(input) : api.updateRule(id, input)),
    onSettled: afterRuleChange,
  })
}

export function useDeleteRule() {
  return useMutation({ mutationFn: (rule: Rule) => api.deleteRule(rule.id), onSettled: afterRuleChange })
}

export function useRetry() {
  return useMutation({
    mutationFn: (ownerId: number) => api.retryApply(ownerId),
    onSuccess: () => toast('已重试'),
    onError: error => reportError(error, '重试失败'),
    onSettled: afterRuleChange,
  })
}
