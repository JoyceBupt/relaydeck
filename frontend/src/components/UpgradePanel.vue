<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useIntervalFn } from '@vueuse/core'
import { ArrowUpCircle, RotateCw } from '@lucide/vue'
import PasswordInput from './PasswordInput.vue'
import OtpInput from './OtpInput.vue'
import { api } from '../api/endpoints'
import { ApiError, errorMessage, isStaleError } from '../api/client'
import { currentUser, sessionState } from '../lib/session'
import type { UpgradeOffer, UpgradeStatus } from '../types'

const status = ref<UpgradeStatus | null>(null)
const error = ref('')
const passwordInvalid = ref(false)
const codeInvalid = ref(false)
const loading = ref(false)
const checking = ref(false)
const sending = ref(false)
const confirming = ref(false)
const confirmedOffer = ref<UpgradeOffer | null>(null)
const reconnecting = ref(false)
const uncertain = ref(false)
let loadedVersion = ''
let previousJobId: string | null = null
function acceptStatus(result: UpgradeStatus) {
  loadedVersion ||= result.current_version
  status.value = result
  if (!result.recovery_required && !result.maintenance && result.job && ['succeeded', 'rolled_back'].includes(result.job.phase) && result.current_version !== loadedVersion) window.location.reload()
}
const form = reactive({ password: '', code: '', acknowledge: false })
watch(() => form.password, value => { if (value && passwordInvalid.value) { passwordInvalid.value = false; error.value = '' } })
watch(() => form.code, value => { if (value && codeInvalid.value) { codeInvalid.value = false; error.value = '' } })
const now = ref(Date.now())
useIntervalFn(() => { now.value = Date.now() }, 1000)
const enabled = computed(() => !!currentUser.value?.mfa_enabled)
const active = computed(() => uncertain.value || !!status.value?.maintenance || !!status.value?.job && ['queued', 'downloading', 'verifying', 'updating', 'recovering'].includes(status.value.job.phase))
const offer = computed(() => status.value?.latest && status.value.latest.expires_at * 1000 > now.value ? status.value.latest : null)
const confirmedFresh = computed(() => confirmedOffer.value && confirmedOffer.value.expires_at * 1000 > now.value && status.value?.latest?.offer === confirmedOffer.value.offer)
const stepLabels: Record<string, string> = { download: '下载中', verify: '校验中', backup: '备份中', install: '安装中', health: '检查服务', rollback: '回滚中' }
const jobLabel = computed(() => {
  const job = status.value?.job
  if (reconnecting.value && active.value) return '面板重启中，等待恢复'
  if (uncertain.value) return '正在确认升级状态'
  if (!job) return status.value?.maintenance ? '服务器维护中' : ''
  if (job.phase === 'queued') return '准备升级'
  if (job.phase === 'succeeded') return '升级完成'
  if (job.phase === 'rolled_back') return '已恢复原版本'
  if (job.phase === 'failed') return '升级失败'
  return stepLabels[job.step] ?? '准备升级'
})

async function load() {
  if (!enabled.value || loading.value || sending.value || checking.value) return
  loading.value = true
  const epoch = sessionState.epoch
  try {
    const result = await api.upgradeStatus()
    if (epoch !== sessionState.epoch) return
    const wasReconnecting = reconnecting.value
    const unaccepted = uncertain.value && (result.job?.id ?? null) === previousJobId
    acceptStatus(result)
    reconnecting.value = false
    uncertain.value = false
    if (unaccepted) error.value = '升级未提交，请重新检查'
    else if (wasReconnecting && !confirming.value) error.value = ''
  } catch (failure) {
    if (isStaleError(failure) || epoch !== sessionState.epoch) return
    reconnecting.value = true
    if (!active.value) error.value = errorMessage(failure)
  } finally { loading.value = false }
}
async function check() {
  if (checking.value || active.value) return
  checking.value = true
  error.value = ''
  const epoch = sessionState.epoch
  try {
    const result = await api.checkUpgrade()
    if (epoch === sessionState.epoch) { acceptStatus(result); reconnecting.value = false }
  } catch (failure) { if (!isStaleError(failure)) error.value = errorMessage(failure) } finally { checking.value = false }
}
function cancel() { confirming.value = false; confirmedOffer.value = null; Object.assign(form, { password: '', code: '', acknowledge: false }); passwordInvalid.value = false; codeInvalid.value = false; error.value = '' }
function beginConfirm() { if (!offer.value) return; cancel(); confirmedOffer.value = { ...offer.value }; confirming.value = true }
async function start() {
  if (sending.value || active.value || !confirmedFresh.value || !confirmedOffer.value || !form.acknowledge || !form.password || form.code.length !== 6) return
  const input = { offer: confirmedOffer.value.offer, password: form.password, code: form.code, acknowledge: true }
  previousJobId = status.value?.job?.id ?? null
  sending.value = true
  error.value = ''
  const epoch = sessionState.epoch
  try {
    const result = await api.startUpgrade(input)
    if (epoch !== sessionState.epoch) return
    acceptStatus(result)
    confirming.value = false
  } catch (failure) {
    if (isStaleError(failure) || epoch !== sessionState.epoch) return
    if (failure instanceof ApiError && (failure.status === 0 || failure.status >= 500)) {
      // A lost acknowledgement is ambiguous: poll the root job before offering another start.
      uncertain.value = true
      reconnecting.value = true
      confirming.value = false
    } else {
      passwordInvalid.value = failure instanceof ApiError && failure.code === 'password_invalid'
      codeInvalid.value = failure instanceof ApiError && ['mfa_invalid', 'mfa_locked'].includes(failure.code)
      error.value = errorMessage(failure)
    }
  } finally { sending.value = false; form.password = ''; form.code = '' }
}
useIntervalFn(load, 5000)
onMounted(load)
</script>

<template>
  <section class="panel px-5 py-5" aria-labelledby="upgrade-title">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <h2 id="upgrade-title" class="text-sm font-semibold">面板升级</h2>
      <button v-if="enabled && !confirming" type="button" class="btn btn-secondary btn-sm" :disabled="checking || sending || active" @click="check"><RotateCw class="size-3.5" :class="checking ? 'anim-spin' : ''" />{{ checking ? '检查中' : '检查更新' }}</button>
    </div>
    <template v-if="enabled">
      <p class="mt-3 text-sm text-muted">当前版本 <span class="font-medium text-fg tabular">{{ status?.current_version ?? '—' }}</span></p>
      <div v-if="active || status?.job" class="mt-3" role="status" aria-live="polite">
        <p class="font-medium" :class="status?.job?.phase === 'failed' ? 'text-danger' : ''"><span v-if="status?.job && status.job.version !== status.current_version && !uncertain" class="tabular">{{ status.job.version }} · </span>{{ jobLabel }}<span v-if="status?.job?.phase === 'downloading'" class="ml-2 tabular text-muted">{{ status.job.progress ?? 0 }}%</span></p>
        <p v-if="status?.job?.error" class="mt-1 text-sm text-muted [overflow-wrap:anywhere]">{{ status.job.error }}</p>
      </div>
      <div v-if="!active && !confirming && !status?.recovery_required" class="mt-4 flex flex-wrap items-center justify-between gap-3">
        <template v-if="offer">
          <a :href="offer.release_url" target="_blank" rel="noopener noreferrer" class="font-medium text-accent hover:underline">{{ offer.version }}</a>
          <button type="button" class="btn btn-primary btn-sm" @click="beginConfirm"><ArrowUpCircle class="size-3.5" />立即升级</button>
        </template>
        <p v-else class="text-sm text-muted">{{ status?.checked_at ? status.latest ? '检查已过期' : '已是最新版本' : '尚未检查更新' }}</p>
      </div>
      <p v-if="status?.recovery_required && !active" class="mt-3 text-sm text-danger">升级恢复未完成，请检查服务日志</p>
      <form v-if="confirming && !active" class="mt-4 grid max-w-sm gap-4" @submit.prevent="start">
        <p class="text-sm font-medium">升级至 {{ confirmedOffer?.version }}</p>
        <div v-if="!confirmedFresh" class="flex items-center justify-between gap-3"><p class="text-sm text-warning" role="alert">检查已过期</p><button type="button" class="btn btn-secondary btn-sm" @click="cancel(); check()">重新检查</button></div>
        <label class="field"><span class="field-label">当前密码</span><PasswordInput v-model="form.password" autocomplete="current-password" required maxlength="128" :disabled="sending" :aria-invalid="passwordInvalid ? 'true' : undefined" /></label>
        <div class="field"><span class="field-label">新的验证码</span><OtpInput v-model="form.code" label="升级验证码" :disabled="sending" :invalid="codeInvalid" /></div>
        <label class="flex items-start gap-2 text-sm"><input v-model="form.acknowledge" type="checkbox" class="mt-1 size-4 shrink-0 accent-[var(--accent)]" :disabled="sending" /><span>确认中断全部转发</span></label>
        <div class="flex gap-2">
          <button type="submit" class="btn btn-primary" :disabled="sending || !confirmedFresh || !form.password || form.code.length !== 6 || !form.acknowledge">{{ sending ? '验证中' : '确认升级' }}</button>
          <button type="button" class="btn btn-ghost" :disabled="sending" @click="cancel">取消</button>
        </div>
      </form>
      <p v-if="error" class="mt-3 text-sm text-danger" role="alert">{{ error }}</p>
      <button v-if="reconnecting && !active" type="button" class="btn btn-ghost btn-sm mt-2" :disabled="loading" @click="load">刷新状态</button>
    </template>
    <a v-else href="#security" class="btn btn-secondary btn-sm mt-4">开启验证</a>
  </section>
</template>
