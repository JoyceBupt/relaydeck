import { reactive } from 'vue'

export interface ToastItem {
  id: number
  title: string
  description?: string
  tone: 'default' | 'success' | 'danger'
  action?: { label: string; run: () => void }
  open: boolean
}

export const toasts = reactive<ToastItem[]>([])
let next = 0

export function toast(title: string, options: Partial<Omit<ToastItem, 'id' | 'title' | 'open'>> = {}) {
  toasts.push({ id: ++next, title, tone: 'default', open: true, ...options })
  if (toasts.length > 4) toasts.splice(0, toasts.length - 4)
}

export function dismissToast(id: number) {
  const index = toasts.findIndex(item => item.id === id)
  if (index >= 0) toasts.splice(index, 1)
}
