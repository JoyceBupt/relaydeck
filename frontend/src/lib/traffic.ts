import type { TrafficMode } from '../types'

export const trafficModes: Record<TrafficMode, string> = { both: '双向合计', ingress: '仅入站', egress: '仅出站' }
export const trafficFactors = { GB: 1_000_000_000, TB: 1_000_000_000_000 }
export function trafficBytes(value: number | null, unit: keyof typeof trafficFactors): number | null {
  if (value === null || !Number.isFinite(value)) return null
  return Math.round(value * trafficFactors[unit])
}
export function trafficText(bytes: number): string {
  const unit = bytes >= trafficFactors.TB ? 'TB' : 'GB'
  const amount = bytes / trafficFactors[unit]
  return `${amount.toLocaleString(undefined, { maximumFractionDigits: 3 })} ${unit}`
}
