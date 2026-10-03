// Client-side hints that mirror the server policy. The server stays authoritative.

const BYTES = new TextEncoder()

export function validateUsername(value: string) {
  return /^[A-Za-z][A-Za-z0-9_-]{2,31}$/.test(value) ? '' : '3–32 位，字母开头，可含数字、_ 和 -'
}

export function validatePassword(value: string) {
  const length = BYTES.encode(value).length
  if (length < 12) return '至少 12 个字符'
  if (length > 128) return '不能超过 128 字节'
  return ''
}

export function validateRuleName(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return '填写名称'
  if ([...trimmed].length > 64) return '最多 64 个字'
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) return '含有非法字符'
  return ''
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i

function isIpv6(value: string) {
  if (!value.includes(':') || /[^0-9a-f:.]/i.test(value)) return false
  try { new URL(`http://[${value}]/`); return true } catch { return false }
}

function privateIpv4(value: string) {
  const [a, b] = value.split('.').map(Number)
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19))
}

export function validateTargetHost(raw: string) {
  const value = raw.trim().replace(/\.$/, '')
  if (!value) return '填写目标地址'
  if (IPV4.test(value)) return privateIpv4(value) ? '须为公网地址' : ''
  if (isIpv6(value)) {
    const head = value.toLowerCase()
    return head.startsWith('2') || head.startsWith('3') ? '' : '须为公网 IPv6 地址'
  }
  const labels = value.split('.')
  if (value.length > 253 || labels.length < 2 || !labels.every(label => LABEL.test(label)) || !/[a-z]/i.test(labels[labels.length - 1])) {
    return '公网 IP 或域名，不带协议和端口'
  }
  return ''
}

export function validatePort(value: number | null, min = 1, max = 65535) {
  if (value === null || !Number.isInteger(value)) return '填写端口'
  if (value < min || value > max) return `端口须在 ${min}–${max} 之间`
  return ''
}

export function validateCidr(value: string) {
  const [address, prefix, extra] = value.split('/')
  if (extra !== undefined || !address || prefix === undefined || !/^\d{1,3}$/.test(prefix)) return false
  const bits = Number(prefix)
  if (IPV4.test(address)) return bits <= 32
  if (isIpv6(address)) return bits <= 128
  return false
}
