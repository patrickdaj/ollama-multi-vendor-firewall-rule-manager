import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export const VENDOR_LABELS: Record<string, string> = {
  paloalto: 'Palo Alto',
  cisco_asa: 'Cisco ASA',
  cisco_ftd: 'Cisco FTD',
  fortinet: 'FortiGate',
}

export const OBJECT_TYPE_LABELS: Record<string, string> = {
  security_rule: 'Security Rules',
  nat_rule: 'NAT Rules',
  address_object: 'Address Objects',
  service_object: 'Service Objects',
  service_group: 'Service Groups',
  application: 'Application Objects',
  app_group: 'App Groups',
  url_category: 'URL Categories',
  auth_policy: 'Auth Policies',
  decryption_rule: 'Decryption Rules',
  decryption_profile: 'Decryption Profiles',
  dos_policy: 'DoS Policies',
  edl: 'EDLs',
  zone: 'Zones',
  security_profile: 'Security Profiles',
}
