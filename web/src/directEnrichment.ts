import { useQuery } from '@tanstack/react-query'
import { api, type SettingsInfo } from './api'

export const providerTypes: Record<string, string[]> = { virustotal: ['file', 'hash', 'ip', 'domain', 'url'], abuseipdb: ['ip'] }
export function useDirectSettings(enabled = true) {
  return useQuery({ enabled, queryKey: ['settings'], queryFn: () => api<SettingsInfo>('/api/settings') })
}
export function directSupported(settings: SettingsInfo | undefined, kind: string) {
  return Object.entries(providerTypes).some(([service, kinds]) => settings?.services?.[service]?.configured && kinds.includes(kind))
}
