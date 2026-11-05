import { useQuery } from '@tanstack/react-query'
import { api, type Job } from './api'

export interface CaseProfile {
  organization_id: string; organization_name?: string; pseudonym: string; summary: string
  sectors: string[]; subsectors?: { name: string; sector: string }[]
  countries: string[]; state?: string; city?: string; first_seen: string; last_seen: string
  software: { name: string; version: string }[]
  vulnerabilities: { name: string; status: 'confirmed' | 'suspected'; description: string }[]
  marking: string
}
export function newCaseProfile(): CaseProfile {
  return { organization_id: '', organization_name: '', pseudonym: '', summary: '', sectors: [], subsectors: [], countries: [], state: '', city: '', first_seen: '', last_seen: '', software: [], vulnerabilities: [], marking: 'TLP:AMBER+STRICT' }
}
export interface OpenCtiSettings {
  url: string; ingester_id: string; configured: boolean; token_hint: string; timeout: number
}
export interface OpenCtiState {
  exports: { id: string; state: string; created: string; updated: string; error?: string; case_url?: string | null; activity_hidden?: boolean; stats: { counts?: OpenCtiCounts } & Record<string, unknown> }[]
  sync: { ioc_id: number; status: 'new' | 'changed' | 'exported' | 'error'; error?: string }[]
  jobs: (Job & { activity_hidden?: boolean })[]
}
export interface OpenCtiOptions { ioc_ids: number[] | null }
export interface OpenCtiCounts { ips: number; cves: number; hashes: number }
export interface OpenCtiPreview {
  preview_id: string; case_reference: string; fingerprint: string
  profile: Omit<CaseProfile, 'organization_id' | 'pseudonym' | 'software' | 'vulnerabilities'>
  target: { url: string; ingester_id: string }; counts: OpenCtiCounts; redacted: boolean
  already_exported: { id: string; updated: string; case_url?: string | null } | null
  objects: ({ id: string; type: string } & Record<string, unknown>)[]
  iocs: { id: number; value: string; type: string; selected: boolean; tags: string[]; object_ids: string[]; warnings: string[] }[]
  warnings: string[]; errors: string[]
}
export const initialExportOptions = (ioc_ids: number[] | null = null): OpenCtiOptions => ({ ioc_ids })
export const transferableIoc = (type: string) => ['ip', 'vulnerability', 'hash', 'file'].includes(type)
export const openCtiKey = (slug: string) => ['opencti', slug]
export function useOpenCti(slug: string) {
  const settings = useOpenCtiSettings()
  const configured = settings.data?.configured === true
  const query = useQuery({ queryKey: openCtiKey(slug), queryFn: () => api<OpenCtiState>(`/api/cases/${slug}/opencti`), enabled: configured, staleTime: 15_000 })
  return { ...query, configured, data: configured ? query.data : undefined, error: configured ? query.error : null }
}
export function useOpenCtiSettings(enabled = true) {
  return useQuery({ enabled, queryKey: ['opencti-settings'], queryFn: () => api<OpenCtiSettings>('/api/opencti/settings'), staleTime: 30_000 })
}

/** Provider links must never execute script URLs. */
export function safeCtiUrl(value: string | undefined): string | undefined {
  if (!value) return undefined
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined } catch { return undefined }
}
