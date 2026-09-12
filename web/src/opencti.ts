import { useQuery } from '@tanstack/react-query'
import { api, type Job } from './api'

export interface CaseProfile {
  organization_id: string
  organization_name?: string
  pseudonym: string
  summary: string
  sectors: string[]
  subsectors?: { name: string; sector: string }[]
  countries: string[]
  state?: string
  city?: string
  first_seen: string
  last_seen: string
  software: { name: string; version: string }[]
  vulnerabilities: { name: string; status: 'confirmed' | 'suspected'; description: string }[]
  marking: string
}
export function newCaseProfile(): CaseProfile {
  return { organization_id: '', organization_name: '', pseudonym: '', summary: '', sectors: [], subsectors: [], countries: [], state: '', city: '', first_seen: '', last_seen: '', software: [], vulnerabilities: [], marking: 'TLP:AMBER+STRICT' }
}
export interface Organization { id: string; name: string }
export interface OpenCtiSettings {
  url: string; ingester_id: string; configured: boolean; token_hint: string
  sample_uploads: boolean; external_file_uploads: false; timeout: number
}
export interface OpenCtiConnector { id: string; name: string; scope: string[]; active: boolean; auto: boolean }
export interface OpenCtiReference {
  id?: string; name?: string; value?: string; url?: string; description?: string; relationship_type?: string
  source_name?: string; external_id?: string; observable_value?: string; entity_type?: string
  from?: OpenCtiReference; to?: OpenCtiReference; createdBy?: OpenCtiReference; created_at?: string; updated_at?: string
}
export interface OpenCtiEntity {
  id: string; type: string; name: string; url: string; description?: string
  score?: number; confidence?: number; labels: (string | { value: string })[]
  x_opencti_cvss_base_score?: number | null
  x_opencti_epss_score?: number | null
  x_opencti_epss_percentile?: number | null
  created_at?: string; updated_at?: string; first_seen?: string; last_seen?: string
  sources: (string | OpenCtiReference)[]; reports: (string | OpenCtiReference)[]
  malware: (string | OpenCtiReference)[]; relationships: (string | OpenCtiReference)[]
}
export interface OpenCtiLookup {
  ioc_id: number; status: 'known' | 'own' | 'unknown' | 'unsupported' | 'error'
  checked_at: string; stale: boolean; entities: OpenCtiEntity[]; error?: string
}
export interface OpenCtiState {
  lookups: OpenCtiLookup[]
  exports: { activity_hidden?: boolean; id: string; state: string; created: string; updated: string; error?: string; stats: Record<string, unknown> }[]
  sync: { ioc_id: number; status: 'new' | 'changed' | 'exported' | 'error'; error?: string }[]
  jobs: (Job & { activity_hidden?: boolean })[]
  enrichments?: { activity_hidden?: boolean; id: string; ioc_id: number; connector_id: string; connector_name?: string; work_id: string; state: string; updated: string; error?: string; url?: string }[]
}
export interface OpenCtiOptions {
  ioc_ids: number[] | null; exclude_relationship_ids: number[]
  exclude_note_ioc_ids: number[]; exclude_evidence_ioc_ids: number[]; exclude_profile_fields: string[]
  indicator_ids: number[]; sample_ids: string[]; include_notes: boolean; include_evidence: boolean
}
export interface OpenCtiPreview {
  preview_id: string; case_reference: string; fingerprint: string
  objects: ({ id: string; type: string } & Record<string, unknown>)[]
  iocs: { id: number; value: string; type: string; selected: boolean; tags?: string[]; object_ids: string[]; indicator_supported: boolean; indicator_suggested: boolean; indicator_default?: boolean; warnings: string[] }[]
  relationships: { id: number; src_id: number; dst_id: number; kind: string; note: string; selected: boolean }[]
  samples: { id: string; display_path: string; sha256: string; size: number; selected: boolean; available: boolean; reason: string; file_id: string }[]
  warnings: string[]; errors: string[]
}
export interface OpenCtiEnrichmentPreview {
  entities: { ioc_id: number; id: string | null; value: string; type: string; requires_creation: boolean; requires_transfer?: boolean }[]
  connectors: OpenCtiConnector[]; warnings: string[]
}

export const initialExportOptions = (ids: number[]): OpenCtiOptions => ({
  ioc_ids: [...ids], exclude_relationship_ids: [], exclude_note_ioc_ids: [], exclude_evidence_ioc_ids: [], exclude_profile_fields: [],
  indicator_ids: [], sample_ids: [], include_notes: false, include_evidence: true,
})

export const openCtiKey = (slug: string) => ['opencti', slug]
export function useOpenCti(slug: string) {
  const settings = useOpenCtiSettings()
  const configured = settings.data?.configured === true
  const query = useQuery({
    enabled: configured,
    queryKey: openCtiKey(slug),
    queryFn: () => api<OpenCtiState>(`/api/cases/${slug}/opencti`),
    refetchInterval: (q) => q.state.data?.jobs?.some((j) => j.state === 'queued' || j.state === 'running') ? 2000 : false,
    staleTime: 15_000,
  })
  // Disabled queries retain cached data; keep it out of the optional integration UI.
  return { ...query, configured, data: configured ? query.data : undefined, error: configured ? query.error : null }
}
export function useOpenCtiSettings() {
  return useQuery({ queryKey: ['opencti-settings'], queryFn: () => api<OpenCtiSettings>('/api/opencti/settings'), staleTime: 30_000 })
}
/** Never turn provider supplied URLs into script links. */
export function safeCtiUrl(value: string | undefined): string | undefined {
  if (!value) return undefined
  try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined } catch { return undefined }
}
