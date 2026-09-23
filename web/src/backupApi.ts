import type { ArtifactRow, EvidenceItem } from './api'

export interface Website { id: number; label: string; timezone: string }
export interface BackupSnapshot {
  id: number; site_id: number; evidence_id: number; root: string; label: string
  captured_at: string; captured_epoch: number | null; timezone: string
  completeness: string; generation: string; state: string; available: boolean
  stats: { files?: number; bytes?: number; prepared?: string; unavailable?: number; error?: string }
}
export interface BackupEntry {
  snapshot: BackupSnapshot; status: string; available?: boolean; stale?: boolean
  scan_state?: string; finding?: ArtifactRow
  file: { relative_path: string; artifact: string; sha256: string; size: number; state: string } | null
  assessment?: { state: string; note: string; origin: string } | null
  inheritance?: { state: string; origin: string } | null
}
export interface BackupHistoryData { site_id: number | null; path: string; entries: BackupEntry[] }
export interface BackupOverview { sites: Website[]; snapshots: BackupSnapshot[] }
export interface BackupComparison {
  snapshots: BackupSnapshot[]; prepared: boolean; total: number
  rows: (BackupHistoryData & { suspicious: boolean; changed: boolean })[]
}
export interface BackupDiff {
  sides: { label: string; artifact?: string; sha256?: string; size?: number; missing?: boolean; limited?: string }[]
  lines: string[]; truncated: boolean
}
export type WebrootEvidence = Pick<EvidenceItem, 'id' | 'path' | 'label' | 'source_timezone'>
