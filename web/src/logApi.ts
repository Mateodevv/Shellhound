export interface LogSettings {
  format: string; timezone: string; label: string; server_root: string; webroot: string
}
export interface LogSource {
  id: string; path: string; format: string; family: string; settings: Partial<LogSettings>
  fresh: boolean; state: string; warning: string; accepted: boolean; fingerprint: string
  stats: { events?: number; unparsed?: number; undated?: number }
  detected?: { ambiguous: boolean; error: string }
}
export interface LogSourcesResponse { sources: LogSource[]; formats: Record<string, string> }
export interface LogEvent {
  id: string; source_id: string; source_name: string; fingerprint: string; family: string
  epoch: number | null; recorded_epoch?: number | null; clock_correction?: number
  raw_time: string; time_meaning: string; line: number; line_end: number
  ip: string; remote_host: string; account: string; path: string; artifact: string; mapped_artifact?: string
  artifact_available?: boolean; triage?: string; timeline_id?: string
  bytes?: number | null
  operation: string; outcome: string; signature: string; detection: boolean; raw: string; fresh: boolean
}
export interface LogSearch { rows: LogEvent[]; total: number; next_offset: number | null }
export interface LogContext { event: LogEvent; source_path?: string; lines: { line: number; text: string; selected: boolean }[] }
