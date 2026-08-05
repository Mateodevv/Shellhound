// api.ts — fetch wrapper + shared types for the SHELLHOUND API.
//
// Every call carries the chosen language in `X-Lang`. Parts of the case
// narrative are assembled on the server -- the chronology, the GeoIP
// descriptions, the observations on an account -- and can only be phrased
// where the data is. A download link cannot set headers and gets `?lang=`
// from `downloadUrl()` instead.
import { activeLang } from './i18n'

declare global {
  interface Window { __SHELLHOUND_TOKEN__?: string }
}

export const TOKEN: string =
  window.__SHELLHOUND_TOKEN__ ??
  new URLSearchParams(location.search).get('token') ??
  ''

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'X-Token': TOKEN,
      'X-Lang': activeLang(),
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? detail
    } catch { /* not JSON */ }
    throw new ApiError(res.status, String(detail))
  }
  return res.json() as Promise<T>
}

export const post = <T = unknown>(path: string, body?: unknown) =>
  api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })

export const patch = <T = unknown>(path: string, body: unknown) =>
  api<T>(path, { method: 'PATCH', body: JSON.stringify(body) })

export const del = <T = unknown>(path: string) => api<T>(path, { method: 'DELETE' })

export function downloadUrl(path: string): string {
  const sep = path.includes('?') ? '&' : '?'
  return `${path}${sep}token=${encodeURIComponent(TOKEN)}`
       + `&lang=${encodeURIComponent(activeLang())}`
}

// ---- types -----------------------------------------------------------------

export interface CaseInfo {
  slug: string
  dir: string
  name: string
  reference: string
  notes: string
  created: string
  findings?: number
  artifacts?: number
  confirmed?: number
  iocs?: number
  evidence?: number
}

export interface EvidenceItem {
  id: number
  kind: 'webroot' | 'access_logs' | 'sql_dump' | 'reference'
  path: string
  added: string
  scanned_at: string
  stats: Record<string, unknown>
  exists?: boolean
  label?: string
  files?: number
  bytes?: number
  meta_at?: string
  meta_partial?: number
}

export interface LogIndexStatus {
  exists: boolean
  fresh: boolean
  reason: string
  lines: number
  clients: number
  unparsed: number
  size: number
}

export interface CaseDetail extends CaseInfo {
  evidence_items: EvidenceItem[]
  log_index: LogIndexStatus
}

export interface Job {
  id: number
  kind: string
  state: 'queued' | 'running' | 'done' | 'failed' | 'cancelled'
  progress: number
  message: string
  error: string
  created: string
  started?: string
  finished?: string
  stats: Record<string, unknown>
}

export interface Finding {
  id: number
  fingerprint: string
  source: 'webshell' | 'sqldb' | 'logs'
  severity: 0 | 1 | 2
  rule: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  artifact: string
  line: number | null
  evidence: string
  created: string
  last_seen: string
  triage: 'new' | 'reviewed' | 'confirmed' | 'dismissed'
  triage_note: string
  triaged_at?: string
}

export type TriageState = 'new' | 'reviewed' | 'confirmed' | 'dismissed'

/** An artifact (file, client, table, dump) with what the server aggregated
 *  over its findings. THAT is the unit decisions are made about -- the
 *  findings below it are the reasoning. */
export interface ArtifactRow {
  artifact: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  worst: 0 | 1 | 2 | 3
  source: 'webshell' | 'sqldb' | 'logs'
  findings: number
  triage: TriageState
  triage_note: string
  triaged_at: string | null
  last_seen: string
}

export interface FindingsResponse {
  /** Anzahl Artefakte im aktuellen Filter. */
  total: number
  artifacts: ArtifactRow[]
  /** All findings of the delivered artifacts. */
  findings: Finding[]
  /** All findings in the case, unfiltered -- as a size only. */
  findings_total: number
  counts: {
    severity: Record<string, number>
    triage: Record<string, number>
    source: Record<string, number>
    total: number
  }
  roots: { kind: string; path: string; label: string }[]
}

export interface ActorAlert {
  kind: string
  severity: number
  detail: string
  /** The URI that triggered the alert -- the trace marks it red. */
  example: string
}

export interface Actor {
  ip_id: number
  ip: string
  requests: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
  err4: number
  err5: number
  bytes: number
  posts: number
  login_posts: number
  login_redirects: number
  login_statuses: string
  scanner_uas: string
  sqli_attempts: number
  sqli_ok: number
  traversal_attempts: number
  traversal_ok: number
  upload_php_attempts: number
  upload_php_ok: number
  agents: number
  alerts: ActorAlert[]
  sparkline: number[]
  in_box: boolean
  /** Decision of the client artifact in Findings; null = no finding. */
  triage: TriageState | null
}

/** Operator configuration. The real API keys never reach the browser --
 *  `hint` is the last four characters, enough to tell two keys apart. */
export interface SettingsInfo {
  services: Record<string, {
    configured: boolean
    hint: string
    /** The ONE kind of value this service is allowed to receive. */
    sends: string
    url: string
  }>
  enrichment_ack: boolean
  path: string
}

/** What a third party said about one indicator. An OPINION, not a
 *  measurement: it never becomes a finding and never moves a severity.
 *  `fetched` matters -- a verdict from six weeks ago is a different
 *  statement from one fetched this morning. */
export interface Enrichment {
  service: string
  value: string
  kind: string
  fetched: string
  cached?: boolean
  result: {
    known: boolean
    score?: number
    of?: number
    suspicious?: number
    label?: string
    names?: string[]
    reports?: number
    distinct_reporters?: number
    country?: string
    isp?: string
    usage?: string
    tor?: boolean
    last_reported?: string
    permalink?: string
  }
}

export interface ActorsResponse {
  /** Login POSTs from which the server calls a client a flood. Comes from
   *  the server so badges and the "inconspicuous" filter cannot drift. */
  bf_threshold?: number
  total: number
  actors: Actor[]
  span: { from_hour: number; to_hour: number } | null
}

export interface TraceRow {
  client: string
  epoch: number
  tz: number
  method: string
  uri: string
  status: number
  size: number
  referrer: string
  agent: string
  source: string
}

/** A neighbour of this indicator, read from the perspective of THIS entry:
 *  `label` already carries the right reading direction ("has the SHA-256" at
 *  the path, "is the SHA-256 of" at the hash). */
export interface IocLink {
  id: number
  kind: string
  label: string
  note: string
  value: string
  type: string
}

export interface Ioc {
  id: number
  value: string
  type: string
  note: string
  tags: string[]
  origin: string
  added: string
  links: IocLink[]
}

/** A flagged artifact below an extension -- the inventory's tie to the case:
 *  THIS extension contains something the rules named. */
export interface CmsArtifactHit {
  artifact: string
  worst: number
  triage: TriageState
  findings: number
}

/** What hangs on a version: the measured value, the file it came from, and
 *  -- if there is one -- the analyst's correction. `version` is always the
 *  value THAT APPLIES, `version_parsed` the measured one. */
export interface VersionFacts {
  version: string
  version_parsed: string
  version_source: string
  version_set: string
  version_note: string
  version_set_at: string
}

export interface CmsItem extends VersionFacts {
  id: number
  install_id: number
  type: string
  name: string
  slug: string
  path: string
  artifacts: CmsArtifactHit[]
  flagged: number
}

export interface CmsInstall extends VersionFacts {
  id: number
  root: string
  cms: string
  items: CmsItem[]
}

export interface DbDump {
  id: number
  path: string
  meta: Record<string, string>
  statements: number
  size: number
  cms: string
  /** `schema` = install/uninstall/update SQL shipped with an extension, not
   *  a database export. */
  kind: 'export' | 'schema'
  /** Filled for schema files only: findings on their tables. */
  flagged?: number
}

export interface DbTable {
  id: number
  dump_id: number
  name: string
  columns: number
  rows: number
  bytes: number
  col_list: string
  /** Findings on this table -- 0 when there are none. */
  flagged: number
  worst: number | null
  triage: TriageState | null
}

/** A named observation about an account. Deliberately not a score: a dump
 *  cannot say that an admin is malicious -- only what stands out about
 *  them. */
export interface AccountSignal {
  id: string
  label: string
  why: string
}

export interface DbAccount {
  id: number
  dump_id: number
  cms: string
  tbl: string
  user_id: string
  login: string
  email: string
  registered: string
  hash_type: string
  admin: number
  /** Empty means "the dump does not say", not "never signed in". */
  last_login: string
  blocked: number
  sessions: number
  signals: AccountSignal[]
  rank: number
  /** The login is already in the IOC box as an indicator. */
  in_box: boolean
}

export interface Dashboard {
  /** Artefakte je Schweregrad (ihr schwerster Fund), ohne False Positives. */
  severity: Record<string, number>
  /** Artefakte je Entscheidung. */
  triage: Record<string, number>
  findings_total: number
  iocs: number
  accounts: number
  admins: number
  cms_installs: { id: number; root: string; cms: string; version: string }[]
  evidence: EvidenceItem[]
  jobs_running: Job[]
  logs: {
    lines: number
    clients: number
    unparsed: number
    alerted_clients: number
    first_epoch: number | null
    last_epoch: number | null
  } | null
  timeline: {
    day: string; requests: number; errors: number; new_clients: number
    /** Answered with 2xx; null on an index from before schema 3. */
    ok: number | null
  }[]
}

export interface CaseSummary {
  name: string
  reference: string
  slug: string
  created: string
  closed?: string
  findings: number
  /** Missing in archives closed before artifact-level triage. */
  artifacts?: number
  confirmed: number
  dismissed: number
  iocs: number
  evidence: { kind: string; path: string }[]
  severity: Record<string, number>
}

export interface ArchiveEntry {
  file: string
  size: number
  modified: string
  readable: boolean
  summary: CaseSummary | null
}

export interface ArchivesResponse {
  archive_dir: string
  archives: ArchiveEntry[]
}

export interface ImportResult {
  slug: string
  dir: string
  renamed: boolean
  name: string
}

export interface FileContent {
  path: string
  size: number
  offset: number
  length: number
  eof: boolean
  mode: 'raw' | 'hex'
  window: number
  binary: boolean
  from_line?: number | null
  lines?: string[]
  rows?: { offset: number; hex: string; ascii: string }[]
}

export interface PickPath {
  path: string
  parent: string | null
  dirs: { name: string; path: string }[]
  /** Files in the directory -- not every piece of evidence is a folder: a
   *  SQL dump is a single file. */
  files: { name: string; path: string; size: number }[]
  truncated: boolean
}

/** An entry in the evidence browser, enriched with what the case already
 *  knows about it. */
export interface BrowseFile {
  name: string
  path: string
  /** Path relative to the evidence root (including its folder name) -- the
   *  form the IOC box carries it in. */
  relative: string
  size: number
  in_box: boolean
  flagged: number
  worst: number | null
  triage: TriageState | null
}

export interface BrowseResponse {
  path: string
  parent: string | null
  roots: { kind: string; path: string; label: string }[]
  dirs: { name: string; path: string }[]
  files: BrowseFile[]
  truncated: boolean
}

export interface DetectResult {
  candidates: Record<'webroot' | 'access_logs' | 'sql_dump',
    { path: string; score: number; why: string; kind: string }[]>
  scanned: number
  truncated: boolean
  root: string
  error: string
}

export interface HuntHit { ip: string; name: string; hits: number; ok_hits: number }

/** A pattern from the library. It lives in the WORKSPACE, not in the case --
 *  created once, it is ready in every further case. */
export interface HuntPattern {
  id: string
  pattern: string
  label: string
  note: string
  added: string
}

export interface HuntClient {
  ip: string
  hits: number
  ok_hits: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
}

export interface HuntResult {
  id: string
  pattern: string
  label: string
  note: string
  hits: number
  ok_hits: number
  /** The URIs actually hit -- so that it is visible whether the pattern
   *  reaches too far. */
  uris: { uri: string; hits: number; ok_hits: number }[]
  clients: HuntClient[]
  /** The pattern hit more distinct URIs than were collected. */
  truncated: boolean
  /** The key figures of the search. `ok_clients` is the number for the
   *  record: how many addresses got through, not how often someone knocked.
   *  `uri_total` counts ALL URLs hit -- `uris` is only the sample. */
  clients_total: number
  ok_clients: number
  uri_total: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
}

/** An event of the case chronology. `at` is a NAIVE LOCAL TIME in seconds --
 *  the log line carries its server time, the account timestamp that of the
 *  database server, and both are compared as they stand. Always format it
 *  with tz = 0 for that reason. */
export interface ChainEvent {
  at: number
  kind: 'erstkontakt' | 'versuch' | 'erfolg' | 'alarm' | 'letzter-zugriff' | 'konto'
  title: string
  detail: string
  /** Where the time comes from: the access log or the SQL export. */
  source: 'log' | 'dump'
  artifact: string
  artifact_kind: '' | 'file' | 'table' | 'client' | 'dump'
  ip: string
  severity: number | null
}

/** The chronology: ordered measured facts, no statements about cause.
 *  `gaps` says what the case does NOT prove -- and that belongs in the
 *  report just as much as the events themselves. */
export interface CaseChain {
  span: { first: number | null; last: number | null }
  events: ChainEvent[]
  gaps: string[]
  undated: { artifact: string; artifact_kind: string; why: string }[]
  confirmed: number
  truncated: boolean
  /** Clock offset per source, set by the analyst, in seconds. */
  offsets: { logs: number; dump: number }
}

/** The record of the case: what was searched for -- unsuccessfully
 *  included. */
export interface HuntRun {
  pattern: string
  label: string
  ran_at: string
  hits: number
  ok_hits: number
  clients: number
  ok_clients: number
  uris: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
}

export interface FilePreview {
  error?: string
  binary?: boolean
  from_line?: number
  focus?: number | null
  lines?: string[]
  total_lines?: number
  truncated?: boolean
}

/** An artifact that HANGS on a decision: it was either decided along
 *  (`linked`) or it is suggested (`suggested`). `previous` is the state from
 *  before -- with it the propagation can be taken back without guessing. */
export interface TriageLink {
  artifact: string
  kind: 'file' | 'table' | 'client' | 'dump'
  why: string
  hits: number | null
  ok_hits: number | null
  previous: { state: TriageState; note: string }
}

export interface TriageResult {
  updated: number
  artifacts: number
  collected: { value: string; type: string; hits?: number; ok_hits?: number }[]
  linked: TriageLink[]
  suggested: TriageLink[]
}

/** An IP that hangs on this artifact -- with the reason why it is here.
 *  Each of them can be opened directly as a trace. */
export interface RelatedIp {
  ip: string
  why: string
  hits: number | null
  ok_hits: number | null
  in_box: boolean
}

/** Everything about ONE artifact: the response a decision is made from. */
export interface ArtifactContext {
  artifact: string
  kind: 'file' | 'table' | 'client' | 'dump'
  findings: Finding[]
  triage: TriageState
  triage_note: string
  triaged_at: string
  worst: number
  sources: string[]
  related_ips: RelatedIp[]
  file?: {
    exists: boolean
    size?: number
    mtime?: string
    sha256?: string
    in_upload_dir?: boolean
    cms_guard?: boolean | null
    preview?: FilePreview
  }
  hunt?: HuntHit[]
  actor?: {
    actor: Actor
    alerts: { kind: string; severity: number; detail: string; example: string }[]
    top_paths: { uri: string; n: number; ok: number }[]
    top_agents: { agent: string; n: number }[]
  } | null
  table?: {
    name: string
    columns: number
    rows: number
    bytes: number
    col_list: string
    dump_path: string
    cms: string
  } | null
  dump?: {
    id: number
    path: string
    meta: Record<string, string>
    statements: number
    size: number
    cms: string
  } | null
}
