// api.ts — fetch wrapper + shared types for the SHELLHOUND API.
//
// Every call carries the chosen language in `X-Lang`. Parts of the case
// narrative are assembled on the server -- the chronology, the GeoIP
// descriptions, the observations on an account -- and can only be phrased
// where the data is. A download link cannot set headers and gets `?lang=`
// from `downloadUrl()` instead.
import { activeLang } from './i18n'
import { activeTimeMode } from './format'

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
      // Part of the chronology is prose the server renders times into.
      'X-TZ': activeTimeMode(),
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

/** Replaces a whole thing rather than amending one -- a YARA rule file is
 *  edited as a document, not field by field. */
export const put = <T = unknown>(path: string, body: unknown) =>
  api<T>(path, { method: 'PUT', body: JSON.stringify(body) })

export const del = <T = unknown>(path: string) => api<T>(path, { method: 'DELETE' })

export function downloadUrl(path: string): string {
  const sep = path.includes('?') ? '&' : '?'
  return `${path}${sep}token=${encodeURIComponent(TOKEN)}`
       + `&lang=${encodeURIComponent(activeLang())}`
       + `&tz=${encodeURIComponent(activeTimeMode())}`
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
  run_id: string
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

export interface TriageEvent {
  id: number
  artifact: string
  artifact_kind: string
  from_state: TriageState
  to_state: TriageState
  note: string
  propagated: number
  at: string
}

export interface CaseActivity {
  decisions: TriageEvent[]
  jobs: Job[]
  hunts: { id: number; pattern: string; label: string; ran_at: string;
    hits: number; clients: number }[]
}

export type FindingSource = 'webshell' | 'sqldb' | 'logs' | 'yara' | 'errorlog' | 'analyst'

export interface Finding {
  id: number
  fingerprint: string
  source: FindingSource
  severity: 0 | 1 | 2 | 3
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
  /** 1 when the engine's last completed scan did not reproduce this row --
   *  the payload moved, the file is gone, or the rule no longer runs. The
   *  row keeps its triage and stays fetchable; it just stopped being a
   *  current statement, and the interface says so instead of pointing a
   *  clickable line number at text that is no longer there. */
  retired: 0 | 1
}

export type TriageState = 'new' | 'reviewed' | 'confirmed' | 'dismissed'

/** An artifact (file, client, table, dump) with what the server aggregated
 *  over its findings. THAT is the unit decisions are made about -- the
 *  findings below it are the reasoning. */
export interface ArtifactRow {
  artifact: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  worst: 0 | 1 | 2 | 3
  source: FindingSource
  /** Findings the last completed scans still reproduce. Retired rows are
   *  not in this number -- counting them made one moved payload read as
   *  two problems. */
  findings: number
  /** Findings the last completed scans did NOT reproduce. 0 on a freshly
   *  scanned artifact; `findings === 0 && retired > 0` is a thing that was
   *  decided about and then not seen again -- shown, never dropped. */
  retired: number
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
  /** Artifacts a switched-off rule took out of this list. Stated rather
   *  than silent: a list that shrinks without saying so is a list nobody
   *  can trust. */
  muted_hidden: number
  /** Undecided artifacts none of whose findings the last completed scans
   *  reproduced. Stated for the same reason as muted_hidden -- and apart
   *  from it, because "a switch hides it" and "it was not seen again" send
   *  the analyst to different places. */
  retired_hidden: number
  /** How many rules are switched off in this workspace. */
  muted_rules: number
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

/** What `logindex.actor_profile` measures about one client -- the part that
 *  comes out of the log index and nothing else.
 *
 *  SPLIT FROM `Actor` ON PURPOSE. The three fields below this one are what
 *  the Actors LIST adds for its own rows: a sparkline to draw, whether the
 *  address is in the IOC box, and the decision on it. The artifact window
 *  embeds a profile and gets none of them, so declaring one type for both
 *  paths meant `actor.triage` read as undefined there -- no error, no
 *  render, just a value that is never right. */
export interface ActorProfile {
  ip_id: number
  ip: string
  requests: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
  err4: number
  err5: number
  bytes: number
  /** Requests whose response size the log did not record -- a `-` in
   *  the size field, which is not the same as zero and is not rare:
   *  measured at 2.0 % and 18.9 % of parsed lines on two real logs,
   *  on one of them including 200s. `bytes` above sums only the
   *  answers that HAVE a size, so this is how many it could not. */
  bytes_unknown: number
  posts: number
  login_posts: number
  login_redirects: number
  /** Requests to the admin backend answered 2xx -- a page an unauthenticated
   *  session does not get, and the only thing in a log that says a login
   *  actually worked. A redirect does not: Joomla answers every login POST
   *  with one whether the credentials were right or wrong. */
  admin_ok: number
  login_statuses: string
  scanner_uas: string
  sqli_attempts: number
  sqli_ok: number
  traversal_attempts: number
  traversal_ok: number
  upload_php_attempts: number
  upload_php_ok: number
  /** Requests for a PHP file lying DIRECTLY in templates/, modules/,
   *  plugins/ or components/. The CMS ships nothing at that depth --
   *  a template is `templates/<name>/...` -- so a bare .php one level
   *  in was put there by somebody. */
  cms_dir_php_attempts: number
  cms_dir_php_ok: number
  /** First and last login POST from this client, as epoch seconds. The
   *  window the flood ran in: 92 POSTs over three weeks and 40 inside one
   *  second are the same count and not the same event, and the count
   *  alone cannot tell them apart. Null when no login POST carried a
   *  readable time. */
  login_first: number | null
  login_last: number | null
  /** The most login POSTs this client made inside any 24 h window. What
   *  separates an intruder from the site's own operator: signing in every
   *  working morning crosses a plain count over a long log and reaches
   *  almost nothing inside one day. */
  login_burst: number
  agents: number
}

/** A profile as the Actors list needs it: the measurements, plus the alerts
 *  raised against this client and what the row itself has to draw. Only the
 *  list endpoint sends these -- the artifact window gets the measurements
 *  with the alerts BESIDE them, in the envelope, not inside the row. */
export interface Actor extends ActorProfile {
  alerts: ActorAlert[]
  sparkline: number[]
  in_box: boolean
  /** Decision of the client artifact in Findings; null = no finding. */
  triage: TriageState | null
}

/** The evidence-oriented inspector record for one client. Telemetry exists
 * even when no detection produced a finding; an analyst decision and its
 * findings are therefore nullable/additive instead of gating the profile. */
export interface ActorDetail {
  actor: ActorProfile
  alerts: ActorAlert[]
  top_paths: { uri: string; n: number; ok: number }[]
  top_agents: { agent: string; n: number }[]
  triage: TriageState | null
  triage_note: string
  triaged_at: string
  worst: number | null
  findings: Finding[]
  in_box: boolean
  /** Evidence-bearing neighbours: each one requested the exact URI that
   * triggered an alert for this actor. */
  relations: ActorRelation[]
}

export interface ActorRelation {
  ip: string
  shared_requests: number
  successful: number
  shared_paths: string[]
  triage: TriageState | null
  in_box: boolean
}

export interface ActorCompareProfile extends ActorProfile {
  triage: TriageState | null
  in_box: boolean
}

export interface ActorOverlap {
  actors: number
  hits: number
  ok: number
}

export interface ActorComparison {
  actors: ActorCompareProfile[]
  time_overlap: { from_epoch: number; to_epoch: number } | null
  shared_paths: (ActorOverlap & { uri: string })[]
  shared_agents: (ActorOverlap & { agent: string })[]
}

/** One built-in detection rule. The id lives next to the rule that
 *  implements it and is stable across versions -- the off-switch stores it. */
export interface DetectionRule {
  id: string
  engine: string
  severity: number
  name: string
  enabled: boolean
  /** How the rule is written, which decides what can be shown of it.
   *  `yara` carries its own source, `regex` the pattern it matches with,
   *  `builtin` is a rule about a file's location or an aggregate over the
   *  log index -- there is no single expression to show, and inventing a
   *  readable-looking one would misdescribe what runs. */
  format: 'yara' | 'regex' | 'builtin'
  /** The definition itself, for `yara` and `regex`. */
  source: string
  /** One sentence on what a hit means. Bundled YARA rules only. */
  what: string
}

/** One `.yar` file in the workspace. The unit of management is the FILE,
 *  not the individual rule: a file is what a vendor feed or a CERT hands
 *  over, and switching one off must not edit somebody else's text. */
export interface YaraRuleFile {
  name: string
  enabled: boolean
  /** The rule names declared inside it. */
  rules: string[]
  /** Compile error, if it has one. A file that does not compile costs that
   *  file and not the scan. */
  error: string
  bytes: number
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
  /** Complete-index counts for the investigation views. Behaviour classes
   *  overlap; triage is the analyst's independent decision axis. */
  facets?: {
    all: number
    quiet: number
    relevant: number
    alerted: number
    scanner: number
    bruteforce: number
    probes: number
    ioc: number
    triage: Record<TriageState, number>
  }
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

export interface AccessLogQuery {
  search: string
  from_epoch: number | null
  to_epoch: number | null
  clients: string[]
  exclude_clients: string[]
  paths: string[]
  exclude_paths: string[]
  agents: string[]
  exclude_agents: string[]
  source_ids: number[]
  exclude_source_ids: number[]
  status: string
  method: string
  min_size: number | null
  max_size: number | null
  signals_only: boolean
  sort: 'time' | 'time_desc'
}

export interface AccessLogRow extends TraceRow {
  request_id: number
  request_key: string
  source_id: number
  line_no: number
  signals: string[]
}

export interface AccessSearchResponse {
  total: number
  rows: AccessLogRow[]
  next_cursor: string | null
  summary: {
    first_epoch: number | null
    last_epoch: number | null
    ok: number
    redirects: number
    client_errors: number
    server_errors: number
  }
}

export interface AccessFacet {
  value: string | number
  label?: string
  count: number
}

export interface AccessOverview {
  total: number
  bucket_seconds: number
  timeline: {
    start_epoch: number
    end_epoch: number
    requests: number
    ok: number
    errors: number
    signals: number
  }[]
  facets: {
    status: AccessFacet[]
    methods: AccessFacet[]
    clients: AccessFacet[]
    paths: AccessFacet[]
    agents: AccessFacet[]
    sources: AccessFacet[]
  }
}

export interface AccessPattern {
  pattern: string
  requests: number
  clients: number
  ok: number
  errors: number
  first_epoch: number | null
  last_epoch: number | null
  examples: string[]
  signals: string[]
}

export interface AccessPatternsResponse {
  patterns: AccessPattern[]
  sampled_uris: number
  truncated: boolean
}

export interface AccessSegment {
  client: string
  first_epoch: number
  last_epoch: number
  tz: number
  duration: number
  requests: number
  ok: number
  errors: number
  bytes: number
  bytes_unknown: number
  signals: string[]
  top_paths: AccessFacet[]
  methods: AccessFacet[]
}

export interface AccessSegmentsResponse {
  segments: AccessSegment[]
  requires_client: boolean
  truncated: boolean
}

export interface AccessRequestContext {
  request: AccessLogRow
  before: AccessLogRow[]
  after: AccessLogRow[]
  raw_line: string
  raw_truncated: boolean
}

export interface AccessSavedQuery {
  id: number
  name: string
  query: AccessLogQuery
  created: string
  updated: string
}

export interface AccessClip {
  id: number
  request_key: string
  snapshot: AccessLogRow & { raw_line?: string; raw_truncated?: boolean }
  note: string
  added: string
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
  /** First/last day the address appears in this case's access logs, as
   *  dates in the log's own local time -- null for non-addresses and for
   *  addresses the index has no dated requests for. `added` is only when
   *  the indicator entered the box; these two are when it was ACTIVE. */
  first_seen: string | null
  last_seen: string | null
  /** For `path` entries: the absolute path under an evidence root where the
   *  file actually lies, or null when no registered copy holds it. The
   *  value itself stays webroot-relative -- what leaves the machine must be
   *  what the other side can look for. */
  resolved?: string | null
  links: IocLink[]
}

export interface CrossCaseIocMatch {
  slug: string
  name: string
  reference: string
  id: number
  value: string
  type: string
  note: string
  tags: string[]
  origin: string
  added: string
}

export interface CrossCaseIocEntry {
  id: number
  value: string
  type: string
  matches: CrossCaseIocMatch[]
}

export interface CrossCaseIocResponse {
  entries: CrossCaseIocEntry[]
  matched_iocs: number
  matches: number
  matched_cases: number
  cases_scanned: number
  cases_skipped: number
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

export interface DbIntelligenceItem {
  category?: 'configuration' | 'extensions' | 'access' | 'persistence' | 'content'
  cms: string
  key: string
  name?: string
  element?: string
  type?: string
  kind?: string
  scope?: string
  enabled?: boolean | null
  protected?: boolean
  version?: string
  value?: string
  autoload?: string
  label?: string
  user_id?: string
  account_login?: string
  account_email?: string
  account_admin?: boolean
  account_signals?: string[]
  roles?: string[]
  created?: string
  modified?: string
  expires?: string
  last_used?: string
  last_run?: string
  next_run?: string
  last_ip?: string
  user_agent?: string
  client?: string
  state?: string
  task_type?: string
  schedule?: string
  interval?: number
  priority?: number
  title?: string
  /** Bounded CMS post/article body. It is always rendered as inert text. */
  content?: string
  content_truncated?: boolean
  status?: string
  author?: string
  path?: string
  domains?: string[]
  source_table: string
  source_row: number
  dump_id: number | null
  dump_name: string
  filesystem_only?: boolean
  filesystem?: {
    status: 'present' | 'missing' | 'unknown'
    path: string
    version: string
    type: string
    findings: { artifact: string; worst: number; triage: TriageState; findings: number }[]
  }
  signals: string[]
  review: boolean
}

export interface DatabaseIntelligence {
  cms: string[]
  configuration: DbIntelligenceItem[]
  extensions: DbIntelligenceItem[]
  access: DbIntelligenceItem[]
  persistence: DbIntelligenceItem[]
  content: DbIntelligenceItem[]
  review_queue: DbIntelligenceItem[]
  truncated: Record<string, boolean>
  summary: {
    needs_review: number
    active_extensions: number
    access_records: number
    persistence_records: number
    content_signals: number
  }
}

export interface DashboardObservation extends ChainEvent {
  role: 'first' | 'first_success' | 'account' | 'first_alert' | 'last'
}

export interface DashboardConfirmedArtifact {
  artifact: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  worst: number
}

export interface DashboardChronology {
  total_events: number
  event_span: { first: number | null; last: number | null }
  /** Kept separately because the first event may itself be the first success. */
  first_success_at: number | null
  observations: DashboardObservation[]
  gaps: string[]
  undated: number
  zone: string
  tz_offsets: string[]
  tz_mixed: boolean
}

export interface Dashboard {
  /** Artefakte je Schweregrad (ihr schwerster Fund), ohne False Positives. */
  severity: Record<string, number>
  /** Artefakte je Entscheidung. */
  triage: Record<string, number>
  /** Confirmed incident artifacts grouped by entity type and severity. */
  confirmed_kinds: Record<string, number>
  confirmed_severity: Record<string, number>
  /** A type-balanced preview; the full confirmed queue remains in Findings. */
  confirmed_artifacts: DashboardConfirmedArtifact[]
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
  chronology: DashboardChronology
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

export interface FileHashes {
  md5?: string
  sha1?: string
  sha256?: string
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
  created_at: string | null
  modified_at: string | null
  accessed_at: string | null
  changed_at: string | null
  /** MD5/SHA-1 are forensic comparison identifiers; SHA-256 is the strong
   *  integrity digest. Empty when the file exceeds the bounded hash limit. */
  hashes: FileHashes
  hashes_limited: boolean
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
  created_at: string | null
  modified_at: string | null
  accessed_at: string | null
  changed_at: string | null
  in_box: boolean
  flagged: number
  worst: number | null
  triage: TriageState | null
  /** Present only after this file was explicitly handled in the manual
   *  review workflow; scanner-backed triage remains distinguishable. */
  review: FileReview | null
}

export interface FileReview {
  state: Exclude<TriageState, 'new'>
  note: string
  at: string
}

export interface FileReviewResult extends TriageResult {
  review: FileReview
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
  /** One or more paths. Several are combined OVER CLIENTS, not over one
   *  request -- a URI cannot be two paths at once. */
  patterns: string[]
  /** `any` = a client that hit at least one; `all` = only clients that hit
   *  every one. The second is the claim that survives a defence lawyer. */
  match: 'any' | 'all'
  /** Optional predicates on the matching request itself. Values within a
   *  field are alternatives; method and user-agent must both match. */
  request: {
    methods: string[]
    user_agents: string[]
  }
  name: string
  cve: string
  description: string
  added: string
  /** Which half of the library this came from. `bundled` ships inside the
   *  package and is identical on every installation of a version -- which is
   *  what makes it citable; `own` was written here. */
  source: 'bundled' | 'own'
  /** Switched off for this workspace. Only ever false for a bundled entry:
   *  an own pattern is deleted rather than disabled. */
  enabled: boolean
}

export interface HuntClient {
  ip: string
  hits: number
  ok_hits: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
  /** Existing case context, including findings written by this hunt. */
  triage: '' | TriageState
  finding_count: number
  in_box: boolean
}

export interface HuntTimelineDay {
  day: string
  requests: number
  ok: number
  errors: number
  clients: number
}

export interface HuntResult {
  id: string
  pattern: string
  /** Request predicates applied in addition to the URL pattern. */
  request: {
    methods: string[]
    user_agents: string[]
  }
  /** What the analyst called it. The server sends `name` and `cve`; the type
   *  used to declare `label` and `note`, which no endpoint ever produced, so
   *  the headline silently fell back to the raw pattern. */
  name: string
  cve: string
  hits: number
  ok_hits: number
  /** The URIs actually hit -- so that it is visible whether the pattern
   *  reaches too far. */
  uris: { uri: string; hits: number; ok_hits: number }[]
  clients: HuntClient[]
  /** The pattern hit more distinct URIs than could be collected at all --
   *  the interning cap, not the display cap. */
  truncated: boolean
  /** The client list is a sample: more addresses matched than are listed.
   *  `clients_total` is the real number and is what belongs in a report. */
  clients_truncated: boolean
  /** The URI list is a sample too. Without this the block reads as the whole
   *  answer, and a pattern reaching too far looks precise. */
  uris_truncated: boolean
  /** The key figures of the search. `ok_clients` is the number of addresses
   *  that received at least one 2xx response; it is not a claim that an
   *  exploit succeeded. `uri_total` counts all URLs hit. */
  clients_total: number
  ok_clients: number
  uri_total: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
  timeline: HuntTimelineDay[]
}

/** An event of the case chronology. `at` is already in the active timeline
 *  reading. Log and dump values retain their measured wall-clock meaning;
 *  absolute filesystem epochs are shifted into that reading by the server.
 *  Always format it with tz = 0 for that reason. */
export interface ChainEvent {
  at: number
  kind: 'erstkontakt' | 'versuch' | 'erfolg' | 'alarm' | 'letzter-zugriff' | 'konto'
    | 'datei-erstellt' | 'datei-geaendert' | 'metadaten-geaendert'
  title: string
  detail: string
  /** Where the time comes from: access log, SQL export, or evidence copy. */
  source: 'log' | 'dump' | 'filesystem'
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
  /** First and last dated observation, independent of page and sort order. */
  event_span: { first: number | null; last: number | null }
  events: ChainEvent[]
  gaps: string[]
  undated: { artifact: string; artifact_kind: string; why: string }[]
  confirmed: number
  /** Number of dated events in the complete chronology, before paging. */
  total_events: number
  truncated: boolean
  /** Paging applied by the interactive chronology endpoint. */
  offset: number
  limit: number
  order: 'asc' | 'desc'
  /** Clock offset per source, set by the analyst, in seconds. */
  offsets: { logs: number; dump: number }
  /** Which reading the events are in, and what to call it. They arrive
   *  ALREADY SHIFTED and carry no offset of their own, so this is the only
   *  thing that says what they mean. */
  tz_mode: 'log' | 'utc'
  /** The zone the events are in. EMPTY when the logs carry several offsets
   *  and the reading is log time -- there is no single answer then, and
   *  naming one of them would be wrong by an hour for the rest. */
  zone: string
  /** Every offset the logs carry. More than one means a DST change or
   *  several servers. */
  tz_offsets: string[]
  tz_mixed: boolean
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
  retained_iocs: RetainedIoc[]
}

export interface RetainedIoc {
  id: number
  value: string
  type: string
  origin: string
  removable: boolean
  sources: { artifact: string; role: string; active: number }[]
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
    hashes?: FileHashes
    hashes_limited?: boolean
    created_at?: string | null
    modified_at?: string | null
    accessed_at?: string | null
    changed_at?: string | null
    in_upload_dir?: boolean
    cms_guard?: boolean | null
    preview?: FilePreview
  }
  hunt?: HuntHit[]
  actor?: {
    actor: ActorProfile
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
