// api.ts — fetch wrapper + shared types for the SHELLHOUND API.

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
  kind: 'webroot' | 'access_logs' | 'sql_dump'
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

/** Ein Artefakt (Datei, Client, Tabelle, Dump) mit dem, was der Server über
 *  seine Findings aggregiert hat. DAS ist die Einheit, über die entschieden
 *  wird — die Findings darunter sind die Begründung. */
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
  /** Alle Findings der gelieferten Artefakte. */
  findings: Finding[]
  /** Alle Findings im Fall, ungefiltert — nur als Größenangabe. */
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
  /** Die URI, die den Alarm ausgelöst hat — der Trace markiert sie rot. */
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
  /** Entscheidung des Client-Artefakts in Findings; null = kein Finding. */
  triage: TriageState | null
}

export interface ActorsResponse {
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

/** Ein Nachbar dieses Indikators, aus Sicht DIESES Eintrags gelesen: `label`
 *  ist bereits die richtige Leserichtung ("hat den SHA-256" am Pfad, "ist der
 *  SHA-256 von" am Hash). */
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

/** Ein geflaggtes Artefakt unterhalb einer Extension — der Fall-Bezug des
 *  Inventars: DIESE Erweiterung enthält etwas, das die Regeln benannt haben. */
export interface CmsArtifactHit {
  artifact: string
  worst: number
  triage: TriageState
  findings: number
}

/** Was an einer Versionsangabe hängt: der Messwert, die Datei, aus der er
 *  stammt, und — falls vorhanden — die Korrektur des Analysten. `version`
 *  ist immer der GELTENDE Wert, `version_parsed` der gemessene. */
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
  /** `schema` = mit einer Erweiterung ausgelieferte install/uninstall/
   *  update-SQL, kein Datenbank-Export. */
  kind: 'export' | 'schema'
  /** Nur bei Schema-Dateien gefüllt: Findings auf ihren Tabellen. */
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
  /** Findings auf dieser Tabelle — 0, wenn keine. */
  flagged: number
  worst: number | null
  triage: TriageState | null
}

/** Eine benannte Beobachtung an einem Konto. Bewusst kein Punktwert: ein
 *  Dump kann nicht sagen, dass ein Admin bösartig ist — nur, was an ihm
 *  auffällt. */
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
  /** Leer heißt „der Dump sagt es nicht", nicht „nie angemeldet". */
  last_login: string
  blocked: number
  sessions: number
  signals: AccountSignal[]
  rank: number
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
    /** Mit 2xx beantwortet; null bei einem Index vor Schema 3. */
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
  /** Fehlt in Archiven, die vor der Artefakt-Triage geschlossen wurden. */
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
  /** Dateien im Verzeichnis — nicht jede Evidence ist ein Ordner: ein
   *  SQL-Dump ist eine einzelne Datei. */
  files: { name: string; path: string; size: number }[]
  truncated: boolean
}

/** Ein Eintrag im Evidence-Browser, angereichert um das, was der Fall über
 *  ihn schon weiß. */
export interface BrowseFile {
  name: string
  path: string
  /** Pfad relativ zur Evidence-Wurzel (inkl. deren Ordnername) — die Form,
   *  in der die IOC Box ihn führt. */
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

/** Ein Muster aus der Bibliothek. Sie liegt im WORKSPACE, nicht im Fall —
 *  einmal angelegt, steht es in jedem weiteren Fall bereit. */
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
  /** Die tatsächlich getroffenen URIs — damit sichtbar ist, ob das Muster
   *  zu weit greift. */
  uris: { uri: string; hits: number; ok_hits: number }[]
  clients: HuntClient[]
  /** Das Muster traf mehr distinkte URIs, als eingesammelt wurden. */
  truncated: boolean
  /** Die Kennzahlen der Suche. `ok_clients` ist die Zahl fürs Protokoll:
   *  wie viele Adressen kamen durch, nicht wie oft geklopft wurde.
   *  `uri_total` zählt ALLE getroffenen URLs — `uris` ist nur die Stichprobe. */
  clients_total: number
  ok_clients: number
  uri_total: number
  first_epoch: number | null
  last_epoch: number | null
  tz: number
}

/** Ein Ereignis der Fall-Chronologie. `at` ist eine NAIVE ORTSZEIT in
 *  Sekunden — die Logzeile trägt ihre Serverzeit, der Kontozeitstempel die
 *  des Datenbankservers, und beide werden verglichen, wie sie dastehen.
 *  Darum immer mit tz = 0 formatieren. */
export interface ChainEvent {
  at: number
  kind: 'erstkontakt' | 'versuch' | 'erfolg' | 'alarm' | 'letzter-zugriff' | 'konto'
  title: string
  detail: string
  /** Woraus die Zeit stammt: aus dem Access-Log oder aus dem SQL-Export. */
  source: 'log' | 'dump'
  artifact: string
  artifact_kind: '' | 'file' | 'table' | 'client' | 'dump'
  ip: string
  severity: number | null
}

/** Die Chronologie: geordnete gemessene Tatsachen, keine Kausalaussagen.
 *  `gaps` sagt, was der Fall NICHT belegt — das gehört genauso in den
 *  Bericht wie die Ereignisse selbst. */
export interface CaseChain {
  span: { first: number | null; last: number | null }
  events: ChainEvent[]
  gaps: string[]
  undated: { artifact: string; artifact_kind: string; why: string }[]
  confirmed: number
  truncated: boolean
}

/** Das Protokoll des Falls: wonach gesucht wurde — auch erfolglos. */
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

/** Ein Artefakt, das an einer Entscheidung HÄNGT: entweder wurde es
 *  mitentschieden (`linked`) oder es wird vorgeschlagen (`suggested`).
 *  `previous` ist der Zustand davor — damit lässt sich die Übernahme
 *  zurücknehmen, ohne zu raten. */
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

/** Eine IP, die an diesem Artefakt hängt — mit dem Grund, warum sie hier
 *  steht. Jede davon lässt sich direkt als Trace öffnen. */
export interface RelatedIp {
  ip: string
  why: string
  hits: number | null
  ok_hits: number | null
  in_box: boolean
}

/** Alles über EIN Artefakt: die Antwort, aus der entschieden wird. */
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
