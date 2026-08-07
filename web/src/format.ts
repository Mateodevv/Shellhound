// format.ts — display helpers.
import { activeLang } from './i18n'

export function formatBytes(n?: number | null): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatCount(n?: number | null): string {
  if (n == null) return '0'
  // Thousands separators follow the chosen language, not the machine.
  return n.toLocaleString(activeLang() === 'de' ? 'de-AT' : 'en-GB')
}

// ---- time ------------------------------------------------------------------
//
// WHAT IS STORED NEVER CHANGES: an epoch in UTC, plus the offset that stood
// in the log line. Those are the measured facts. Everything below is only
// how they are RENDERED, and the analyst chooses between two readings:
//
//   log  the time as the server wrote it, in its own offset. What somebody
//        reading that server's log at the time would have seen.
//   utc  the same instant in UTC. The only way to lay two sources with
//        different offsets on one timeline and be sure.
//
// There is deliberately no third mode for "this workstation's time zone".
// That is a fact about the forensic VM and about nothing in the case; a
// timestamp rendered in it looks like evidence and is an artefact of where
// the analysis happened to run.
//
// AND NO ZONE NAMES ARE INVENTED. A log line carries an OFFSET, not a zone:
// `+0200` is CEST, and equally EET, SAST and half a dozen others. Printing
// "CEST" next to a timestamp would be a guess wearing the clothes of a
// measurement. The offset is what is known, so the offset is what is shown.

export type TimeMode = 'log' | 'utc'

export const TIME_KEY = 'shellhound.timeMode'

/** The remembered choice, read before the first render. A non-component
 *  export lives here rather than in the switcher, or Fast Refresh stops
 *  working for that file. */
export function storedTimeMode(): TimeMode {
  try {
    const stored = localStorage.getItem(TIME_KEY)
    if (stored === 'log' || stored === 'utc') return stored
  } catch { /* storage blocked */ }
  return 'log'
}

let currentMode: TimeMode = 'log'

/** The active mode outside React -- exports and the API layer need it and
 *  cannot use a hook, the same arrangement as the language. */
export function activeTimeMode(): TimeMode {
  return currentMode
}
export function setActiveTimeMode(mode: TimeMode) {
  currentMode = mode
}

/** `+02:00`, `-05:30`, or `UTC` for zero -- which is the one offset whose
 *  name is not a guess. */
export function formatOffset(tz = 0): string {
  if (!tz) return 'UTC'
  const sign = tz < 0 ? '-' : '+'
  const total = Math.abs(Math.round(tz / 60))
  const hh = String(Math.floor(total / 60)).padStart(2, '0')
  const mm = String(total % 60).padStart(2, '0')
  return `UTC${sign}${hh}:${mm}`
}

/** What zone the rendered stamp is in, given the mode and the line's own
 *  offset. In UTC mode the line's offset is irrelevant, which is the point. */
export function zoneLabel(tz = 0, mode: TimeMode = currentMode): string {
  return mode === 'utc' ? 'UTC' : formatOffset(tz)
}

/** Epoch (UTC) + the log line's offset, rendered in the active mode.
 *
 *  `withZone` appends the zone. Dense tables leave it off and state the zone
 *  once for the column; a timestamp standing on its own in running text
 *  carries it, because that is the one that ends up pasted into a report. */
export function formatLogTime(epoch?: number | null, tz = 0,
                              opts: { withZone?: boolean; mode?: TimeMode } = {}): string {
  if (!epoch) return '—'
  const mode = opts.mode ?? currentMode
  const shift = mode === 'utc' ? 0 : tz
  const stamp = new Date((epoch + shift) * 1000)
    .toISOString().replace('T', ' ').slice(0, 19)
  return opts.withZone ? `${stamp} ${zoneLabel(tz, mode)}` : stamp
}

export function formatDay(epoch?: number | null, tz = 0): string {
  if (!epoch) return '—'
  const shift = currentMode === 'utc' ? 0 : tz
  return new Date((epoch + shift) * 1000).toISOString().slice(0, 10)
}

/** The length of a time span in words. Activity across four minutes is
 *  something other than the same across four months -- the span says so in
 *  one word that can be carried into a report. */
export function formatSpan(from?: number | null, to?: number | null): string {
  if (!from || !to) return '—'
  const s = Math.max(0, to - from)
  const de = activeLang() === 'de'
  const unit = (n: number, one: string, many: string) =>
    `${n} ${n === 1 ? one : many}`
  // THE UNIT IS CHOSEN FROM THE ROUNDED VALUE, not from the raw one. Picking
  // it first and rounding afterwards produced "60 minutes" for 3599 seconds
  // and "24 hours" for 86399 -- the very readings the next branch exists to
  // express, and a gap reported as 24 hours reads as a day nobody looked at.
  if (s < 60) return unit(s, de ? 'Sekunde' : 'second', de ? 'Sekunden' : 'seconds')
  const minutes = Math.round(s / 60)
  if (minutes < 60) return unit(minutes, de ? 'Minute' : 'minute', de ? 'Minuten' : 'minutes')
  const hours = Math.round(s / 3600)
  if (hours < 24) return unit(hours, de ? 'Stunde' : 'hour', de ? 'Stunden' : 'hours')
  return unit(Math.round(s / 86400), de ? 'Tag' : 'day', de ? 'Tage' : 'days')
}

/** "3 minutes ago" -- clock times are for reports; for the interface what
 *  usually counts is the distance from now. The exact time stands next to it
 *  in the tooltip. */
export function relativeTime(iso?: string | null): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return String(iso)
  const secs = Math.round((Date.now() - then) / 1000)
  const de = activeLang() === 'de'
  const ago = (n: number, one: string, many: string) =>
    de ? `vor ${n} ${n === 1 ? one : many}` : `${n} ${n === 1 ? one : many} ago`
  if (secs < 45) return de ? 'gerade eben' : 'just now'
  const mins = Math.round(secs / 60)
  if (mins < 60) return ago(mins, de ? 'Minute' : 'minute', de ? 'Minuten' : 'minutes')
  const hours = Math.round(mins / 60)
  if (hours < 24) return ago(hours, de ? 'Stunde' : 'hour', de ? 'Stunden' : 'hours')
  const days = Math.round(hours / 24)
  if (days < 31) return ago(days, de ? 'Tag' : 'day', de ? 'Tage' : 'days')
  const months = Math.round(days / 30)
  if (months < 12) return ago(months, de ? 'Monat' : 'month', de ? 'Monate' : 'months')
  const years = Math.round(months / 12)
  return ago(years, de ? 'Jahr' : 'year', de ? 'Jahre' : 'years')
}

export function absoluteTime(iso?: string | null): string {
  if (!iso) return '—'
  return String(iso).replace('T', ' ').slice(0, 19)
}

export interface EvidenceRoot { kind: string; path: string; label?: string }

/** A path the way a human thinks of it: relative to the evidence it sits
 *  under. 90 characters of absolute path become `images/shell.php` -- the
 *  full path is kept as a tooltip, it is the defensible statement. */
export function relativeToRoot(path: string, roots: EvidenceRoot[]):
    { root: EvidenceRoot | null; rel: string } {
  const norm = (s: string) => s.replace(/\\/g, '/').replace(/\/+$/, '')
  const target = norm(path)
  let best: EvidenceRoot | null = null
  let bestLen = -1
  for (const r of roots) {
    const root = norm(r.path)
    if (target.toLowerCase().startsWith(root.toLowerCase() + '/') && root.length > bestLen) {
      best = r
      bestLen = root.length
    }
  }
  if (!best) return { root: null, rel: path }
  return { root: best, rel: target.slice(bestLen + 1) }
}

export function evidenceName(e: { label?: string; path: string; kind?: string }): string {
  if (e.label?.trim()) return e.label.trim()
  return baseName(e.path) || e.path
}

export function shortPath(path: string, max = 60): string {
  if (path.length <= max) return path
  const norm = path.replace(/\\/g, '/')
  const parts = norm.split('/')
  const name = parts[parts.length - 1]
  return `…/${parts.slice(-3, -1).join('/')}/${name}`.slice(-max)
}

export function baseName(path: string): string {
  return path.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop() ?? path
}

// Severity names are the same in both languages -- they come from the
// engines and appear verbatim in exports.
export const SEVERITY_LABEL: Record<number, string> = {
  0: 'HIGH', 1: 'MEDIUM', 2: 'LOW', 3: 'INFO',
}
export const SEVERITY_VAR: Record<number, string> = {
  0: 'var(--sev-high)', 1: 'var(--sev-medium)', 2: 'var(--sev-low)',
  3: 'var(--muted)',
}

export const SOURCE_KEYS: Record<string, string> = {
  webshell: 'source.webshell',
  sqldb: 'source.sqldb',
  logs: 'source.logs',
}
