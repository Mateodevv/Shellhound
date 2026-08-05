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

/** Epoch (UTC) + tz offset of the log line -> the log's own local time. */
export function formatLogTime(epoch?: number | null, tz = 0): string {
  if (!epoch) return '—'
  const d = new Date((epoch + tz) * 1000)
  return d.toISOString().replace('T', ' ').slice(0, 19)
}

export function formatDay(epoch?: number | null, tz = 0): string {
  if (!epoch) return '—'
  return new Date((epoch + tz) * 1000).toISOString().slice(0, 10)
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
  if (s < 60) return unit(s, de ? 'Sekunde' : 'second', de ? 'Sekunden' : 'seconds')
  if (s < 3600) return unit(Math.round(s / 60), de ? 'Minute' : 'minute', de ? 'Minuten' : 'minutes')
  if (s < 86400) return unit(Math.round(s / 3600), de ? 'Stunde' : 'hour', de ? 'Stunden' : 'hours')
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
