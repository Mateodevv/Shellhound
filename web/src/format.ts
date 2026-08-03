// format.ts — display helpers.

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
  return n.toLocaleString('de-AT')
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

/** "vor 3 Minuten" — Uhrzeiten sind für Berichte, für die Oberfläche zählt
 *  meist der Abstand zu jetzt. Die genaue Zeit steht im Tooltip daneben. */
export function relativeTime(iso?: string | null): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return String(iso)
  const secs = Math.round((Date.now() - then) / 1000)
  if (secs < 45) return 'gerade eben'
  const mins = Math.round(secs / 60)
  if (mins < 60) return `vor ${mins} Minute${mins === 1 ? '' : 'n'}`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `vor ${hours} Stunde${hours === 1 ? '' : 'n'}`
  const days = Math.round(hours / 24)
  if (days < 31) return `vor ${days} Tag${days === 1 ? '' : 'en'}`
  const months = Math.round(days / 30)
  if (months < 12) return `vor ${months} Monat${months === 1 ? '' : 'en'}`
  return `vor ${Math.round(months / 12)} Jahr${Math.round(months / 12) === 1 ? '' : 'en'}`
}

export function absoluteTime(iso?: string | null): string {
  if (!iso) return '—'
  return String(iso).replace('T', ' ').slice(0, 19)
}

export interface EvidenceRoot { kind: string; path: string; label?: string }

/** Ein Pfad, wie ein Mensch ihn denkt: relativ zur Evidence, unter der er
 *  liegt. Aus 90 Zeichen Absolutpfad wird `images/shell.php` — der volle
 *  Pfad bleibt als Tooltip erhalten, er ist die belastbare Angabe. */
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

export const SEVERITY_LABEL: Record<number, string> = {
  0: 'HIGH', 1: 'MEDIUM', 2: 'LOW', 3: 'INFO',
}
export const SEVERITY_VAR: Record<number, string> = {
  0: 'var(--sev-high)', 1: 'var(--sev-medium)', 2: 'var(--sev-low)',
  3: 'var(--muted)',
}

export const TRIAGE_LABEL: Record<string, string> = {
  new: 'Neu',
  reviewed: 'Gesichtet',
  confirmed: 'Bestätigt',
  dismissed: 'False Positive',
}

export const SOURCE_LABEL: Record<string, string> = {
  webshell: 'Webshell-Scan',
  sqldb: 'Datenbank',
  logs: 'Access-Logs',
}
