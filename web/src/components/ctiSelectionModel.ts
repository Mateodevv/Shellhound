export const iocCategories = ['all', 'ip', 'file', 'hash', 'domains', 'vulnerability', 'other']
export function inIocCategory(type: string, category: string) {
  if (category === 'all') return true
  if (category === 'domains') return type === 'domain' || type === 'url'
  if (category === 'other') return !['ip', 'file', 'hash', 'domain', 'url', 'vulnerability'].includes(type)
  return type === category
}
export function selectBatch<T>(current: T[], eligible: T[], checked: boolean): T[] {
  const scope = new Set(eligible)
  return checked ? [...new Set([...current, ...eligible])] : current.filter(id => !scope.has(id))
}
export const selectionTable = 'w-full min-w-[680px] table-fixed border-separate border-spacing-0 text-left text-[12px] [&_th]:px-3 [&_th]:py-2 [&_td]:px-3 [&_td]:py-2 [&_td]:align-middle [&_tbody_td]:border-b [&_tbody_td]:border-[var(--line)] [&_tbody_tr:hover]:bg-[var(--panel-2)]'
export const selectionHead = 'text-[11px] text-[var(--muted)] [&_th]:sticky [&_th]:top-0 [&_th]:z-10 [&_th]:border-b [&_th]:border-[var(--line)] [&_th]:bg-[var(--panel-2)] [&_th]:font-medium'
import type { OpenCtiOptions, OpenCtiPreview } from '../opencti'

/** One default indicator per file content, even when file/hash/path rows coexist. */
export function webshellIndicatorDefaults(preview: OpenCtiPreview, options: OpenCtiOptions): number[] {
  const fileKey = (row: OpenCtiPreview['iocs'][number]) => row.object_ids.find(id => id.startsWith('file--')) || `ioc:${row.id}`
  const used = new Set(preview.iocs.filter(row => options.indicator_ids.includes(row.id)).map(fileKey))
  const rank = (type: string) => type === 'file' ? 0 : type === 'hash' ? 1 : 2
  const candidates = preview.iocs.filter(row => row.indicator_default && row.indicator_supported &&
    (options.ioc_ids === null || options.ioc_ids.includes(row.id)))
    .sort((a, b) => rank(a.type) - rank(b.type) || a.id - b.id)
  return candidates.filter(row => {
    const key = fileKey(row)
    if (used.has(key)) return false
    used.add(key)
    return true
  }).map(row => row.id)
}
