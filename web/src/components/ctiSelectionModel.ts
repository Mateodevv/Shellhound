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
