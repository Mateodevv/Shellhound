import { Search, Plus } from 'lucide-react'
import type { HuntPattern, HuntTest } from '../../api'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui/ui'

export function PatternPicker({ patterns, tests, selectedId, search, filter, busy, onSearch, onFilter, onSelect, onToggle, onNew, onRun, canRun, footer }: {
  onRun: () => void; canRun: boolean; footer?: React.ReactNode
  patterns: HuntPattern[]; tests: HuntTest[]; selectedId: string; search: string; filter: string; busy: boolean
  onSearch: (value: string) => void; onFilter: (value: 'active' | 'all' | 'hit' | 'own') => void
  onSelect: (pattern: HuntPattern) => void; onToggle: (pattern: HuntPattern) => void; onNew: () => void
}) {
  const tr = useT()
  const last = new Map<string, HuntTest>()
  for (const test of tests) if (!last.has(test.pattern_id) || last.get(test.pattern_id)!.id < test.id) last.set(test.pattern_id, test)
  const needle = search.trim().toLowerCase()
  const visible = patterns.filter(p => (filter !== 'active' || (p.enabled && !p.archived))
    && (filter !== 'own' || p.source === 'own') && (filter !== 'hit' || Boolean(last.get(p.id)?.hits))
    && (!needle || [p.name, p.cve, p.technology, p.description].join(' ').toLowerCase().includes(needle)))
  return <aside aria-label={tr('hunt.flow.managePatterns')} className="flex min-h-0 flex-col overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)] lg:sticky lg:top-3 lg:max-h-[calc(100dvh-180px)]">
    <div className="space-y-3 border-b border-[var(--line)] p-3">
      <div className="flex items-center justify-between gap-2"><h2 className="font-semibold">{tr('hunt.flow.managePatterns')}</h2><Button onClick={onNew} aria-label={tr('hunt.flow.addAPattern')} title={tr('hunt.flow.addAPattern')}><Plus size={14} /></Button></div>
      <label className="flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2"><Search size={14} /><input className="min-w-0 flex-1 bg-transparent py-2 text-sm outline-none" value={search} onChange={e => onSearch(e.target.value)} aria-label={tr('hunt.flow.searchSavedPatterns')} placeholder={tr('hunt.flow.searchPlaceholder')} /></label>
      <div className="flex flex-wrap gap-1">{(['active', 'all', 'hit', 'own'] as const).map(value => <button key={value} type="button" aria-pressed={filter === value} onClick={() => onFilter(value)} className={`cursor-pointer rounded px-2 py-1 text-xs ${filter === value ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]'}`}>{tr(`hunt.workbench.filter.${value}`)}</button>)}</div>
    <Button variant="primary" className="w-full" onClick={onRun} disabled={!canRun}>{tr('hunt.workspace.run')}</Button>
    </div>
    <div className="min-h-0 overflow-y-auto">{visible.map(p => <div key={p.id} className={`flex items-start gap-3 border-b border-l-[3px] border-[var(--line-soft)] px-3 py-4 ${selectedId === p.id ? 'border-l-[var(--accent)] bg-[var(--accent-soft)]' : 'border-l-transparent'}`}>
      <input type="checkbox" className="mt-1" aria-label={`${tr('hunt.flow.enabledLabel')}: ${p.name}`} checked={p.enabled && !p.archived} disabled={busy || p.archived} onChange={() => onToggle(p)} />
      <button type="button" aria-pressed={selectedId === p.id} onClick={() => onSelect(p)} className="min-w-0 flex-1 cursor-pointer text-left">
        <span className="block break-words text-sm font-semibold">{p.name}</span>
        <span className="mt-1 flex items-center justify-between gap-2 text-xs text-[var(--muted)]"><span className="flex flex-wrap gap-1"><Tag>{tr(`hunt.technology.${p.technology}`)}</Tag>{(p.cve.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map(cve => <Tag key={cve}>{cve}</Tag>)}</span><span className="shrink-0 whitespace-nowrap" title={tr('hunt.flow.matchingRequests')}>{last.get(p.id) ? tr(last.get(p.id)!.hits === 1 ? 'hunt.workspace.oneMatch' : 'hunt.workspace.hitCount', { n: last.get(p.id)!.hits ?? 0 }) : tr('hunt.workspace.notRun')}</span></span>
      </button>
    </div>)}{!visible.length && <p className="p-4 text-sm text-[var(--muted)]">{tr('hunt.flow.noLibraryMatches')}</p>}</div>
    {footer && <div className="flex flex-wrap gap-2 border-t border-[var(--line)] p-2">{footer}</div>}
  </aside>
}
