import { Search, Plus } from 'lucide-react'
import type { HuntPattern, HuntTest } from '../../api'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui/ui'

export function PatternPicker({ patterns, tests, selectedId, search, filter, busy, onSearch, onFilter, onSelect, onToggle, onNew }: {
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
      <div className="flex items-center justify-between gap-2"><h2 className="font-semibold">{tr('hunt.flow.managePatterns')}</h2><Button onClick={onNew}><Plus size={14} />{tr('hunt.flow.addAPattern')}</Button></div>
      <label className="flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2"><Search size={14} /><input className="min-w-0 flex-1 bg-transparent py-2 text-sm outline-none" value={search} onChange={e => onSearch(e.target.value)} aria-label={tr('hunt.flow.searchSavedPatterns')} placeholder={tr('hunt.flow.searchPlaceholder')} /></label>
      <div className="flex flex-wrap gap-1">{(['active', 'all', 'hit', 'own'] as const).map(value => <button key={value} type="button" aria-pressed={filter === value} onClick={() => onFilter(value)} className={`cursor-pointer rounded px-2 py-1 text-xs ${filter === value ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]'}`}>{tr(`hunt.workbench.filter.${value}`)}</button>)}</div>
    </div>
    <div className="min-h-0 overflow-y-auto">{visible.map(p => <div key={p.id} className={`flex items-start gap-2 border-b border-[var(--line-soft)] p-3 ${selectedId === p.id ? 'bg-[var(--accent-soft)]' : ''}`}>
      <input type="checkbox" className="mt-1" aria-label={`${tr('hunt.flow.enabledLabel')}: ${p.name}`} checked={p.enabled && !p.archived} disabled={busy || p.archived} onChange={() => onToggle(p)} />
      <button type="button" aria-pressed={selectedId === p.id} onClick={() => onSelect(p)} className="min-w-0 flex-1 cursor-pointer text-left">
        <span className="block break-words text-sm font-semibold">{p.name}</span>
        <span className="mt-1 flex flex-wrap gap-1"><Tag>{tr(`hunt.technology.${p.technology}`)}</Tag>{p.cve && <Tag>{p.cve}</Tag>}</span>
        <span className="mt-1 block text-xs text-[var(--muted)]">{last.get(p.id) ? `${last.get(p.id)!.hits} ${tr('hunt.flow.matchingRequests')} · ${last.get(p.id)!.clients} ${tr('hunt.flow.ipAddresses')}` : tr('hunt.workspace.notRun')}</span>
      </button>
    </div>)}{!visible.length && <p className="p-4 text-sm text-[var(--muted)]">{tr('hunt.flow.noLibraryMatches')}</p>}</div>
  </aside>
}
