import clsx from 'clsx'
import { Archive, Copy, PencilLine, Play, Plus, Search, ScrollText, ToggleLeft, ToggleRight, X } from 'lucide-react'
import type { HuntPattern, HuntTechnology, HuntTest, Job } from '../../api'
import { formatCount } from '../../format'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui'
import { splitDescription } from './state'

const TECHNOLOGIES: HuntTechnology[] = ['wordpress', 'joomla', 'generic', 'other']

export function PatternLibrary({
  patterns, tests, selectedId, search, filter, collapsed, busy, runDisabled = busy,
  onSearch, onFilter, onSelect, onEdit, onNew, onDuplicate, onToggle, onArchive,
  onBatch, onRun, onFromLogs, onCollapse, batchJob, onCancelBatch,
}: {
  patterns: HuntPattern[]
  tests: HuntTest[]
  selectedId: string
  search: string
  filter: 'active' | 'all' | 'own' | 'bundled' | 'archived' | 'hit'
  collapsed: boolean
  busy: boolean
  runDisabled?: boolean
  onSearch: (value: string) => void
  onFilter: (value: 'active' | 'all' | 'own' | 'bundled' | 'archived' | 'hit') => void
  onSelect: (pattern: HuntPattern) => void
  onEdit: (pattern: HuntPattern) => void
  onNew: () => void
  onDuplicate: (pattern: HuntPattern) => void
  onToggle: (pattern: HuntPattern) => void
  onArchive: (pattern: HuntPattern) => void
  onBatch?: () => void
  onRun?: (pattern: HuntPattern) => void
  onFromLogs: () => void
  onCollapse: () => void
  batchJob: Job | null
  onCancelBatch: () => void
}) {
  const tr = useT()
  if (collapsed) {
    return <aside className="flex h-full w-12 flex-col items-center bg-[var(--panel)] py-2">
      <button type="button" onClick={onCollapse} title={tr('hunt.flow.managePatterns')} aria-label={tr('hunt.flow.managePatterns')}
        className="cursor-pointer rounded-lg p-2 text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]"><Search size={18} /></button>
      <button type="button" onClick={onNew} title={tr('hunt.flow.addAPattern')} aria-label={tr('hunt.flow.addAPattern')}
        className="mt-2 cursor-pointer rounded-lg p-2 text-[var(--accent)] hover:bg-[var(--accent-soft)]"><Plus size={18} /></button>
    </aside>
  }
  const lastByPattern = new Map<string, HuntTest>()
  tests.forEach((test) => {
    if (!test.pattern_id) return
    const previous = lastByPattern.get(test.pattern_id)
    if (!previous || previous.id < test.id) lastByPattern.set(test.pattern_id, test)
  })
  const needle = search.trim().toLowerCase()
  const visible = patterns.filter((pattern) => {
    const test = lastByPattern.get(pattern.id)
    if (filter === 'active' && (!pattern.enabled || pattern.archived)) return false
    if (filter === 'own' && pattern.source !== 'own') return false
    if (filter === 'bundled' && pattern.source !== 'bundled') return false
    if (filter === 'archived' && !pattern.archived) return false
    if (filter === 'hit' && !(test?.hits ?? 0)) return false
    return !needle || [pattern.name, pattern.cve, pattern.technology, pattern.description, pattern.dsl]
      .some((value) => String(value).toLowerCase().includes(needle))
  })
  const enabled = patterns.filter((pattern) => pattern.enabled && !pattern.archived).length

  return <aside className="flex h-full min-w-0 flex-col bg-[var(--panel)]">
    <div className="border-b border-[var(--line)] p-4 sm:p-5">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="text-lg font-semibold">{tr('hunt.flow.managePatterns')}</h2>
          <p className="mt-1 text-sm leading-relaxed text-[var(--muted)]">{tr('hunt.flow.libraryScopeHint')}</p>
          <p className="mt-2 text-sm text-[var(--muted)]"><span className="font-medium text-[var(--fg)]">{formatCount(enabled)} {tr('hunt.flow.enabled')}</span> · {formatCount(patterns.length)} {tr('hunt.flow.saved')}</p>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="primary" onClick={onNew}><Plus size={16} /> {tr('hunt.flow.addAPattern')}</Button>
        <Button onClick={onFromLogs} title={tr('hunt.workbench.fromLogsHint')}><ScrollText size={16} /> {tr('hunt.flow.startFromAccessLogs')}</Button>
        {onBatch && <Button disabled={runDisabled || !enabled} onClick={onBatch}><Play size={15} /> {tr('hunt.flow.checkAllPatterns')}</Button>}
      </div>
      {batchJob && ['queued', 'running'].includes(batchJob.state) && <div className="mt-3 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3" role="status">
        <div className="flex items-center gap-2 text-sm text-[var(--muted)]">
          <span className="min-w-0 flex-1">{batchJob.message || tr('hunt.workbench.batchRunning')}</span>
          <button type="button" onClick={onCancelBatch} title={tr('common.cancel')} aria-label={tr('common.cancel')}
            className="cursor-pointer rounded p-1 hover:bg-[var(--panel)]"><X size={16} /></button>
        </div>
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--line)]"><div className="h-full bg-[var(--accent)] transition-[width]" style={{ width: `${Math.max(2, Math.min(100, batchJob.progress * 100))}%` }} /></div>
      </div>}
      <div className="relative mt-4">
        <Search size={16} className="absolute left-3 top-3 text-[var(--muted)]" />
        <input value={search} onChange={(event) => onSearch(event.target.value)} aria-label={tr('hunt.flow.searchSavedPatterns')} placeholder={tr('hunt.flow.searchPlaceholder')}
          className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] py-2.5 pl-10 pr-3 text-sm outline-none focus:border-[var(--accent)]" />
      </div>
      <div className="mt-3 flex flex-wrap gap-1" role="group" aria-label={tr('hunt.flow.filterSavedPatterns')}>
        {(['active', 'own', 'bundled', 'archived', 'hit', 'all'] as const).map((value) => <button key={value} type="button" onClick={() => onFilter(value)} aria-pressed={filter === value}
          className={clsx('cursor-pointer rounded-md px-3 py-1.5 text-sm font-medium', filter === value ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)] hover:bg-[var(--panel-2)]')}>
          {value === 'active' ? tr('hunt.flow.enabledLabel') : tr(`hunt.workbench.filter.${value}`)}
        </button>)}
      </div>
    </div>
    <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-4 sm:p-5">
      {TECHNOLOGIES.map((technology) => {
        const group = visible.filter((pattern) => pattern.technology === technology)
        if (!group.length) return null
        return <section key={technology}>
          <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--muted)]">{tr(`hunt.technology.${technology}`)} <span className="tabular font-normal">({group.length})</span></h3>
          <div className="space-y-2">{group.map((pattern) => {
            const description = splitDescription(pattern.description).means
            const isEnabled = pattern.enabled && !pattern.archived
            return <article key={pattern.id} className={clsx('rounded-xl border p-4 transition-colors', selectedId === pattern.id ? 'border-[var(--accent)] bg-[var(--accent-soft)]' : 'border-[var(--line)] bg-[var(--panel-2)]')}>
              <button type="button" onClick={() => onSelect(pattern)} className="w-full cursor-pointer rounded text-left focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[var(--accent)]">
                <span className="block break-words text-base font-semibold">{pattern.name || tr('hunt.flow.unnamedPattern')}</span>
                {description && <span className="mt-1.5 line-clamp-2 block text-sm leading-relaxed text-[var(--muted)]">{description}</span>}
                <span className="mt-3 flex flex-wrap items-center gap-2">
                  <span className={clsx('text-sm font-medium', isEnabled ? 'text-[var(--accent-text)]' : 'text-[var(--muted)]')}>{pattern.archived ? tr('hunt.workbench.filter.archived') : isEnabled ? tr('hunt.flow.enabledLabel') : tr('hunt.flow.disabled')}</span>
                  <Tag>{pattern.source === 'bundled' ? tr('hunt.flow.includedWithShellhound') : tr('hunt.flow.workspacePattern')}</Tag><Tag>v{pattern.version}</Tag>
                  {pattern.cve && <Tag tone="accent">{pattern.cve}</Tag>}
                </span>
              </button>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                {onRun && isEnabled && <Button onClick={() => onRun(pattern)} disabled={runDisabled}><Play size={14} /> {tr('hunt.flow.checkThisPattern')}</Button>}
                <Button onClick={() => onEdit(pattern)}><PencilLine size={14} /> {tr('hunt.flow.edit')}</Button>
                <Button onClick={() => onDuplicate(pattern)} disabled={busy}><Copy size={14} /> {tr('hunt.workbench.duplicate')}</Button>
                {!pattern.archived && <Button onClick={() => onToggle(pattern)} disabled={busy}>{isEnabled ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}{isEnabled ? tr('hunt.flow.disable') : tr('hunt.flow.enable')}</Button>}
                {pattern.source === 'own' && !pattern.archived && <Button onClick={() => onArchive(pattern)} disabled={busy}><Archive size={14} /> {tr('hunt.workbench.archive')}</Button>}
              </div>
            </article>
          })}</div>
        </section>
      })}
      {!visible.length && <div className="rounded-xl border border-dashed border-[var(--line)] p-8 text-center text-sm leading-relaxed text-[var(--muted)]">{patterns.length ? tr('hunt.flow.noLibraryMatches') : tr('hunt.flow.emptyLibrary')}</div>}
    </div>
  </aside>
}
