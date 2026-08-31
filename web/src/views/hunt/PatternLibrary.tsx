import clsx from 'clsx'
import {
  Archive, ChevronLeft, Copy, Download, MoreHorizontal, PencilLine, Play, Plus,
  Search, ScrollText, ToggleLeft, ToggleRight, Upload, X,
} from 'lucide-react'
import type { HuntPattern, HuntTechnology, HuntTest, Job } from '../../api'
import { downloadUrl } from '../../api'
import { formatCount } from '../../format'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui'

const TECHNOLOGIES: HuntTechnology[] = ['wordpress', 'joomla', 'generic', 'other']

export function PatternLibrary({
  patterns, tests, selectedId, search, filter, collapsed, busy,
  onSearch, onFilter, onSelect, onEdit, onNew, onDuplicate, onToggle, onArchive,
  onBatch, onFromLogs, onCollapse, importText, onImportText, onImport,
  batchJob, onCancelBatch,
}: {
  patterns: HuntPattern[]
  tests: HuntTest[]
  selectedId: string
  search: string
  filter: 'active' | 'all' | 'own' | 'bundled' | 'archived' | 'hit'
  collapsed: boolean
  busy: boolean
  onSearch: (value: string) => void
  onFilter: (value: 'active' | 'all' | 'own' | 'bundled' | 'archived' | 'hit') => void
  onSelect: (pattern: HuntPattern) => void
  onEdit: (pattern: HuntPattern) => void
  onNew: () => void
  onDuplicate: (pattern: HuntPattern) => void
  onToggle: (pattern: HuntPattern) => void
  onArchive: (pattern: HuntPattern) => void
  onBatch: () => void
  onFromLogs: () => void
  onCollapse: () => void
  importText: string
  onImportText: (value: string) => void
  onImport: () => void
  batchJob: Job | null
  onCancelBatch: () => void
}) {
  const tr = useT()
  if (collapsed) {
    return <aside className="flex h-full w-12 flex-col items-center border-r border-[var(--line)] bg-[var(--panel)] py-2">
      <button type="button" onClick={onCollapse} title={tr('hunt.workbench.library')}
        className="cursor-pointer rounded-lg p-2 text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]">
        <Search size={16} />
      </button>
      <button type="button" onClick={onNew} title={tr('hunt.workbench.new')}
        className="mt-2 cursor-pointer rounded-lg p-2 text-[var(--accent)] hover:bg-[var(--accent-soft)]">
        <Plus size={17} />
      </button>
    </aside>
  }

  const lastByPattern = new Map<string, HuntTest>()
  tests.forEach((test) => { if (test.pattern_id && !lastByPattern.has(test.pattern_id)) lastByPattern.set(test.pattern_id, test) })
  const needle = search.trim().toLowerCase()
  const visible = patterns.filter((pattern) => {
    const test = lastByPattern.get(pattern.id)
    if (filter === 'active' && !pattern.enabled) return false
    if (filter === 'own' && pattern.source !== 'own') return false
    if (filter === 'bundled' && pattern.source !== 'bundled') return false
    if (filter === 'archived' && !pattern.archived) return false
    if (filter === 'hit' && !(test?.hits ?? 0)) return false
    return !needle || [pattern.name, pattern.cve, pattern.technology, pattern.dsl]
      .some((value) => String(value).toLowerCase().includes(needle))
  })

  return <aside className="flex h-full min-w-0 flex-col border-r border-[var(--line)] bg-[var(--panel)]">
    <div className="border-b border-[var(--line)] p-3">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <div className="text-[12px] font-semibold">{tr('hunt.workbench.library')}</div>
          <div className="text-[10.5px] text-[var(--muted)]">{formatCount(patterns.length)} {tr('hunt.workbench.rules')}</div>
        </div>
        <button type="button" onClick={onCollapse} title={tr('common.close')}
          className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)]">
          <ChevronLeft size={15} />
        </button>
      </div>
      <div className="mt-3 flex gap-1.5">
        <Button variant="primary" onClick={onNew}><Plus size={13} /> {tr('hunt.workbench.new')}</Button>
        <Button onClick={onFromLogs} title={tr('hunt.workbench.fromLogsHint')}><ScrollText size={13} /></Button>
        <Button disabled={busy || !patterns.some((pattern) => pattern.enabled)} onClick={onBatch}>
          <Play size={13} /> {tr('hunt.workbench.testAll')}
        </Button>
        <details className="relative">
          <summary className="flex h-full cursor-pointer list-none items-center rounded-lg border border-[var(--line)] px-2 text-[var(--muted)] hover:bg-[var(--panel-2)]">
            <MoreHorizontal size={15} />
          </summary>
          <div className="absolute right-0 z-30 mt-1 w-72 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3 shadow-2xl">
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              {tr('hunt.manageLibrary')}
            </div>
            <textarea value={importText} onChange={(event) => onImportText(event.target.value)} rows={4}
              placeholder="/path/*.php | Name | CVE"
              className="mono w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[11px] outline-none focus:border-[var(--accent)]" />
            <div className="mt-2 flex gap-2">
              <Button disabled={!importText.trim()} onClick={onImport}><Upload size={12} /> {tr('hunt.import')}</Button>
              <a href={downloadUrl('/api/patterns/export')}
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] px-2 py-1.5 text-[11px] hover:bg-[var(--panel-2)]">
                <Download size={12} /> {tr('hunt.backup')}
              </a>
            </div>
          </div>
        </details>
      </div>
      {batchJob && ['queued', 'running'].includes(batchJob.state) && <div
        className="mt-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2">
        <div className="flex items-center gap-2 text-[9.5px] text-[var(--muted)]">
          <span className="min-w-0 flex-1 truncate">{batchJob.message || tr('hunt.workbench.batchRunning')}</span>
          <button type="button" onClick={onCancelBatch} title={tr('common.cancel')}
            className="cursor-pointer rounded p-0.5 hover:bg-[var(--panel)]"><X size={11} /></button>
        </div>
        <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-[var(--line)]">
          <div className="h-full bg-[var(--accent)] transition-[width]"
            style={{ width: `${Math.max(2, Math.min(100, batchJob.progress * 100))}%` }} />
        </div>
      </div>}
      <div className="relative mt-3">
        <Search size={13} className="absolute left-2.5 top-2.5 text-[var(--muted)]" />
        <input value={search} onChange={(event) => onSearch(event.target.value)}
          placeholder={tr('hunt.library.search')}
          className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] py-2 pl-8 pr-2 text-[11.5px] outline-none focus:border-[var(--accent)]" />
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {(['active', 'own', 'bundled', 'archived', 'hit', 'all'] as const).map((value) => <button key={value}
          type="button" onClick={() => onFilter(value)}
          className={clsx('cursor-pointer rounded-md px-2 py-1 text-[10px] font-semibold',
            filter === value ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
              : 'text-[var(--muted)] hover:bg-[var(--panel-2)]')}>
          {tr(`hunt.workbench.filter.${value}`)}
        </button>)}
      </div>
    </div>

    <div className="min-h-0 flex-1 overflow-y-auto">
      {TECHNOLOGIES.map((technology) => {
        const group = visible.filter((pattern) => pattern.technology === technology)
        if (!group.length) return null
        return <section key={technology}>
          <div className="sticky top-0 z-10 flex items-center border-y border-[var(--line-soft)] bg-[var(--panel-2)] px-3 py-1.5 text-[9.5px] font-bold uppercase tracking-[0.12em] text-[var(--muted)]">
            {tr(`hunt.technology.${technology}`)} <span className="ml-auto tabular">{group.length}</span>
          </div>
          {group.map((pattern) => {
            const test = lastByPattern.get(pattern.id)
            return <div key={pattern.id} className={clsx(
              'group border-b border-[var(--line-soft)] transition-colors',
              selectedId === pattern.id ? 'bg-[var(--accent-soft)] shadow-[inset_3px_0_0_var(--accent)]'
                : 'hover:bg-[var(--panel-2)]', !pattern.enabled && 'opacity-55')}>
              <button type="button" onClick={() => onSelect(pattern)}
                className="w-full cursor-pointer px-3 pb-1.5 pt-2.5 text-left">
                <span className="flex items-start gap-2">
                  <span className="min-w-0 flex-1 truncate text-[12px] font-semibold">{pattern.name || pattern.patterns[0]}</span>
                  {test && <span className={clsx('shrink-0 text-[10.5px] font-bold tabular',
                    (test.hits ?? 0) > 0 ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                    {formatCount(test.hits ?? 0)}
                  </span>}
                </span>
                <span className="mono mt-0.5 block truncate text-[10px] text-[var(--muted)]">{
                  pattern.dsl.split('\n').find((line) => line.startsWith('  '))?.trim()
                    || pattern.patterns.join(' · ')
                }</span>
                <span className="mt-1 flex flex-wrap gap-1">
                  <Tag>{pattern.source === 'bundled' ? tr('hunt.bundled') : tr('hunt.own')}</Tag>
                  <Tag>v{pattern.version}</Tag>
                  {pattern.cve && <Tag tone="accent">{pattern.cve}</Tag>}
                  {pattern.archived && <Tag>{tr('hunt.workbench.archived')}</Tag>}
                </span>
              </button>
              <div className="flex items-center justify-end gap-0.5 px-2 pb-1.5 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                <button type="button" onClick={() => onEdit(pattern)} title={tr('hunt.workbench.editRule')}
                  className="cursor-pointer rounded p-1 text-[var(--accent-text)] hover:bg-[var(--accent-soft)]"><PencilLine size={12} /></button>
                <button type="button" onClick={() => onDuplicate(pattern)} title={tr('hunt.workbench.duplicate')}
                  className="cursor-pointer rounded p-1 text-[var(--muted)] hover:bg-[var(--panel)] hover:text-[var(--fg)]"><Copy size={12} /></button>
                <button type="button" onClick={() => onToggle(pattern)} title={pattern.enabled ? tr('hunt.disable.hint') : tr('hunt.enable.hint')}
                  className="cursor-pointer rounded p-1 text-[var(--muted)] hover:bg-[var(--panel)]">
                  {pattern.enabled ? <ToggleRight size={14} className="text-[var(--accent)]" /> : <ToggleLeft size={14} />}
                </button>
                {pattern.source === 'own' && !pattern.archived && <button type="button" onClick={() => onArchive(pattern)}
                  title={tr('hunt.workbench.archive')}
                  className="cursor-pointer rounded p-1 text-[var(--muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]"><Archive size={12} /></button>}
              </div>
            </div>
          })}
        </section>
      })}
      {!visible.length && <div className="p-8 text-center text-[11.5px] text-[var(--muted)]">{tr('hunt.library.noMatch')}</div>}
    </div>
  </aside>
}
