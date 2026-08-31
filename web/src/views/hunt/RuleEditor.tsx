import clsx from 'clsx'
import {
  AlertTriangle, Braces, Check, ChevronRight, FlaskConical, GitCompare,
  Plus, RotateCcw, Save, Trash2, X,
} from 'lucide-react'
import type {
  HuntClause, HuntField, HuntOperator, HuntTechnology,
} from '../../api'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui'
import type { HuntDraft } from './state'
import { toDsl, updateClause } from './state'

const FIELDS: HuntField[] = [
  'uri', 'path', 'query', 'method', 'status', 'user_agent', 'referrer', 'host',
]
const TEXT_OPERATORS: HuntOperator[] = ['wildcard', 'contains', 'equals']
const TECHNOLOGIES: HuntTechnology[] = ['wordpress', 'joomla', 'generic', 'other']

function operators(field: HuntField): HuntOperator[] {
  return field === 'method' || field === 'status' ? ['in', 'equals'] : TEXT_OPERATORS
}

function nextOperator(field: HuntField): HuntOperator {
  return field === 'method' || field === 'status' ? 'in' : 'wildcard'
}

const VERSION_FIELDS = ['name', 'cve', 'technology', 'description', 'rule', 'archived', 'own_enabled'] as const

function changedFields(current: Record<string, unknown>, previous?: Record<string, unknown>) {
  if (!previous) return ['initial']
  return VERSION_FIELDS.filter((field) => JSON.stringify(current[field]) !== JSON.stringify(previous[field]))
}

export function RuleEditor({
  draft, dirty, tested, stale, selectedClusters, pending, error, versions,
  onChange, onTest, onApply, onValidateDsl, onRestore, onClose,
}: {
  draft: HuntDraft | null
  dirty: boolean
  tested: boolean
  stale: boolean
  selectedClusters: number
  pending: boolean
  error: string
  versions: Array<Record<string, unknown>>
  onChange: (draft: HuntDraft) => void
  onTest: () => void
  onApply: () => void
  onValidateDsl: () => void
  onRestore: (version: number) => void
  onClose: () => void
}) {
  const tr = useT()
  if (!draft) return <section className="flex h-full min-w-0 items-center justify-center border-r border-[var(--line)] bg-[var(--panel)] p-8 text-center">
    <div>
      <FlaskConical size={28} className="mx-auto text-[var(--muted)]" />
      <div className="mt-3 text-[13px] font-semibold">{tr('hunt.workbench.selectRule')}</div>
      <p className="mt-1 max-w-xs text-[11.5px] text-[var(--muted)]">{tr('hunt.workbench.selectRuleSub')}</p>
    </div>
  </section>

  const set = <K extends keyof HuntDraft>(key: K, value: HuntDraft[K]) => onChange({ ...draft, [key]: value })
  const setRule = (rule: HuntDraft['rule']) => onChange({ ...draft, rule, dsl: toDsl(rule) })
  const addRequest = () => setRule({ ...draft.rule, requests: [...draft.rule.requests, {
    clauses: [{ field: 'uri', operator: 'wildcard', values: [''] }],
  }] })
  const removeRequest = (index: number) => {
    if (draft.rule.requests.length === 1) return
    setRule({ ...draft.rule, requests: draft.rule.requests.filter((_, i) => i !== index) })
  }
  const addClause = (requestIndex: number) => {
    const rule = structuredClone(draft.rule)
    rule.requests[requestIndex].clauses.push({ field: 'uri', operator: 'wildcard', values: [''] })
    setRule(rule)
  }
  const removeClause = (requestIndex: number, clauseIndex: number) => {
    const rule = structuredClone(draft.rule)
    if (rule.requests[requestIndex].clauses.length === 1) return
    rule.requests[requestIndex].clauses.splice(clauseIndex, 1)
    setRule(rule)
  }

  return <section className="flex h-full min-w-0 flex-col border-r border-[var(--line)] bg-[var(--panel)]">
    <header className="sticky top-0 z-20 border-b border-[var(--line)] bg-[var(--panel)] p-3">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[12px] font-semibold">{tr('hunt.workbench.editor')}</span>
            <Tag>{draft.source === 'bundled' ? tr('hunt.bundled') : draft.source === 'own' ? tr('hunt.own') : tr('hunt.workbench.unsaved')}</Tag>
            {draft.expectedVersion && <Tag>v{draft.expectedVersion}</Tag>}
            {stale ? <Tag tone="warn">{tr('hunt.workbench.stale')}</Tag>
              : tested ? <Tag tone="accent"><Check size={10} /> {tr('hunt.workbench.tested')}</Tag>
                : dirty ? <Tag>{tr('hunt.workbench.unsaved')}</Tag> : null}
          </div>
          <div className="mt-1 truncate text-[10.5px] text-[var(--muted)]">
            {draft.source === 'bundled' ? tr('hunt.workbench.variantHint') : tr('hunt.edit.note')}
          </div>
        </div>
        <button type="button" onClick={onClose} title={tr('hunt.workbench.closeEditor')}
          aria-label={tr('hunt.workbench.closeEditor')}
          className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]">
          <X size={14} />
        </button>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Button disabled={pending} onClick={onTest}>
          <FlaskConical size={13} /> {pending ? tr('hunt.searching') : tr('hunt.workbench.test')}
        </Button>
        <Button variant="primary" disabled={pending || !tested || stale || selectedClusters === 0} onClick={onApply}>
          <Save size={13} /> {tr('hunt.workbench.saveApply')} ({selectedClusters})
        </Button>
      </div>
      {error && <div className="mt-2 rounded-lg border border-[var(--sev-high)]/30 bg-[var(--danger-soft)] px-2.5 py-2 text-[11px] text-[var(--danger-text)]">{error}</div>}
    </header>

    <div className="min-h-0 flex-1 overflow-y-auto p-3">
      <div className="grid grid-cols-[minmax(0,1fr)_120px] gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[9.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.field.name')}</span>
          <input value={draft.name} onChange={(event) => set('name', event.target.value)}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-2 text-[12px] outline-none focus:border-[var(--accent)]" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[9.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.field.cve')}</span>
          <input value={draft.cve} onChange={(event) => set('cve', event.target.value)} placeholder="CVE-…"
            className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-2 text-[11px] outline-none focus:border-[var(--accent)]" />
        </label>
      </div>
      <label className="mt-2 flex flex-col gap-1">
        <span className="text-[9.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.workbench.technology')}</span>
        <select value={draft.technology} onChange={(event) => set('technology', event.target.value as HuntTechnology)}
          className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-2 text-[11.5px] outline-none">
          {TECHNOLOGIES.map((value) => <option key={value} value={value}>{tr(`hunt.technology.${value}`)}</option>)}
        </select>
      </label>

      <div className="mt-4 flex items-center gap-2 border-b border-[var(--line-soft)] pb-2">
        <span className="mr-auto text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.workbench.logic')}</span>
        <button type="button" onClick={() => set('textMode', false)}
          className={clsx('cursor-pointer rounded px-2 py-1 text-[10px] font-semibold', !draft.textMode ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]')}>{tr('hunt.workbench.visual')}</button>
        <button type="button" onClick={() => set('textMode', true)}
          className={clsx('cursor-pointer rounded px-2 py-1 text-[10px] font-semibold', draft.textMode ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]')}><Braces size={11} className="inline" /> DSL</button>
      </div>

      {draft.textMode ? <div className="mt-3">
        <textarea value={draft.dsl} onChange={(event) => set('dsl', event.target.value)} rows={16}
          spellCheck={false}
          className="mono w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-[11px] leading-relaxed outline-none focus:border-[var(--accent)]" />
        <Button onClick={onValidateDsl} disabled={pending} className="mt-2"><Check size={12} /> {tr('hunt.workbench.validateDsl')}</Button>
      </div> : <div className="mt-3 space-y-3">
        <div className="flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2">
          <span className="text-[10.5px] text-[var(--muted)]">{tr('hunt.workbench.sameClient')}</span>
          <div className="ml-auto flex rounded-md border border-[var(--line)] bg-[var(--panel)] p-0.5">
            {(['any', 'all'] as const).map((mode) => <button key={mode} type="button"
              onClick={() => setRule({ ...draft.rule, client_match: mode })}
              className={clsx('cursor-pointer rounded px-2 py-1 text-[10px] font-bold uppercase',
                draft.rule.client_match === mode ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]')}>
              {mode}
            </button>)}
          </div>
        </div>

        {draft.rule.requests.map((request, requestIndex) => <div key={requestIndex}
          className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-2.5">
          <div className="mb-2 flex items-center gap-2">
            <span className="flex size-5 items-center justify-center rounded bg-[var(--accent-soft)] text-[10px] font-bold text-[var(--accent-text)]">{requestIndex + 1}</span>
            <span className="text-[10.5px] font-semibold">{tr('hunt.workbench.requestStep')}</span>
            {draft.rule.requests.length > 1 && <button type="button" onClick={() => removeRequest(requestIndex)}
              className="ml-auto cursor-pointer rounded p-1 text-[var(--muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]"><Trash2 size={12} /></button>}
          </div>
          <div className="space-y-1.5">
            {request.clauses.map((clause, clauseIndex) => <ClauseRow key={clauseIndex}
              clause={clause}
              onChange={(update) => setRule(updateClause(draft.rule, requestIndex, clauseIndex, update))}
              onRemove={() => removeClause(requestIndex, clauseIndex)}
              removable={request.clauses.length > 1} />)}
          </div>
          <button type="button" onClick={() => addClause(requestIndex)}
            className="mt-2 inline-flex cursor-pointer items-center gap-1 text-[10.5px] font-semibold text-[var(--accent-text)] hover:underline"><Plus size={11} /> {tr('hunt.workbench.addClause')}</button>
        </div>)}
        <Button onClick={addRequest}><Plus size={12} /> {tr('hunt.workbench.addRequest')}</Button>
      </div>}

      <div className="mt-4 grid gap-3">
        <label className="flex flex-col gap-1">
          <span className="text-[9.5px] font-bold uppercase tracking-wider text-[var(--accent-text)]">{tr('hunt.means.title')}</span>
          <textarea value={draft.means} onChange={(event) => set('means', event.target.value)} rows={4}
            className="resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2.5 text-[11.5px] leading-relaxed outline-none focus:border-[var(--accent)]" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[9.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.notMeans.title')}</span>
          <textarea value={draft.notMeans} onChange={(event) => set('notMeans', event.target.value)} rows={3}
            placeholder={tr('hunt.notMeans.fallback')}
            className="resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2.5 text-[11.5px] leading-relaxed outline-none focus:border-[var(--accent)]" />
        </label>
      </div>

      {versions.length > 0 && <details className="mt-4 rounded-lg border border-[var(--line)]">
        <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-[10.5px] font-semibold">
          <GitCompare size={12} /> {tr('hunt.workbench.versions')} ({versions.length}) <ChevronRight size={12} className="ml-auto" />
        </summary>
        <div className="border-t border-[var(--line)]">
          {[...versions].reverse().map((version) => {
            const previous = versions.find((candidate) => Number(candidate.version) === Number(version.version) - 1)
            const changes = changedFields(version, previous)
            return <div key={String(version.version)} className="border-b border-[var(--line-soft)] px-3 py-2 last:border-0">
              <div className="flex items-center gap-2">
                <span className="text-[10.5px] font-semibold">v{String(version.version)}</span>
                <span className="min-w-0 flex-1 truncate text-[10px] text-[var(--muted)]">{String(version.updated_at || version.created_at || '')}</span>
                {Number(version.version) !== draft.expectedVersion && <button type="button" onClick={() => onRestore(Number(version.version))}
                  className="inline-flex cursor-pointer items-center gap-1 rounded px-1.5 py-1 text-[10px] text-[var(--accent-text)] hover:bg-[var(--accent-soft)]"><RotateCcw size={10} /> {tr('hunt.workbench.restore')}</button>}
              </div>
              <details className="mt-1 text-[10px] text-[var(--muted)]">
                <summary className="cursor-pointer select-none hover:text-[var(--fg)]">
                  {tr('hunt.workbench.comparePrevious')} · {changes.join(', ')}
                </summary>
                <pre className="mono mt-1 max-h-36 overflow-auto whitespace-pre-wrap rounded-md bg-[var(--panel-2)] p-2 text-[9.5px]">{
                  JSON.stringify({ changes, rule: version.rule }, null, 2)
                }</pre>
              </details>
            </div>
          })}
        </div>
      </details>}

      {!tested && <div className="mt-4 flex gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-[10.5px] text-[var(--muted)]">
        <AlertTriangle size={13} className="shrink-0" /> {tr('hunt.workbench.testFirst')}
      </div>}
    </div>
  </section>
}

function ClauseRow({ clause, onChange, onRemove, removable }: {
  clause: HuntClause
  onChange: (update: Partial<HuntClause>) => void
  onRemove: () => void
  removable: boolean
}) {
  const tr = useT()
  return <div className="grid grid-cols-[96px_88px_minmax(0,1fr)_24px] items-center gap-1">
    <select value={clause.field} onChange={(event) => {
      const field = event.target.value as HuntField
      onChange({ field, operator: nextOperator(field) })
    }} aria-label={tr('hunt.workbench.field')}
      className="min-w-0 rounded-md border border-[var(--line)] bg-[var(--panel)] px-1.5 py-1.5 text-[10.5px] outline-none">
      {FIELDS.map((field) => <option key={field} value={field}>{tr(`hunt.field.${field}`)}</option>)}
    </select>
    <select value={clause.operator} onChange={(event) => onChange({ operator: event.target.value as HuntOperator })}
      aria-label={tr('hunt.workbench.operator')}
      className="min-w-0 rounded-md border border-[var(--line)] bg-[var(--panel)] px-1.5 py-1.5 text-[10px] outline-none">
      {operators(clause.field).map((operator) => <option key={operator} value={operator}>{tr(`hunt.operator.${operator}`)}</option>)}
    </select>
    <input value={clause.values.join(', ')} onChange={(event) => onChange({
      values: event.target.value.split(',').map((value) => value.trim()),
    })} placeholder={clause.field === 'status' ? '2xx, 403' : '*pattern*'}
      className="mono min-w-0 rounded-md border border-[var(--line)] bg-[var(--panel)] px-2 py-1.5 text-[10.5px] outline-none focus:border-[var(--accent)]" />
    <button type="button" disabled={!removable} onClick={onRemove}
      className="cursor-pointer rounded p-1 text-[var(--muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)] disabled:cursor-default disabled:opacity-20"><Trash2 size={11} /></button>
  </div>
}
