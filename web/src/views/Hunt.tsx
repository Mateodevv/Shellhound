import { useEffect, useMemo, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Columns3, Library, PanelRight, type LucideIcon } from 'lucide-react'
import {
  api, del, post, type AccessRequestContext, type HuntPattern, type HuntRuleV2, type HuntTest,
  type Job,
  type HuntTestResponse,
} from '../api'
import type { Navigate } from '../App'
import { useT } from '../i18n'
import { Button, Modal, Toast } from '../components/ui'
import { HuntResults } from './hunt/HuntResults'
import { PatternLibrary } from './hunt/PatternLibrary'
import { RuleEditor } from './hunt/RuleEditor'
import {
  draftHash, emptyDraft, joinDescription, loadSession, patternDraft, saveSession, toDsl,
  type HuntSessionState,
} from './hunt/state'

type ValidatedRule = {
  rule: HuntRuleV2
  rule_hash: string
  dsl: string
  technology: HuntPattern['technology']
}

type ApplyResponse = {
  application_id: number
  pattern: HuntPattern
  findings: number
  already_applied: boolean
}

export function Hunt({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const [session, setSession] = useState<HuntSessionState>(() => loadSession(slug))
  const [cleanHash, setCleanHash] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [importText, setImportText] = useState('')
  const [confirmVariant, setConfirmVariant] = useState(false)
  const [disableOriginal, setDisableOriginal] = useState(true)
  const [batchJobId, setBatchJobId] = useState<number | null>(null)
  const [focus, setFocus] = useState<'library' | 'editor' | 'results'>('results')

  const library = useQuery({
    queryKey: ['patterns'],
    queryFn: () => api<{ patterns: HuntPattern[]; path: string }>('/api/patterns'),
  })
  const tests = useQuery({
    queryKey: ['hunt-tests', slug],
    queryFn: () => api<{ tests: HuntTest[] }>(`/api/cases/${slug}/hunt/tests?limit=500`),
  })
  const patterns = useMemo(() => library.data?.patterns ?? [], [library.data])
  const audits = useMemo(() => tests.data?.tests ?? [], [tests.data])
  const draft = session.draft
  const activeTest = audits.find((test) => test.id === session.testId) ?? null
  const selected = useMemo(() => new Set(session.selectedClusters), [session.selectedClusters])
  const seedRequestId = Number(new URLSearchParams(location.search).get('request')) || 0
  const seedRequest = useQuery({
    queryKey: ['access-request', slug, seedRequestId],
    queryFn: () => api<AccessRequestContext>(
      `/api/cases/${slug}/access/request/${seedRequestId}`),
    enabled: seedRequestId > 0,
  })
  const jobs = useQuery({
    queryKey: ['jobs', slug],
    queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    enabled: batchJobId !== null,
    refetchInterval: (query) => {
      const rows = query.state.data
      const job = rows?.find((item) => item.id === batchJobId)
      return job && ['queued', 'running'].includes(job.state) ? 600 : false
    },
  })
  const batchJob = jobs.data?.find((job) => job.id === batchJobId) ?? null

  const versions = useQuery({
    queryKey: ['pattern-versions', draft?.sourceId],
    queryFn: () => api<{ versions: Array<Record<string, unknown>> }>(
      `/api/patterns/${draft!.sourceId}/versions`),
    enabled: Boolean(draft?.sourceId),
  })

  useEffect(() => saveSession(slug, session), [session, slug])

  useEffect(() => {
    if (!seedRequestId || !seedRequest.data) return
    const request = seedRequest.data.request
    const rule: HuntRuleV2 = { client_match: 'any', requests: [{ clauses: [
      { field: 'uri', operator: 'equals', values: [request.uri] },
      { field: 'method', operator: 'equals', values: [request.method] },
    ] }] }
    const uri = request.uri.toLowerCase()
    const technology = uri.includes('wp-') || uri.includes('wordpress') ? 'wordpress'
      : uri.includes('option=com_') || uri.includes('/joomla') ? 'joomla' : 'generic'
    const next = emptyDraft({ name: `${request.method} ${request.uri}`.slice(0, 120),
      technology, means: tr('hunt.workbench.seedMeaning'), rule, dsl: toDsl(rule) })
    setCleanHash('')
    setFocus('editor')
    setSession((state) => ({ ...state, selectedId: '', draft: next, editorOpen: true, testId: null,
      testedHash: '', selectedClusters: [] }))
    const url = new URL(location.href)
    url.searchParams.delete('request')
    history.replaceState(null, '', url)
  }, [seedRequest.data, seedRequestId, tr])

  useEffect(() => {
    if (!batchJob || ['queued', 'running'].includes(batchJob.state)) return
    void qc.invalidateQueries({ queryKey: ['hunt-tests', slug] })
  }, [batchJob, qc, slug])

  useEffect(() => {
    if (!patterns.length || session.draft) return
    const initial = patterns.find((pattern) => pattern.id === session.selectedId)
      ?? patterns.find((pattern) => pattern.enabled && !pattern.archived)
      ?? patterns[0]
    if (!initial) return
    const next = patternDraft(initial)
    const last = audits.find((test) => test.pattern_id === initial.id) ?? null
    const hash = draftHash(next)
    setCleanHash(hash)
    setSession((state) => ({ ...state, selectedId: initial.id, draft: next, editorOpen: false,
      testId: last?.id ?? null, testedHash: last?.rule_hash === initial.rule_hash ? hash : '',
      selectedClusters: [] }))
  }, [audits, patterns, session.draft, session.selectedId])

  useEffect(() => {
    if (!session.draft || cleanHash) return
    const source = patterns.find((pattern) => pattern.id === session.draft?.sourceId)
    setCleanHash(source ? draftHash(patternDraft(source)) : '')
  }, [cleanHash, patterns, session.draft])

  const mutateSession = (update: Partial<HuntSessionState>) =>
    setSession((state) => ({ ...state, ...update }))
  const loadPattern = (pattern: HuntPattern, edit: boolean) => {
    const next = patternDraft(pattern)
    const last = audits.find((test) => test.pattern_id === pattern.id) ?? null
    const hash = draftHash(next)
    setCleanHash(hash)
    setError('')
    mutateSession({ selectedId: pattern.id, draft: next, editorOpen: edit, testId: last?.id ?? null,
      testedHash: last?.rule_hash === pattern.rule_hash ? hash : '', selectedClusters: [] })
    setFocus(edit ? 'editor' : 'results')
  }
  const choose = (pattern: HuntPattern) => loadPattern(pattern, false)
  const beginEdit = (pattern: HuntPattern) => loadPattern(pattern, true)
  const resumeEdit = () => {
    if (!draft) return
    mutateSession({ editorOpen: true })
    setFocus('editor')
  }
  const closeEditor = () => {
    mutateSession({ editorOpen: false })
    setFocus('results')
  }
  const create = () => {
    const next = emptyDraft()
    setCleanHash('')
    setError('')
    setFocus('editor')
    mutateSession({ selectedId: '', draft: next, editorOpen: true, testId: null,
      testedHash: '', selectedClusters: [] })
  }

  const validate = useMutation({
    mutationFn: () => post<ValidatedRule>('/api/patterns/validate', { dsl: draft?.dsl }),
    onSuccess: (result) => {
      if (!draft) return
      const next = { ...draft, rule: result.rule, dsl: result.dsl,
        technology: draft.source === 'new' && draft.technology === 'generic'
          ? result.technology : draft.technology }
      mutateSession({ draft: next })
      setError('')
    },
    onError: (cause: Error) => setError(cause.message),
  })

  const testRule = useMutation({
    mutationFn: () => {
      if (!draft) throw new Error(tr('hunt.workbench.selectRule'))
      return post<HuntTestResponse>(`/api/cases/${slug}/hunt/tests`, {
        pattern_id: draft.sourceId,
        ...(draft.textMode ? { dsl: draft.dsl } : { rule: draft.rule }),
      })
    },
    onSuccess: (response) => {
      if (!draft) return
      const next = { ...draft, rule: response.test.rule, dsl: response.test.dsl }
      mutateSession({ draft: next, testedHash: draftHash(next), testId: response.test.id,
        selectedClusters: [] })
      setFocus('results')
      setError('')
      qc.setQueryData<{ tests: HuntTest[] }>(['hunt-tests', slug], (old) => ({
        tests: [response.test, ...(old?.tests ?? []).filter((item) => item.id !== response.test.id)],
      }))
    },
    onError: (cause: Error) => setError(cause.message),
  })

  const applyRule = useMutation({
    mutationFn: (disable: boolean) => {
      if (!draft || !activeTest) throw new Error(tr('hunt.workbench.testFirst'))
      return post<ApplyResponse>(`/api/cases/${slug}/hunt/tests/${activeTest.id}/apply`, {
        cluster_keys: [...selected], pattern_id: draft.sourceId,
        expected_version: draft.expectedVersion,
        disable_original: disable,
        pattern: { name: draft.name, cve: draft.cve, technology: draft.technology,
          description: joinDescription(draft.means, draft.notMeans), rule: draft.rule },
      })
    },
    onSuccess: (response) => {
      const next = patternDraft(response.pattern)
      const hash = draftHash(next)
      setCleanHash(hash)
      mutateSession({ selectedId: response.pattern.id, draft: next, editorOpen: false, testedHash: hash,
        selectedClusters: [] })
      setFocus('results')
      setConfirmVariant(false)
      setNotice(response.already_applied
        ? tr('hunt.workbench.alreadyApplied')
        : tr('hunt.workbench.applySuccess', { findings: response.findings }))
      setError('')
      void qc.invalidateQueries({ queryKey: ['patterns'] })
      void qc.invalidateQueries({ queryKey: ['findings'] })
      void qc.invalidateQueries({ queryKey: ['dashboard', slug] })
    },
    onError: (cause: Error) => { setConfirmVariant(false); setError(cause.message) },
  })

  const clone = useMutation({
    mutationFn: (pattern: HuntPattern) => post<HuntPattern>(
      `/api/patterns/${pattern.id}/clone`, { disable_original: false }),
    onSuccess: (pattern) => {
      qc.setQueryData<{ patterns: HuntPattern[]; path: string }>(['patterns'], (old) =>
        old ? { ...old, patterns: [...old.patterns, pattern] } : old)
      beginEdit(pattern)
    },
    onError: (cause: Error) => setError(cause.message),
  })

  const toggle = useMutation({
    mutationFn: (pattern: HuntPattern) => post(`/api/patterns/${pattern.id}/enabled`, {
      enabled: !pattern.enabled,
    }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['patterns'] }),
    onError: (cause: Error) => setError(cause.message),
  })
  const archive = useMutation({
    mutationFn: (pattern: HuntPattern) => del(`/api/patterns/${pattern.id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['patterns'] }),
    onError: (cause: Error) => setError(cause.message),
  })
  const importPatterns = useMutation({
    mutationFn: () => post<{ added: number; skipped: number; invalid: number }>(
      '/api/patterns', { text: importText }),
    onSuccess: (result) => {
      setImportText('')
      setNotice(tr('hunt.import.result', result))
      void qc.invalidateQueries({ queryKey: ['patterns'] })
    },
    onError: (cause: Error) => setError(cause.message),
  })
  const batch = useMutation({
    mutationFn: () => post<{ job_id: number; batch_id: string; patterns: number }>(
      `/api/cases/${slug}/hunt/batch-tests`, {}),
    onSuccess: (result) => {
      setBatchJobId(result.job_id)
      setNotice(tr('hunt.workbench.batchStarted', { n: result.patterns }))
    },
    onError: (cause: Error) => setError(cause.message),
  })
  const cancelBatch = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/jobs/${batchJobId}/cancel`),
    onSuccess: () => void jobs.refetch(),
    onError: (cause: Error) => setError(cause.message),
  })
  const restore = useMutation({
    mutationFn: (version: number) => {
      if (!draft?.sourceId) throw new Error(tr('hunt.workbench.selectRule'))
      return post<HuntPattern>(`/api/patterns/${draft.sourceId}/versions/${version}/restore`, {
        expected_version: draft.expectedVersion,
      })
    },
    onSuccess: (pattern) => {
      beginEdit(pattern)
      void qc.invalidateQueries({ queryKey: ['patterns'] })
      void qc.invalidateQueries({ queryKey: ['pattern-versions', pattern.id] })
    },
    onError: (cause: Error) => setError(cause.message),
  })

  const currentHash = draftHash(draft)
  const dirty = Boolean(draft && currentHash !== cleanHash)
  const tested = Boolean(activeTest && session.testedHash && session.testedHash === currentHash)
  const stale = Boolean(activeTest && session.testedHash && session.testedHash !== currentHash)
  const pending = validate.isPending || testRule.isPending || applyRule.isPending
    || clone.isPending || restore.isPending

  const beginResize = (which: 'library' | 'editor') =>
    (event: ReactPointerEvent<HTMLDivElement>) => {
      event.preventDefault()
      const start = event.clientX
      const initial = which === 'library' ? session.libraryWidth : session.editorWidth
      const move = (next: PointerEvent) => {
        const value = Math.round(Math.max(which === 'library' ? 260 : 400,
          Math.min(which === 'library' ? 520 : 820, initial + next.clientX - start)))
        setSession((state) => ({ ...state,
          [which === 'library' ? 'libraryWidth' : 'editorWidth']: value }))
      }
      const up = () => {
        window.removeEventListener('pointermove', move)
        window.removeEventListener('pointerup', up)
      }
      window.addEventListener('pointermove', move)
      window.addEventListener('pointerup', up)
    }

  const editorOpen = session.editorOpen && Boolean(draft)
  const resultColumn = session.resultCollapsed ? '48px' : 'minmax(420px,1fr)'
  const grid = editorOpen
    ? `${session.libraryCollapsed ? 48 : session.libraryWidth}px 5px ${session.editorWidth}px 5px ${resultColumn}`
    : `${session.libraryCollapsed ? 48 : session.libraryWidth}px 5px ${resultColumn}`
  const focusTabs: Array<['library' | 'editor' | 'results', LucideIcon]> = editorOpen
    ? [['library', Library], ['editor', Columns3], ['results', PanelRight]]
    : [['library', Library], ['results', PanelRight]]
  return <>
    <div className="mb-2 flex items-center rounded-lg border border-[var(--line)] bg-[var(--panel)] p-1 min-[1400px]:hidden">
      {focusTabs.map(([value, Icon]) => <button
        key={value} type="button" onClick={() => setFocus(value)}
        className={clsx('flex flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-[11px] font-semibold',
          focus === value ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]' : 'text-[var(--muted)]')}>
        <Icon size={12} />{tr(`hunt.workbench.${value}`)}
      </button>)}
    </div>
    <div className="grid h-[calc(100dvh-116px)] min-h-[620px] overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)] shadow-sm max-[1399px]:grid-cols-1"
      style={{ gridTemplateColumns: grid }}>
      <div className={clsx('min-h-0 min-w-0 max-[1399px]:col-span-full', focus !== 'library' && 'max-[1399px]:hidden')}>
        <PatternLibrary patterns={patterns} tests={audits} selectedId={session.selectedId}
          search={session.search} filter={session.filter} collapsed={session.libraryCollapsed}
          busy={batch.isPending} onSearch={(search) => mutateSession({ search })}
          onFilter={(filter) => mutateSession({ filter })} onSelect={choose} onEdit={beginEdit} onNew={create}
          onDuplicate={(pattern) => clone.mutate(pattern)} onToggle={(pattern) => toggle.mutate(pattern)}
          onArchive={(pattern) => archive.mutate(pattern)} onBatch={() => batch.mutate()}
          onFromLogs={() => gotoView('logs')}
          onCollapse={() => mutateSession({ libraryCollapsed: !session.libraryCollapsed })}
          importText={importText} onImportText={setImportText}
          onImport={() => importPatterns.mutate()} batchJob={batchJob}
          onCancelBatch={() => cancelBatch.mutate()} />
      </div>
      <div onPointerDown={beginResize('library')}
        className="cursor-col-resize bg-[var(--line)] transition-colors hover:bg-[var(--accent)] max-[1399px]:hidden" />
      {editorOpen && <><div className={clsx('min-h-0 min-w-0 max-[1399px]:col-span-full', focus !== 'editor' && 'max-[1399px]:hidden')}>
        <RuleEditor draft={draft} dirty={dirty} tested={tested} stale={stale}
          selectedClusters={selected.size} pending={pending} error={error}
          versions={versions.data?.versions ?? []}
          onChange={(next) => mutateSession({ draft: next })}
          onTest={() => testRule.mutate()}
          onApply={() => draft?.source === 'bundled' && dirty
            ? setConfirmVariant(true) : applyRule.mutate(false)}
          onValidateDsl={() => validate.mutate()}
          onRestore={(version) => restore.mutate(version)} onClose={closeEditor} />
      </div>
      <div onPointerDown={beginResize('editor')}
        className="cursor-col-resize bg-[var(--line)] transition-colors hover:bg-[var(--accent)] max-[1399px]:hidden" /></>}
      <div className={clsx('min-h-0 min-w-0 max-[1399px]:col-span-full', focus !== 'results' && 'max-[1399px]:hidden')}>
        <HuntResults slug={slug} test={activeTest} selected={selected}
          collapsed={session.resultCollapsed}
          ruleName={draft?.name}
          onSelected={(value) => mutateSession({ selectedClusters: [...value] })}
          onCollapse={() => mutateSession({ resultCollapsed: !session.resultCollapsed })}
          onEdit={draft ? resumeEdit : undefined}
          editLabel={draft?.source === 'new' ? tr('hunt.workbench.resumeDraft') : tr('hunt.workbench.editRule')}
          gotoView={gotoView} />
      </div>
    </div>

    <Modal open={confirmVariant} onClose={() => setConfirmVariant(false)}
      title={tr('hunt.workbench.variantTitle')}>
      <p className="text-[12px] leading-relaxed text-[var(--muted)]">{tr('hunt.workbench.variantBody')}</p>
      <label className="mt-4 flex cursor-pointer items-start gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-[12px]">
        <input type="checkbox" checked={disableOriginal}
          onChange={(event) => setDisableOriginal(event.target.checked)} />
        <span><b className="block">{tr('hunt.workbench.disableOriginal')}</b>
          <span className="text-[11px] text-[var(--muted)]">{tr('hunt.workbench.disableOriginalHint')}</span></span>
      </label>
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={() => setConfirmVariant(false)}>{tr('common.cancel')}</Button>
        <Button variant="primary" disabled={applyRule.isPending}
          onClick={() => applyRule.mutate(disableOriginal)}>{tr('hunt.workbench.createVariant')}</Button>
      </div>
    </Modal>
    <Toast open={Boolean(notice)} onClose={() => setNotice('')} tone="ok"
      title={tr('hunt.workbench.notice')}><span>{notice}</span></Toast>
  </>
}
