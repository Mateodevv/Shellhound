import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft } from 'lucide-react'
import { api, del, patch, post, type AccessRequestContext, type CaseDetail, type Dashboard,
  type HuntBatch, type HuntPattern, type HuntRuleV2, type HuntTest, type HuntTestResponse, type Job } from '../api'
import type { Navigate } from '../App'
import { useT } from '../i18n'
import { formatCount, formatLogTime } from '../format'
import { Button, Card, Modal, Toast } from '../components/ui'
import { HuntResults } from './hunt/HuntResults'
import { HuntRunOverview, ErrorMessage } from './hunt/HuntRunOverview'
import { HuntLibrarySummary, HuntResultsSummary } from './hunt/HuntOverview'
import { PatternLibrary } from './hunt/PatternLibrary'
import { RuleEditor } from './hunt/RuleEditor'
import { draftHash, emptyDraft, joinDescription, loadSession, patternDraft, saveSession, splitDescription, toDsl,
  type HuntDraft, type HuntSessionState } from './hunt/state'

export function Hunt({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  return <HuntCase key={slug} slug={slug} gotoView={gotoView} />
}

function HuntCase({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const [session, setSession] = useState<HuntSessionState>(() => loadSession(slug))
  const sessionRef = useRef(session)
  sessionRef.current = session
  // Editing fields keeps this identity; opening another draft replaces it.
  const draftIdentity = useRef(0)
  const headingRef = useRef<HTMLHeadingElement>(null)
  const [cleanHash, setCleanHash] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [confirmVariant, setConfirmVariant] = useState(false)
  const [disableOriginal, setDisableOriginal] = useState(true)
  const [replaceDraft, setReplaceDraft] = useState<HuntDraft | null>(null)
  const mutateSession = (update: Partial<HuntSessionState>) => setSession((state) => ({ ...state, ...update }))
  const library = useQuery({ queryKey: ['patterns'], queryFn: () => api<{ patterns: HuntPattern[]; path: string }>('/api/patterns') })
  const tests = useQuery({ queryKey: ['hunt-tests', slug], queryFn: () => api<{ tests: HuntTest[] }>(`/api/cases/${slug}/hunt/tests?limit=500`) })
  const [linkedTestId] = useState(() => Number(new URLSearchParams(location.search).get('section')) || 0)
  const linkedRecord = useQuery({ queryKey: ['hunt-tests', slug, linkedTestId], enabled: linkedTestId > 0,
    queryFn: () => api<{ tests: HuntTest[] }>(`/api/cases/${slug}/hunt/tests?test_id=${linkedTestId}`) })
  const linkedTest = linkedRecord.data?.tests[0] ?? null
  const showingEvidence = session.page === 'evidence'
  const caseInfo = useQuery({ queryKey: ['case', slug], queryFn: () => api<CaseDetail>(`/api/cases/${slug}`) })
  const dashboard = useQuery({ queryKey: ['dashboard', slug], queryFn: () => api<Dashboard>(`/api/cases/${slug}/dashboard`) })
  const jobs = useQuery({ queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    refetchInterval: (q) => q.state.data?.some((j) => ['queued', 'running'].includes(j.state)) ? 1500 : false })
  const runs = useQuery({ queryKey: ['hunt-batches', slug], queryFn: () => api<{ runs: HuntBatch[] }>(`/api/cases/${slug}/hunt/batch-tests`),
    refetchInterval: (q) => q.state.data?.runs.some((r) => ['queued', 'running'].includes(r.state)) ? 1000 : false })
  const runId = session.batchId || runs.data?.runs[0]?.batch_id || ''
  useEffect(() => { headingRef.current?.focus() }, [session.page, session.runPatternId, runId])
  const runQuery = useQuery({ queryKey: ['hunt-batch', slug, runId], enabled: Boolean(runId),
    queryFn: () => api<HuntBatch>(`/api/cases/${slug}/hunt/batch-tests/${encodeURIComponent(runId)}`),
    refetchInterval: (q) => ['queued', 'running'].includes(q.state.data?.state ?? '') ? 1000 : false })
  const run = runQuery.data
  const runPattern = run?.patterns.find((p) => p.id === session.runPatternId)
  const patterns = useMemo(() => library.data?.patterns ?? [], [library.data])
  const audits = useMemo(() => tests.data?.tests ?? [], [tests.data])
  const draft = session.draft
  const previewTest = audits.find((test) => test.id === session.testId) ?? null
  const activeTest = showingEvidence ? linkedTest : session.page === 'preview' ? previewTest : runPattern?.test ?? null
  const activePattern = patterns.find((p) => p.id === (session.page === 'preview' ? draft?.sourceId : runPattern?.id))
  const selected = useMemo(() => new Set(session.selectedClusters), [session.selectedClusters])
  const enabledPatterns = patterns.filter((p) => p.enabled && !p.archived)
  const busyJob = jobs.data?.find((j) => ['queued', 'running'].includes(j.state))
  const hasLogs = caseInfo.data?.evidence_items.some((item) => item.kind === 'access_logs')
  const indexReady = Boolean(caseInfo.data?.log_index.exists && caseInfo.data.log_index.fresh)
  const runReady = !caseInfo.isPending && !jobs.isPending && !library.isPending
    && !caseInfo.isError && !jobs.isError && !library.isError && indexReady && !busyJob
  const versions = useQuery({ queryKey: ['pattern-versions', draft?.sourceId], enabled: Boolean(draft?.sourceId),
    queryFn: () => api<{ versions: Array<Record<string, unknown>> }>(`/api/patterns/${draft!.sourceId}/versions`) })
  const seedRequestId = Number(new URLSearchParams(location.search).get('request')) || 0
  const seedRequest = useQuery({ queryKey: ['access-request', slug, seedRequestId], enabled: seedRequestId > 0,
    queryFn: () => api<AccessRequestContext>(`/api/cases/${slug}/access/request/${seedRequestId}`) })
  useEffect(() => {
    saveSession(slug, session)
    const url = new URL(location.href)
    if (url.searchParams.get('case') !== slug || url.searchParams.get('view') !== 'hunt') return
    if (showingEvidence) url.searchParams.set('section', String(linkedTestId))
    else if (session.page === 'overview') url.searchParams.delete('section')
    else url.searchParams.set('section', session.page)
    if (runId) url.searchParams.set('batch', runId)
    else url.searchParams.delete('batch')
    if (session.page === 'runs' && session.runPatternId) url.searchParams.set('pattern', session.runPatternId)
    else url.searchParams.delete('pattern')
    history.replaceState(null, '', url)
  }, [session, slug, runId, showingEvidence, linkedTestId])
  useEffect(() => {
    if (!draft || cleanHash) return
    const source = patterns.find((p) => p.id === draft.sourceId)
    if (source) setCleanHash(draftHash(patternDraft(source)))
  }, [cleanHash, patterns, draft])
  useEffect(() => {
    if (!seedRequestId || !seedRequest.data) return
    const request = seedRequest.data.request
    const rule: HuntRuleV2 = { client_match: 'any', requests: [{ clauses: [
      { field: 'uri', operator: 'equals', values: [request.uri] },
      { field: 'method', operator: 'equals', values: [request.method] },
    ] }] }
    const next = emptyDraft({ name: `${request.method} ${request.uri}`.slice(0, 120),
      means: tr('hunt.workbench.seedMeaning'), rule, dsl: toDsl(rule) })
    if (draft && draftHash(draft) !== cleanHash) setReplaceDraft(next)
    else { draftIdentity.current += 1; setCleanHash(''); setSession((s) => ({ ...s, draft: next, page: 'editor', testId: null, testedHash: '', selectedClusters: [] })) }
    const url = new URL(location.href); url.searchParams.delete('request'); history.replaceState(null, '', url)
  }, [seedRequest.data, seedRequestId, tr, draft, cleanHash])
  const openDraft = (next: HuntDraft) => {
    draftIdentity.current += 1
    setCleanHash(next.sourceId ? draftHash(next) : '')
    mutateSession({ draft: next, selectedId: next.sourceId, page: 'editor', editorOpen: true, testId: null, testedHash: '', selectedClusters: [] })
    setError(''); setReplaceDraft(null)
  }
  const chooseDraft = (next: HuntDraft) => {
    if (draft && draftHash(draft) !== cleanHash && draftHash(draft) !== draftHash(next)) setReplaceDraft(next)
    else openDraft(next)
  }
  const beginEdit = (pattern: HuntPattern) => {
    if (draft?.sourceId === pattern.id) mutateSession({ page: 'editor' })
    else chooseDraft(patternDraft(pattern))
  }
  const fail = (cause: Error) => setError(cause.message)
  const isCurrentDraft = (submitted: HuntDraft) => {
    const current = sessionRef.current.draft
    return current?.sourceId === submitted.sourceId && current.expectedVersion === submitted.expectedVersion
      && draftHash(current) === draftHash(submitted)
  }
  const installSavedDraft = (pattern: HuntPattern, submitted: HuntDraft, submittedIdentity: number) => {
    if (submittedIdentity !== draftIdentity.current) {
      setNotice(tr('hunt.flow.newerDraftKept')); return
    }
    if (!isCurrentDraft(submitted)) {
      const current = sessionRef.current.draft
      if (current && current.sourceId === submitted.sourceId
          && current.expectedVersion === submitted.expectedVersion) {
        setCleanHash(draftHash(patternDraft(pattern)))
        // A create or bundled clone acquires its own identity on success.
        // Keep later edits, but save them as the next version of this pattern.
        mutateSession({ draft: { ...current, sourceId: pattern.id, source: pattern.source,
          expectedVersion: pattern.version }, selectedId: pattern.id })
      }
      setNotice(tr('hunt.flow.newerDraftKept')); return
    }
    const next = patternDraft(pattern)
    setCleanHash(draftHash(next))
    mutateSession({ draft: next, selectedId: next.sourceId, testId: null, testedHash: '' })
    setNotice(tr('hunt.flow.savedNotice'))
  }
  const validate = useMutation({ mutationFn: (submitted: HuntDraft) => post<{ rule: HuntRuleV2; dsl: string }>('/api/patterns/validate', { dsl: submitted.dsl }),
    onSuccess: (r, submitted) => {
      if (isCurrentDraft(submitted)) mutateSession({ draft: { ...submitted, rule: r.rule, dsl: r.dsl, textMode: false } })
      else setNotice(tr('hunt.flow.newerDraftKept'))
      setError('')
    }, onError: fail })
  const testRule = useMutation({ mutationFn: (submitted: HuntDraft) => post<HuntTestResponse>(`/api/cases/${slug}/hunt/tests`, {
    pattern_id: submitted.sourceId, name: submitted.name, cve: submitted.cve, ...(submitted.textMode ? { dsl: submitted.dsl } : { rule: submitted.rule }),
  }), onSuccess: (r, submitted) => {
    qc.setQueryData<{ tests: HuntTest[] }>(['hunt-tests', slug], (old) => ({ tests: [r.test, ...(old?.tests ?? []).filter((t) => t.id !== r.test.id)] }))
    if (isCurrentDraft(submitted) && sessionRef.current.page === 'editor') {
      const next = { ...submitted, rule: r.test.rule, dsl: r.test.dsl }
      mutateSession({ draft: next, testedHash: draftHash(next), testId: r.test.id, selectedClusters: [], page: 'preview' })
    } else setNotice(tr('hunt.flow.newerDraftKept'))
    setError('')
  }, onError: fail })
  const saveRule = useMutation({ mutationFn: async ({ draft, disable }: { draft: HuntDraft; disable: boolean; identity: number }) => {
    const metadata = { name: draft.name, cve: draft.cve, technology: draft.technology,
      description: joinDescription(draft.means, draft.notMeans), ...(draft.textMode ? { dsl: draft.dsl } : { rule: draft.rule }) }
    if (draft.source === 'bundled') return post<HuntPattern>(`/api/patterns/${draft.sourceId}/clone`, { ...metadata, disable_original: disable })
    if (draft.source === 'own') return patch<HuntPattern>(`/api/patterns/${draft.sourceId}`, { ...metadata, expected_version: draft.expectedVersion })
    return (await post<{ entry: HuntPattern }>('/api/patterns', metadata)).entry
  }, onSuccess: (p, submitted) => {
    installSavedDraft(p, submitted.draft, submitted.identity); setConfirmVariant(false)
    void qc.invalidateQueries({ queryKey: ['patterns'] }); void qc.invalidateQueries({ queryKey: ['pattern-versions', p.id] })
  }, onError: (e: Error) => { setConfirmVariant(false); fail(e) } })
  const batch = useMutation({ mutationFn: (ids?: string[]) => post<{ job_id: number; batch_id: string; patterns: number }>(`/api/cases/${slug}/hunt/batch-tests`, ids ? { ids } : {}),
    onSuccess: (r, ids) => {
      mutateSession({ batchId: r.batch_id, runPatternId: '', selectedClusters: [], page: ids ? 'runs' : 'overview' }); setError('')
      void qc.invalidateQueries({ queryKey: ['hunt-batches', slug] }); void qc.invalidateQueries({ queryKey: ['jobs', slug] })
    }, onError: fail })
  const cancelBatch = useMutation({ mutationFn: () => post(`/api/cases/${slug}/jobs/${run?.job_id}/cancel`),
    onSuccess: () => { void runQuery.refetch(); void jobs.refetch() }, onError: fail })
  const applyRule = useMutation({ mutationFn: () => {
    if (!activeTest || !activePattern) throw new Error(tr('hunt.flow.saveBeforeEvidence'))
    return post<{ findings: number; already_applied: boolean }>(`/api/cases/${slug}/hunt/tests/${activeTest.id}/apply`, {
      cluster_keys: [...selected], pattern_id: activePattern.id, expected_version: activePattern.version,
    })
  }, onSuccess: (r) => {
    mutateSession({ selectedClusters: [] }); setNotice(r.already_applied ? tr('hunt.flow.alreadyAdded') : tr(r.findings === 1 ? 'hunt.flow.findingAdded' : 'hunt.flow.findingsAdded', { n: r.findings })); setError('')
    void qc.invalidateQueries({ queryKey: ['findings'] }); void qc.invalidateQueries({ queryKey: ['dashboard', slug] })
  }, onError: fail })
  const clone = useMutation({ mutationFn: (p: HuntPattern) => post<HuntPattern>(`/api/patterns/${p.id}/clone`, { disable_original: false }),
    onSuccess: (p) => { chooseDraft(patternDraft(p)); void qc.invalidateQueries({ queryKey: ['patterns'] }) }, onError: fail })
  const toggle = useMutation({ mutationFn: (p: HuntPattern) => post(`/api/patterns/${p.id}/enabled`, { enabled: !p.enabled }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['patterns'] }), onError: fail })
  const archive = useMutation({ mutationFn: (p: HuntPattern) => del(`/api/patterns/${p.id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['patterns'] }), onError: fail })
  const restore = useMutation({ mutationFn: ({ version, draft }: { version: number; draft: HuntDraft; identity: number }) => post<HuntPattern>(`/api/patterns/${draft.sourceId}/versions/${version}/restore`, { expected_version: draft.expectedVersion }),
    onSuccess: (p, submitted) => { installSavedDraft(p, submitted.draft, submitted.identity); void qc.invalidateQueries({ queryKey: ['patterns'] }); void qc.invalidateQueries({ queryKey: ['pattern-versions', p.id] }) }, onError: fail })
  const dirty = Boolean(draft && draftHash(draft) !== cleanHash)
  const tested = Boolean(previewTest && session.testedHash === draftHash(draft))
  const stale = Boolean(previewTest && session.testedHash !== draftHash(draft))
  const pending = validate.isPending || testRule.isPending || saveRule.isPending || restore.isPending
  const currentRun = runs.data?.runs.find((r) => ['queued', 'running'].includes(r.state))
  const canRun = runReady && !runs.isPending && !runs.isError && !currentRun && !batch.isPending
  const metadata = showingEvidence ? { name: tr('hunt.linked.title', { id: linkedTestId }), means: '', notMeans: '' } : session.page === 'preview' ? { name: draft?.name, means: draft?.means, notMeans: draft?.notMeans }
    : { name: runPattern?.name, ...splitDescription(runPattern?.description ?? '') }
  const applyHint = showingEvidence ? tr('hunt.linked.evidenceHint') : session.page === 'preview' ? tr('hunt.flow.previewApplyHint')
    : !run?.fresh ? tr('hunt.flow.staleApplyHint')
      : !activePattern || activePattern.rule_hash !== activeTest?.rule_hash || activePattern.version !== activeTest?.pattern_version
        ? tr('hunt.flow.changedApplyHint') : ''
  const openOverview = () => mutateSession({ page: 'overview', selectedClusters: [] })
  const scope = <div className="space-y-2">
    {caseInfo.isPending || library.isPending || jobs.isPending ? <p role="status">{tr('hunt.flow.loadingPrerequisites')}</p>
      : caseInfo.isError || library.isError || jobs.isError ? <p>{tr('hunt.overview.prerequisitesUnavailable')}</p>
        : !hasLogs || !indexReady ? <div className="flex flex-wrap items-center justify-center gap-3 text-[var(--review-text)]">
          <span>{!hasLogs ? tr('hunt.flow.logsRequired') : tr('hunt.flow.indexRequired')}</span>
          <Button onClick={() => gotoView('evidence')}>{!hasLogs ? tr('hunt.flow.addAccessLogs') : tr('case.action.viewAnalysis')}</Button>
        </div> : <>
          <p>{tr('hunt.flow.indexScope', { requests: formatCount(caseInfo.data?.log_index.lines), patterns: enabledPatterns.length })}</p>
          {dashboard.data?.logs && <p>{formatLogTime(dashboard.data.logs.first_epoch, 0, { withZone: true, mode: 'utc' })} → {formatLogTime(dashboard.data.logs.last_epoch, 0, { withZone: true, mode: 'utc' })}</p>}
        </>}
    {!library.isPending && !library.isError && !enabledPatterns.length && <p className="text-[var(--review-text)]">{tr('hunt.overview.enableBelow')}</p>}
    {busyJob && <p role="status" className="text-[var(--review-text)]">{busyJob.kind === 'hunt' ? tr('hunt.flow.runningNotice') : tr('hunt.flow.analysisRunning')}</p>}
  </div>

  return <div className="mx-auto max-w-[1400px] space-y-5 pb-8">
    {session.page !== 'overview' && <Button variant="ghost" onClick={openOverview}><ArrowLeft size={16} />{tr('hunt.overview.back')}</Button>}
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div className="max-w-2xl"><h1 ref={headingRef} tabIndex={-1} className="text-2xl font-semibold outline-none">{tr('hunt.workbench.notice')}</h1>
        <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{tr('hunt.flow.purpose')}</p></div>
    </header>
    {session.page !== 'overview' && <div className="text-sm text-[var(--muted)]">{scope}</div>}
    {error && <ErrorMessage message={error} />}
    {[library, caseInfo, jobs, runs].map((q, i) => q.isError && <ErrorMessage key={i} message={q.error.message} onRetry={() => void q.refetch()} />)}
    {session.page === 'overview' ? <>
      {runQuery.isError && <ErrorMessage message={runQuery.error.message} onRetry={() => void runQuery.refetch()} />}
      <HuntResultsSummary run={run} loading={runs.isPending || Boolean(runId && runQuery.isPending)}
        unavailable={runs.isError || runQuery.isError} canRun={canRun} enabled={enabledPatterns.length} starting={batch.isPending}
        scope={scope} onStart={() => batch.mutate(undefined)} onResults={() => mutateSession({ page: 'runs', runPatternId: '', batchId: runId, selectedClusters: [] })}
        onCancel={() => cancelBatch.mutate()} cancelling={cancelBatch.isPending} />
      <HuntLibrarySummary patterns={patterns} loading={library.isPending} unavailable={library.isError}
        onLibrary={() => mutateSession({ page: 'library' })} onNew={() => chooseDraft(emptyDraft())}
        onResume={draft ? () => mutateSession({ page: 'editor' }) : undefined} />
    </> : session.page === 'library' ? <>
      {draft && <div className="flex justify-end"><Button onClick={() => mutateSession({ page: 'editor' })}>{tr('hunt.flow.resumeDraft')}</Button></div>}
      <Card className="overflow-hidden"><PatternLibrary patterns={patterns} tests={audits} selectedId={session.selectedId}
        search={session.search} filter={session.filter} collapsed={false}
        busy={clone.isPending || toggle.isPending || archive.isPending} runDisabled={!canRun}
        onSearch={(search) => mutateSession({ search })} onFilter={(filter) => mutateSession({ filter })}
        onSelect={beginEdit} onEdit={beginEdit} onNew={() => chooseDraft(emptyDraft())}
        onDuplicate={(p) => clone.mutate(p)} onToggle={(p) => toggle.mutate(p)} onArchive={(p) => archive.mutate(p)}
        onRun={(p) => batch.mutate([p.id])} onFromLogs={() => gotoView('logs')} onCollapse={openOverview}
        batchJob={null} onCancelBatch={() => cancelBatch.mutate()} /></Card>
    </> : session.page === 'editor' ? <div className="mx-auto max-w-4xl overflow-hidden rounded-xl border border-[var(--line)]">
      <RuleEditor draft={draft} dirty={dirty} tested={tested} stale={stale} selectedClusters={0} pending={pending}
        error={error} versions={versions.data?.versions ?? []} onChange={(next) => mutateSession({ draft: next })}
        onTest={() => draft && testRule.mutate(structuredClone(draft))} onSave={() => draft?.source === 'bundled' ? setConfirmVariant(true) : draft && saveRule.mutate({ draft: structuredClone(draft), disable: false, identity: draftIdentity.current })}
        onValidateDsl={() => draft && validate.mutate(structuredClone(draft))} onRestore={(version) => draft && restore.mutate({ version, draft: structuredClone(draft), identity: draftIdentity.current })} onClose={() => mutateSession({ page: 'library' })} />
      {draft?.sourceId && !dirty && <div className="border-t border-[var(--line)] bg-[var(--panel)] p-4">
        <Button disabled={!canRun || !patterns.find((p) => p.id === draft.sourceId)?.enabled} onClick={() => batch.mutate([draft.sourceId])}>{tr('hunt.flow.checkThisSavedPattern')}</Button></div>}
    </div> : <>
      {session.page === 'preview' || showingEvidence || runPattern ? <>
        <Button variant="ghost" onClick={() => mutateSession({ page: showingEvidence ? 'overview' : session.page === 'preview' ? 'editor' : 'runs', runPatternId: '', selectedClusters: [] })}>
          <ArrowLeft size={16} /> {showingEvidence ? tr('hunt.overview.back') : session.page === 'preview' ? tr('hunt.flow.backToEditor') : tr('hunt.flow.backToRunOverview')}</Button>
        {showingEvidence && linkedRecord.isError && <ErrorMessage message={linkedRecord.error.message} onRetry={() => void linkedRecord.refetch()} />}
        {showingEvidence && linkedRecord.data && !linkedTest && <p role="alert">{tr('hunt.linked.missing')}</p>}
        <HuntResults key={`${activeTest?.id}:${session.page}`} slug={slug} test={activeTest}
          ruleName={metadata.name} ruleMeaning={metadata.means} ruleNotMeaning={metadata.notMeans}
          selected={selected} onSelected={(value) => mutateSession({ selectedClusters: [...value] })}
          fresh={session.page === 'preview' || showingEvidence ? indexReady : Boolean(run?.fresh)} applyHint={applyHint}
          applying={applyRule.isPending} onApply={() => applyRule.mutate()} onEdit={!showingEvidence && activePattern ? () => beginEdit(activePattern) : undefined} />
      </> : <>
        {runQuery.isError && <ErrorMessage message={runQuery.error.message} onRetry={() => void runQuery.refetch()} />}
        {(runs.isPending || (runId && runQuery.isPending)) ? <p role="status" className="p-6 text-sm">{tr('hunt.flow.loadingPatternChecks')}</p>
          : !runs.isError && !runQuery.isError && <HuntRunOverview run={run} runs={runs.data?.runs ?? []}
            onRun={(batchId) => mutateSession({ batchId, runPatternId: '', selectedClusters: [] })}
            onPattern={(p) => mutateSession({ runPatternId: p.id, selectedClusters: [], batchId: runId })}
            onCancel={() => cancelBatch.mutate()} cancelling={cancelBatch.isPending} />}
      </>}
    </>}
    <Modal open={confirmVariant} onClose={() => setConfirmVariant(false)} title={tr('hunt.workbench.variantTitle')}>
      <p className="text-sm leading-relaxed text-[var(--muted)]">{tr('hunt.workbench.variantBody')}</p>
      <label className="mt-4 flex cursor-pointer items-start gap-2 rounded-lg border border-[var(--line)] p-3 text-sm">
        <input type="checkbox" checked={disableOriginal} onChange={(e) => setDisableOriginal(e.target.checked)} />
        <span><b className="block">{tr('hunt.workbench.disableOriginal')}</b>{tr('hunt.workbench.disableOriginalHint')}</span></label>
      <div className="mt-5 flex justify-end gap-2"><Button onClick={() => setConfirmVariant(false)}>{tr('common.cancel')}</Button>
        <Button variant="primary" disabled={saveRule.isPending} onClick={() => draft && saveRule.mutate({ draft: structuredClone(draft), disable: disableOriginal, identity: draftIdentity.current })}>{tr('hunt.workbench.createVariant')}</Button></div>
    </Modal>
    <Modal open={Boolean(replaceDraft)} onClose={() => setReplaceDraft(null)} title={tr('hunt.flow.keepYourUnsavedPattern')}>
      <p className="text-sm">{tr('hunt.flow.replaceDraftWarning')}</p>
      <div className="mt-5 flex justify-end gap-2"><Button onClick={() => setReplaceDraft(null)}>{tr('hunt.flow.keepDraft')}</Button>
        <Button onClick={() => replaceDraft && openDraft(replaceDraft)}>{tr('hunt.flow.discardDraftAndContinue')}</Button></div>
    </Modal>
    <Toast open={Boolean(notice)} onClose={() => setNotice('')} tone="ok" title={tr('hunt.workbench.notice')}>{notice}</Toast>
  </div>
}
