// The case overview separates analyst decisions from technical scan coverage.
import { CaseProfileButton } from '../components/CaseProfile'
import { useT } from '../i18n'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowRight, Check, Database, FileSearch, HardDrive, Layers, Radar, ShieldAlert, ShieldCheck } from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData, type Job } from '../api'
import { absoluteTime, formatCount, formatDay, relativeToRoot, shortPath } from '../format'
import { KIND_ICON } from '../artifactKinds'
import { artifactNoun, categories } from '../explain'
import { Card, PageSkeleton, Tag } from '../components/ui'
import { evidenceAttempt } from '../analysis'
import { deriveWorkflowActions, isBaseAnalysisJob, type WorkflowAction } from '../workflow'
import type { Navigate } from '../App'
import { dashboardCopy as copy } from './dashboard-copy'

const buttonClass = 'inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]'
const linkClass = 'inline-flex cursor-pointer items-center gap-2 rounded text-sm font-semibold text-[var(--accent-text)] hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]'
const allSeverities = '0,1,2,3'
const cmsNames: Record<string, string> = { wordpress: 'WordPress', joomla: 'Joomla' }
const extensionNames: Record<string, readonly [string, string]> = copy.extensions
const statusTones = {
  danger: { background: 'var(--danger-soft)', borderColor: 'color-mix(in srgb, var(--danger-text) 45%, transparent)', color: 'var(--danger-text)' },
  warn: { background: 'var(--review-soft)', borderColor: 'color-mix(in srgb, var(--sev-low) 45%, transparent)', color: 'var(--review-text)' },
  ok: { background: 'color-mix(in srgb, var(--ok) 10%, var(--panel))', borderColor: 'color-mix(in srgb, var(--ok) 45%, transparent)', color: 'color-mix(in srgb, var(--ok) 78%, white)' },
}

function artifactLabel(item: { artifact: string; artifact_kind: string }, evidence: DashboardData['evidence']) {
  if (item.artifact_kind === 'file') {
    const { root, rel } = relativeToRoot(item.artifact, evidence)
    return root ? rel : shortPath(item.artifact, 64)
  }
  return item.artifact_kind === 'dump' ? shortPath(item.artifact, 64) : item.artifact
}

function Heading({ title, sub }: { title: string; sub: string }) {
  return <div className="mb-3">
    <h2 className="text-lg font-semibold">{title}</h2>
    <p className="mt-1 max-w-3xl text-sm leading-relaxed text-[var(--muted)]">{sub}</p>
  </div>
}

/** Old failures must not turn a successful retry or an unrelated source red. */
function hasFailedCheck(evidence: DashboardData['evidence'], jobs: Job[]): boolean {
  const present = new Set(evidence.map((item) => item.kind))
  const applicable = (job: Job) => isBaseAnalysisJob(job) && (
    (present.has('webroot') && ['webshell', 'cms', 'yara'].includes(job.kind))
    || (present.has('access_logs') && ['index_logs', 'sigma'].includes(job.kind))
    || (present.has('access_logs') && present.has('webroot') && job.kind === 'errorlog')
    || (present.has('sql_dump') && job.kind === 'sqldb'))
  const latest = new Map<string, Job>()
  for (const job of jobs.filter(applicable).sort((a, b) => b.created.localeCompare(a.created) || b.id - a.id)) {
    if (!latest.has(job.kind)) latest.set(job.kind, job)
  }
  return [...latest.values()].some((job) => job.state === 'failed')
    || evidence.some((item) => evidenceAttempt(item, jobs)?.status === 'failed')
}

export function Dashboard({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const dashboardQuery = useQuery({
    queryKey: ['dashboard', slug], queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  const caseQuery = useQuery({
    queryKey: ['case', slug], queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const jobsQuery = useQuery({
    queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    refetchInterval: 4000,
  })
  const data = dashboardQuery.data
  const caseInfo = caseQuery.data
  const jobs = jobsQuery.data
  if (dashboardQuery.isError || caseQuery.isError || jobsQuery.isError) return <Card className="p-6">
    <div role="alert">
      <h2 className="text-lg font-semibold">{copy.error}</h2>
      <p className="mt-2 text-sm text-[var(--muted)]">{copy.errorSub}</p>
    </div>
    <button type="button" className={`${buttonClass} mt-4 bg-[var(--accent-soft)] text-[var(--accent-text)]`}
      onClick={() => { void dashboardQuery.refetch(); void caseQuery.refetch(); void jobsQuery.refetch() }}>{copy.retry}</button>
  </Card>
  if (!data || !caseInfo || !jobs) return <PageSkeleton label={copy.loading} />

  const { primary, secondary } = deriveWorkflowActions(caseInfo, jobs, data)
  const evidence = caseInfo.evidence_items.filter((item) => item.kind !== 'reference')
  const hasEvidence = evidence.length > 0
  const confirmed = data.triage.confirmed ?? 0
  const outstanding = (data.triage.new ?? 0) + (data.triage.reviewed ?? 0)
  const hunt = data.hunt_summary?.matched ? data.hunt_summary : null
  const dismissed = data.triage.dismissed ?? 0
  const warnings = hasEvidence ? data.analysis_warnings ?? 0 : 0
  const active = primary?.id === 'running'
  // Queries refresh independently: newer job/evidence state can invalidate a
  // previously complete aggregate before the dashboard request catches up.
  const analysisComplete = data.analysis_complete !== false && hasEvidence
    && evidence.every((item) => item.scanned_at)
    && Boolean(primary && ['triage', 'warnings', 'report'].includes(primary.id))
  const failed = !active && !analysisComplete && hasFailedCheck(evidence, jobs)
  const verdict = confirmed > 0 ? 'confirmed' : outstanding > 0 ? 'inProgress'
    : !analysisComplete ? 'pendingAnalysis' : dismissed > 0 ? 'reviewedClear' : 'noFindings'
  const assessmentSub = confirmed ? copy.assessmentConfirmedSub
    : outstanding ? copy.assessmentInProgressSub : !hasEvidence ? copy.assessmentEmptySub : !analysisComplete ? copy.assessmentPendingSub
    : dismissed ? copy.assessmentReviewedSub : copy.assessmentNoFindingsSub
  const assessmentTone = confirmed ? 'danger' : !analysisComplete || outstanding || hunt ? 'warn' : 'ok'
  const coverageTone = analysisComplete ? 'ok' : failed ? 'danger' : 'warn'
  const AssessmentIcon = confirmed ? ShieldAlert : assessmentTone === 'ok' ? ShieldCheck : FileSearch
  const CoverageIcon = analysisComplete ? Check : failed ? AlertTriangle : FileSearch
  const coverageTitle = !hasEvidence ? copy.coverageEmpty : analysisComplete ? copy.coverageComplete
    : active ? copy.coverageRunning : failed ? copy.coverageFailed : copy.coveragePending
  const coverageSub = !hasEvidence ? copy.coverageEmptySub : analysisComplete ? copy.coverageCompleteSub
    : active ? copy.coverageRunningSub : failed ? copy.coverageFailedSub : copy.coveragePendingSub
  const sources = [...new Set(evidence.map((item) => item.kind))]
  const installations = hasEvidence ? data.system_summary?.installations ?? data.cms_installs.map((install) => ({
    ...install, version_parsed: install.version, version_set: false, version_source: '', extensions: {},
  })) : []
  const databases = hasEvidence ? data.system_summary?.databases ?? [] : []
  const highlights = data.top_findings
  const groups = highlights?.groups.slice(0, 3) ?? []
  const findingCategories = categories(tr)
  const hasOtherFindings = Boolean(highlights && (highlights.informational || highlights.hidden))
  const highlightsUnavailable = !highlights || (!hasOtherFindings && !groups.length && (confirmed > 0 || outstanding > 0))
  const emptyTone = !analysisComplete ? 'warn' : hasOtherFindings || highlightsUnavailable ? undefined : 'ok'
  const emptyTitle = !analysisComplete ? copy.topPending : highlightsUnavailable ? copy.topUnavailable
    : hasOtherFindings ? copy.topOther : dismissed ? copy.topDismissed : copy.topNone
  const emptySub = !analysisComplete ? copy.topPendingSub : highlightsUnavailable ? copy.topUnavailableSub
    : hasOtherFindings ? copy.topOtherSub : dismissed ? copy.topDismissedSub : copy.topNoneSub
  const navigateAction = (action: WorkflowAction) => action.params
    ? gotoView(action.view, action.params) : gotoView(action.view)
  const actionTitle = (action: WorkflowAction) => action.id === 'triage'
    ? (action.count ?? outstanding) === 1 ? copy.reviewOne : copy.reviewCount.replace('{n}', formatCount(action.count ?? outstanding)) : copy.actions[action.id][0]

  return <div className="flex flex-col gap-7 pb-4">
    <div className="flex justify-end"><CaseProfileButton slug={slug} /></div>
    <section aria-label={copy.status}>
      <Heading title={copy.status} sub={copy.statusSub} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="flex min-w-0 flex-col p-5 sm:p-6" style={statusTones[assessmentTone]}>
          <div className="flex items-center gap-2.5">
            <AssessmentIcon size={21} className="shrink-0" />
            <h3 className="text-xs font-semibold uppercase tracking-wider">{copy.conclusion}</h3>
          </div>
          <p className="mt-3 text-xl font-semibold leading-snug">{hunt && analysisComplete && !confirmed && !outstanding
            ? tr(hunt.fresh ? 'dashboard.hunt.assessment' : 'dashboard.hunt.historicalAssessment')
            : hasEvidence || confirmed || outstanding ? tr(`dashboard.brief.${verdict}`) : copy.assessmentEmpty}</p>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--muted)]">{hunt && analysisComplete && !confirmed && !outstanding
            ? tr('dashboard.hunt.assessmentSub') : assessmentSub}</p>
          {(outstanding > 0 || confirmed > 0) && <div className="mt-5 flex flex-wrap gap-3 border-t border-current/20 pt-4">
            {outstanding > 0 && <button type="button" aria-label={outstanding === 1 ? copy.outstandingOne : copy.outstandingCount.replace('{n}', formatCount(outstanding))}
              className="flex min-w-0 cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-left transition-colors hover:brightness-110"
              style={statusTones.warn} onClick={() => gotoView('findings', { triage: 'new,reviewed', severity: allSeverities })}>
              <span className="text-3xl font-semibold tabular">{formatCount(outstanding)}</span>
              <span className="text-sm font-semibold">{copy.outstanding}</span><ArrowRight size={16} className="shrink-0" />
            </button>}
            {confirmed > 0 && <button type="button" aria-label={confirmed === 1 ? copy.confirmedOne : copy.confirmedCount.replace('{n}', formatCount(confirmed))}
              className="flex min-w-0 cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-left transition-colors hover:brightness-110"
              style={statusTones.danger} onClick={() => gotoView('findings', { triage: 'confirmed', severity: allSeverities })}>
              <span className="text-3xl font-semibold tabular">{formatCount(confirmed)}</span>
              <span className="text-sm font-semibold">{copy.confirmed}</span><ArrowRight size={16} className="shrink-0" />
            </button>}
          </div>}
          {dismissed > 0 && !outstanding && !confirmed && <button type="button" className={`${linkClass} mt-4 self-start`}
            onClick={() => gotoView('findings', { triage: 'dismissed', severity: allSeverities })}>{copy.openDismissed}<ArrowRight size={14} /></button>}
        </Card>
        <Card className="min-w-0 p-5 sm:p-6" style={statusTones[coverageTone]}>
          <div className="flex items-center gap-2.5">
            <CoverageIcon size={21} className="shrink-0" />
            <h3 className="text-xs font-semibold uppercase tracking-wider">{copy.coverage}</h3>
          </div>
          <p className="mt-3 text-xl font-semibold leading-snug">{coverageTitle}</p>
          <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{coverageSub}</p>
          {warnings > 0 && <div className="mt-4 space-y-3 border-t border-current/20 pt-4">
            {warnings > 0 && <div className="rounded-lg border p-3" style={statusTones.warn}>
              <p className="flex items-center gap-2 text-sm font-semibold"><AlertTriangle size={16} className="shrink-0" />{copy.unresolved}</p>
              <p className="mt-1 text-sm leading-relaxed text-[var(--muted)]">{tr('dashboard.analysisWarnings', { n: warnings })}</p>
              <button type="button" className={`${linkClass} mt-2`} onClick={() => gotoView('evidence')}>{tr('dashboard.reviewSkipped')}<ArrowRight size={14} /></button>
            </div>}
          </div>}
        </Card>
      </div>
    </section>

    {primary && <section aria-label={copy.next}>
      <Heading title={copy.next} sub={copy.nextSub} />
      <Card className="border-[var(--accent)]/40 bg-[var(--accent-soft)] p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-5">
          <div className="max-w-2xl">
            <h3 className="text-lg font-semibold">{actionTitle(primary)}</h3>
            <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{copy.actions[primary.id][1]}</p>
          </div>
          <button type="button" onClick={() => navigateAction(primary)}
            className={`${buttonClass} bg-[var(--primary)] text-[var(--primary-text)] hover:bg-[var(--primary-hover)]`}>
            {actionTitle(primary)}{' '}{primary.id !== 'triage' && primary.count !== undefined && <span className="rounded bg-black/15 px-1.5 tabular">{formatCount(primary.count)}</span>}
            <ArrowRight size={17} />
          </button>
        </div>
        {secondary.length > 0 && <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-3 border-t border-[var(--line)] pt-4">
          <span className="text-sm text-[var(--muted)]">{copy.also}</span>
          {secondary.map((action) => <button key={action.id} type="button" className={linkClass}
            onClick={() => navigateAction(action)}>{actionTitle(action)}
            {action.id !== 'triage' && action.count !== undefined && <span className="tabular">({formatCount(action.count)})</span>}<ArrowRight size={14} />
          </button>)}
        </div>}
      </Card>
    </section>}

    <section aria-label={copy.top}>
      <div className="flex flex-wrap items-start justify-between gap-x-5 gap-y-1">
        <Heading title={copy.top} sub={copy.topSub} />
        <button type="button" className={`${linkClass} mb-3 py-1`} onClick={() => gotoView('findings', { severity: allSeverities, triage: 'new,reviewed,confirmed,dismissed' })}>
          {copy.topOpen}<ArrowRight size={14} />
        </button>
      </div>
      <Card className="p-3 sm:p-4">
        {groups.length > 0 ? <div className="space-y-3">
          {groups.map((group) => {
            const Icon = group.confirmed ? ShieldAlert : FileSearch
            const ArtifactIcon = KIND_ICON[group.example.artifact_kind]
            const label = copy.topCategories[group.category as keyof typeof copy.topCategories]
              ?? findingCategories[group.category]?.label ?? findingCategories.other.label
            const affected = ['file', 'client', 'table', 'dump'].filter((kind) => group.kinds[kind] > 0)
              .map((kind) => `${formatCount(group.kinds[kind])} ${artifactNoun(tr, kind, group.kinds[kind])}`).join(' · ')
            return <button key={group.category} type="button"
              onClick={() => gotoView('findings', { category: group.category, triage: 'new,reviewed,confirmed', severity: allSeverities })}
              className="group flex w-full min-w-0 cursor-pointer items-start gap-3 rounded-xl border p-4 text-left transition-colors hover:brightness-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] sm:gap-4 sm:p-5"
              style={statusTones[group.confirmed ? 'danger' : 'warn']}>
              <Icon size={21} className="mt-0.5 shrink-0" />
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                  <span className="text-base font-semibold">{label}</span>
                  <span className="text-xs font-medium text-[var(--muted)]">{affected}</span>
                </span>
                <span className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm font-semibold">
                  {group.confirmed > 0 && <span className="text-[var(--danger-text)]">{tr('dashboard.top.confirmed', { n: formatCount(group.confirmed) })}</span>}
                  {group.awaiting_review > 0 && <span className="text-[var(--review-text)]">{tr('dashboard.top.awaiting', { n: formatCount(group.awaiting_review) })}</span>}
                </span>
                <span className="mt-3 flex min-w-0 items-start gap-2 text-xs leading-relaxed text-[var(--muted)]">
                  <ArtifactIcon size={14} className="mt-0.5 shrink-0" />
                  <span className="min-w-0"><span>{copy.topExample} </span><span className="mono break-all" title={group.example.artifact}>{artifactLabel(group.example, evidence)}</span></span>
                </span>
                {group.historical > 0 && <span className="mt-2 block text-xs leading-relaxed text-[var(--muted)]">
                  {tr('dashboard.top.historical', { n: formatCount(group.historical) })}
                </span>}
              </span>
              <ArrowRight size={17} className="mt-1 shrink-0 transition-transform group-hover:translate-x-0.5" />
            </button>
          })}
        </div> : !hunt && <div className="rounded-xl border border-[var(--line-soft)] p-4 sm:p-5" style={emptyTone ? statusTones[emptyTone] : undefined}>
          <p className="font-semibold">{emptyTitle}</p>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-[var(--muted)]">{emptySub}</p>
          {hasOtherFindings && <p className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--muted)]">
            {highlights!.informational > 0 && <span>{tr(highlights!.informational === 1 ? 'dashboard.top.informationalOne' : 'dashboard.top.informational', { n: formatCount(highlights!.informational) })}</span>}
            {highlights!.hidden > 0 && <span>{tr(highlights!.hidden === 1 ? 'dashboard.top.hiddenOne' : 'dashboard.top.hidden', { n: formatCount(highlights!.hidden) })}</span>}
          </p>}
        </div>}
        {hunt && <button type="button" aria-label={tr('dashboard.hunt.open')}
          onClick={() => gotoView('hunt', { section: 'runs', batch: hunt.batch_id })}
          className={`group flex w-full min-w-0 cursor-pointer items-start gap-3 rounded-xl border p-4 text-left hover:brightness-110 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] sm:p-5 ${groups.length ? 'mt-3' : ''}`}
          style={statusTones.warn}>
          <Radar size={21} className="mt-0.5 shrink-0" />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
              <span className="text-base font-semibold">{tr('dashboard.hunt.title')}</span>
              <span className="text-xs text-[var(--muted)]">{absoluteTime(hunt.created)} UTC</span>
            </span>
            <span className="mt-2 block text-sm font-semibold">{tr(hunt.matched === 1 ? 'dashboard.hunt.matchedOne' : 'dashboard.hunt.matched', { n: formatCount(hunt.matched) })}</span>
            <span className="mt-1 block break-words text-sm text-[var(--fg)]">{hunt.pattern_names.map((name) => name || tr('hunt.flow.unnamedPattern')).join(' · ')}{hunt.matched > hunt.pattern_names.length ? ` · +${formatCount(hunt.matched - hunt.pattern_names.length)}` : ''}</span>
            <span className="mt-2 block text-xs leading-relaxed text-[var(--muted)]">{tr('dashboard.hunt.hint')}</span>
            {!hunt.complete && <span className="mt-2 block text-xs">{tr(['queued', 'running'].includes(hunt.state) ? 'dashboard.hunt.running' : 'dashboard.hunt.partial')}</span>}
            {!hunt.fresh && <span className="mt-2 block text-xs">{tr('dashboard.hunt.stale')}</span>}
          </span>
          <ArrowRight size={17} className="mt-1 shrink-0 transition-transform group-hover:translate-x-0.5" />
        </button>}
      </Card>
    </section>

    <section aria-label={copy.evidence}>
      <Heading title={copy.evidence} sub={copy.evidenceSub} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <Card className="min-w-0 p-5">
          <h3 className="flex items-center gap-2 text-base font-semibold"><Layers size={18} className="text-[var(--accent-text)]" />{copy.software}</h3>
          <p className="mt-1 text-sm leading-relaxed text-[var(--muted)]">{copy.softwareSub}</p>
          {(installations.length > 0 || databases.length > 0) ? <div className="mt-4 space-y-3">
            {installations.map((install) => <div key={install.id} className="min-w-0 rounded-lg border border-[var(--line-soft)] bg-[var(--panel-2)]/40 p-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-semibold">{cmsNames[install.cms.toLowerCase()] ?? install.cms}</p>
                <span className="mono text-sm text-[var(--accent-text)]">{!install.version || install.version === '(unknown)' ? copy.versionUnknown : install.version}</span>
                {install.version_set && <Tag tone="accent">{copy.correctedVersion}</Tag>}
              </div>
              <p className="mono mt-1 break-all text-xs leading-relaxed text-[var(--muted)]">{install.root}</p>
              {Object.keys(install.extensions).length > 0 && <div className="mt-3 flex flex-wrap gap-2">
                {Object.entries(install.extensions).map(([kind, count]) => <Tag key={kind}>{formatCount(count)} {extensionNames[kind]?.[count === 1 ? 0 : 1] ?? kind}</Tag>)}
              </div>}
            </div>)}
            {databases.map((database) => <div key={database.id} className="min-w-0 rounded-lg border border-[var(--line-soft)] bg-[var(--panel-2)]/40 p-3.5">
              <div className="flex flex-wrap items-center gap-2">
                <Database size={16} className="text-[var(--muted)]" /><p className="font-semibold">{copy.database}</p>
                <span className="mono text-sm text-[var(--accent-text)]">{database.server_version || copy.versionUnknown}</span>
              </div>
              <p className="mono mt-1 break-all text-xs leading-relaxed text-[var(--muted)]">{database.path}</p>
              {database.server_version && <p className="mt-2 text-xs text-[var(--muted)]">{copy.databaseVersionSource}</p>}
            </div>)}
          </div> : <p className="mt-4 rounded-lg bg-[var(--panel-2)]/50 p-4 text-sm leading-relaxed text-[var(--muted)]">
            {!analysisComplete ? copy.softwarePending : sources.length === 1 && sources[0] === 'access_logs' ? copy.softwareLogsOnly : copy.softwareUnknown}
          </p>}
          {(installations.length > 0 || databases.length > 0) && <div className="mt-4 flex flex-wrap gap-x-5 gap-y-3">
            {installations.length > 0 && <button type="button" className={linkClass} onClick={() => gotoView('cms')}>{copy.softwareOpen}<ArrowRight size={14} /></button>}
            {databases.length > 0 && <button type="button" className={linkClass} onClick={() => gotoView('database')}>{copy.databaseOpen}<ArrowRight size={14} /></button>}
          </div>}
        </Card>
        <Card className="min-w-0 p-5">
          <h3 className="flex items-center gap-2 text-base font-semibold"><HardDrive size={18} className="text-[var(--accent-text)]" />{copy.available}</h3>
          {hasEvidence ? <>
            <dl className="mt-3 divide-y divide-[var(--line-soft)]">
              {sources.map((kind) => {
                const group = evidence.filter((item) => item.kind === kind)
                const files = group.every((item) => item.files !== undefined && !item.meta_partial)
                  ? group.reduce((sum, item) => sum + (item.files ?? 0), 0) : undefined
                return <div key={kind} className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 py-3">
                  <dt className="text-sm font-medium">{tr(`evidence.${kind}`)}</dt>
                  <dd className="text-right text-sm text-[var(--muted)]">
                    {group.length === 1 ? copy.sourceOne : copy.sourceCount.replace('{n}', formatCount(group.length))}
                    {files !== undefined && <span className="ml-2">· {files === 1 ? copy.fileOne : copy.fileCount.replace('{n}', formatCount(files))}</span>}
                  </dd>
                </div>
              })}
            </dl>
            {data.logs && <dl className="mt-2 grid grid-cols-2 gap-4 border-t border-[var(--line-soft)] pt-4">
              <div><dt className="text-xs text-[var(--muted)]">{copy.requests}</dt><dd className="mt-1 text-xl font-semibold tabular">{formatCount(data.logs.lines)}</dd></div>
              <div><dt className="text-xs text-[var(--muted)]">{copy.clients}</dt><dd className="mt-1 text-xl font-semibold tabular">{formatCount(data.logs.clients)}</dd></div>
              <div className="col-span-2"><dt className="text-xs text-[var(--muted)]">{copy.logPeriod}</dt><dd className="mt-1 text-sm font-semibold tabular">{formatDay(data.logs.first_epoch)} → {formatDay(data.logs.last_epoch)}</dd></div>
            </dl>}
          </> : <p className="mt-4 text-sm leading-relaxed text-[var(--muted)]">{copy.availableEmpty}</p>}
          <button type="button" className={`${linkClass} mt-4`} onClick={() => gotoView('evidence')}>{copy.evidenceOpen}<ArrowRight size={14} /></button>
        </Card>
      </div>

    </section>
  </div>
}
