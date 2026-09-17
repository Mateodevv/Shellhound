// The case overview separates analyst decisions from technical scan coverage.
import { CaseProfileButton } from '../components/casework/CaseProfile'
import { useT } from '../i18n'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowRight, Check, Database, FileSearch, HardDrive, Layers, Radar, ShieldAlert, ShieldCheck } from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData, type Job } from '../api'
import { formatCount, formatLogTime } from '../format'
import { Card, PageSkeleton, Tag } from '../components/ui/ui'
import { evidenceAttempt } from '../analysis'
import { EvidenceTimeline } from '../components/casework/EvidenceTimeline'
import { FirstSign } from '../components/casework/FirstSign'
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
    || (present.has('logs') && ['log_events', 'index_logs', 'sigma'].includes(job.kind))
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
  const hasConfirmed = data.has_confirmed_findings ?? confirmed > 0
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
  const verdict = hasConfirmed ? 'confirmed' : outstanding > 0 ? 'inProgress'
    : !analysisComplete ? 'pendingAnalysis' : dismissed > 0 ? 'reviewedClear' : 'noFindings'
  const assessmentSub = hasConfirmed ? copy.assessmentConfirmedSub
    : outstanding ? copy.assessmentInProgressSub : !hasEvidence ? copy.assessmentEmptySub : !analysisComplete ? copy.assessmentPendingSub
    : dismissed ? copy.assessmentReviewedSub : copy.assessmentNoFindingsSub
  const assessmentTone = hasConfirmed ? 'danger' : !analysisComplete || outstanding || hunt ? 'warn' : 'ok'
  const coverageTone = analysisComplete ? 'ok' : failed ? 'danger' : 'warn'
  const AssessmentIcon = hasConfirmed ? ShieldAlert : assessmentTone === 'ok' ? ShieldCheck : FileSearch
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
  const summary = data.incident_summary
  const navigateAction = (action: WorkflowAction) => action.params
    ? gotoView(action.view, action.params) : gotoView(action.view)
  const actionTitle = (action: WorkflowAction) => action.id === 'triage'
    ? (action.count ?? outstanding) === 1 ? copy.reviewOne : copy.reviewCount.replace('{n}', formatCount(action.count ?? outstanding)) : copy.actions[action.id][0]

  return <div className="flex flex-col gap-7 pb-4">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold">{tr('dashboardTimeline.title')}</h1>
        {secondary.length > 0 && <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2">
          {secondary.slice(0, 2).map(action => <button key={action.id} type="button" className={linkClass}
            onClick={() => navigateAction(action)}>{actionTitle(action)}<ArrowRight size={13} /></button>)}
        </div>}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        {primary && <button type="button" onClick={() => navigateAction(primary)}
          className={`${buttonClass} bg-[var(--primary)] text-[var(--primary-text)] hover:bg-[var(--primary-hover)]`}>
          {actionTitle(primary)}<ArrowRight size={16} />
        </button>}
        <CaseProfileButton slug={slug} />
      </div>
    </header>
    <section aria-label={copy.status}>
      <Heading title={copy.status} sub={copy.statusSub} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="flex min-w-0 flex-col p-5 sm:p-6" style={statusTones[assessmentTone]}>
          <div className="flex items-center gap-2.5">
            <AssessmentIcon size={21} className="shrink-0" />
            <h3 className="text-xs font-semibold uppercase tracking-wider">{copy.conclusion}</h3>
          </div>
          <p className="mt-3 text-xl font-semibold leading-snug">{hunt && analysisComplete && !hasConfirmed && !outstanding
            ? tr(hunt.fresh ? 'dashboard.hunt.assessment' : 'dashboard.hunt.historicalAssessment')
            : hasEvidence || hasConfirmed || outstanding ? tr(`dashboard.brief.${verdict}`) : copy.assessmentEmpty}</p>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--muted)]">{hunt && analysisComplete && !hasConfirmed && !outstanding
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
          {dismissed > 0 && !outstanding && !hasConfirmed && <button type="button" className={`${linkClass} mt-4 self-start`}
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

    <section aria-label={tr('dashboardTimeline.timeline')}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">{tr('dashboardTimeline.timeline')}</h2>
        <button type="button" className={linkClass} onClick={() => gotoView('timeline', { scope: 'all' })}>
          {tr('dashboardTimeline.openTimeline')}<ArrowRight size={14} />
        </button>
      </div>
      <Card className="min-w-0 p-4 sm:p-5">
        <FirstSign slug={slug} data={data.first_sign}
          onTimeline={(id) => gotoView('timeline', id ? { event: id } : {})} />
        <EvidenceTimeline slug={slug} firstSign={data.first_sign} gotoView={gotoView} />
      </Card>
    </section>

    <section aria-label={tr('dashboardTimeline.glance')}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">{tr('dashboardTimeline.glance')}</h2>
        <button type="button" className={linkClass} onClick={() => gotoView('findings', { severity: allSeverities, triage: 'new,reviewed,confirmed,dismissed' })}>
          {copy.topOpen}<ArrowRight size={14} />
        </button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card className="min-w-0 p-4">
          <h3 className="text-sm font-medium text-[var(--muted)]">{tr('dashboardTimeline.latest')}</h3>
          {summary?.last_action != null ? <button type="button" className="mt-3 cursor-pointer rounded text-left text-sm font-semibold tabular hover:underline focus-visible:outline-2 focus-visible:outline-[var(--accent)]"
            onClick={() => gotoView('timeline', { scope: 'confirmed', ...(summary.last_action_event_id ? { event: summary.last_action_event_id } : {}) })}>
            {formatLogTime(summary.last_action, 0, { mode: 'utc', withZone: true })}<ArrowRight size={13} className="ml-2 inline" />
          </button> : <p className="mt-3 text-sm text-[var(--muted)]">{tr('dashboardTimeline.notObserved')}</p>}
          <p className="mt-2 text-xs leading-relaxed text-[var(--muted)]">{tr('dashboardTimeline.latestHint')}</p>
        </Card>
        <Card className="min-w-0 p-4">
          <h3 className="text-sm font-medium text-[var(--muted)]">{tr('dashboardTimeline.coverage')}</h3>
          {data.logs?.first_epoch != null && data.logs.last_epoch != null ? <button type="button" className="mt-3 cursor-pointer rounded text-left text-sm font-semibold tabular hover:underline focus-visible:outline-2 focus-visible:outline-[var(--accent)]"
            onClick={() => gotoView('logs')}>
            <span className="block">{formatLogTime(data.logs.first_epoch, 0, { mode: 'utc', withZone: true })}</span>
            <span className="mt-1 block">{formatLogTime(data.logs.last_epoch, 0, { mode: 'utc', withZone: true })}<ArrowRight size={13} className="ml-2 inline" /></span>
          </button> : <p className="mt-3 text-sm text-[var(--muted)]">{tr('dashboardTimeline.noCoverage')}</p>}
          <p className="mt-2 text-xs text-[var(--muted)]">{tr('dashboardTimeline.coverageHint')}</p>
        </Card>
        {(['ips', 'malware_files'] as const).map(group => {
          const confirmedCount = group === 'ips' ? summary?.confirmed_ips : summary?.malware_files
          const pendingCount = group === 'ips' ? summary?.pending_ips : summary?.pending_malware_files
          const tone = confirmedCount ? statusTones.danger : pendingCount ? statusTones.warn : undefined
          return <Card key={group} className="min-w-0 p-4" style={tone}>
            <h3 className="text-sm font-semibold">{tr(group === 'ips' ? 'dashboardTimeline.ips' : 'dashboardTimeline.malware')}</h3>
            {confirmedCount == null || pendingCount == null ? <p className="mt-3 text-sm text-[var(--muted)]">{tr('dashboardTimeline.unavailable')}</p>
              : <div className="mt-3 flex flex-col items-start gap-2">
                {([['confirmed', confirmedCount], ['new,reviewed', pendingCount]] as const).map(([triage, count]) => <button key={triage} type="button"
                  aria-label={tr(triage === 'confirmed' ? 'dashboardTimeline.groupConfirmed' : 'dashboardTimeline.groupPending', {
                    n: formatCount(count), group: tr(group === 'ips' ? 'dashboardTimeline.ips' : 'dashboardTimeline.malware'),
                  })}
                  disabled={!count} onClick={() => gotoView('findings', { summary_group: group, triage, severity: allSeverities })}
                  className="flex max-w-full cursor-pointer items-baseline gap-2 rounded text-left hover:underline focus-visible:outline-2 focus-visible:outline-[var(--accent)] disabled:cursor-default disabled:no-underline"
                  style={{ color: count ? triage === 'confirmed' ? 'var(--danger-text)' : 'var(--review-text)' : 'var(--muted)' }}>
                  <span className="text-2xl font-semibold tabular">{formatCount(count)}</span>
                  <span className="text-xs font-semibold">{tr(triage === 'confirmed' ? 'dashboardTimeline.confirmed' : 'dashboardTimeline.pending')}</span>
                  {count > 0 && <ArrowRight size={12} className="shrink-0 self-center" />}
                </button>)}
              </div>}
          </Card>
        })}
      </div>
      {hunt && <button type="button" className={`${linkClass} mt-3 text-[var(--review-text)]`}
        onClick={() => gotoView('hunt', { section: 'runs', batch: hunt.batch_id })}>
        <Radar size={15} />{tr('dashboardTimeline.hunt', { n: formatCount(hunt.matched) })}<ArrowRight size={14} />
        {!hunt.fresh && <span className="text-xs font-normal text-[var(--muted)]">{tr('dashboardTimeline.huntStale')}</span>}
      </button>}
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
          </> : <p className="mt-4 text-sm leading-relaxed text-[var(--muted)]">{copy.availableEmpty}</p>}
          <button type="button" className={`${linkClass} mt-4`} onClick={() => gotoView('evidence')}>{copy.evidenceOpen}<ArrowRight size={14} /></button>
        </Card>
      </div>

    </section>
  </div>
}
