// App.tsx — shell: case selection + the left rail with the five views.
import { useT } from './i18n'
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { QueryClientProvider, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity, ArrowLeft, Box, Bug, Database, FileCheck2, FolderCog, FolderTree,
  LayoutDashboard, ListChecks, Puzzle, Radar, ScrollText, Search,
  SlidersHorizontal, Users,
} from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData, type Job } from './api'
import { useLiveEvents } from './ws'
import { PageSkeleton, ProgressBar } from './components/ui'
import { ThemeSwitcher } from './components/ThemeSwitcher'
import { LanguageSwitcher } from './components/LanguageSwitcher'
import { TimeSwitcher } from './components/TimeSwitcher'
import { Mark } from './components/Mark'
import { CommandPalette } from './components/CommandPalette'
import { ArtifactWindow, type ArtifactStub } from './components/ArtifactWindow'
import { TraceWindow, type TraceMarks } from './components/TraceWindow'
import { FileViewer } from './components/FileViewer'
import { TriageFollowUp } from './components/triage'
import { useTriage } from './components/useTriage'
import type { EvidenceRoot } from './format'
import { queryClient } from './queryClient'
import { deriveWorkflowAction } from './workflow'

const Start = lazy(() => import('./views/Start').then((m) => ({ default: m.Start })))
const Dashboard = lazy(() => import('./views/Dashboard').then((m) => ({ default: m.Dashboard })))
const Evidence = lazy(() => import('./views/Evidence').then((m) => ({ default: m.Evidence })))
const Findings = lazy(() => import('./views/Findings').then((m) => ({ default: m.Findings })))
const Actors = lazy(() => import('./views/Actors').then((m) => ({ default: m.Actors })))
const AccessLogs = lazy(() => import('./views/AccessLogs').then((m) => ({ default: m.AccessLogs })))
const Hunt = lazy(() => import('./views/Hunt').then((m) => ({ default: m.Hunt })))
const Files = lazy(() => import('./views/Files').then((m) => ({ default: m.Files })))
const IocBox = lazy(() => import('./views/IocBox').then((m) => ({ default: m.IocBox })))
const Cms = lazy(() => import('./views/Cms').then((m) => ({ default: m.Cms })))
const DatabaseView = lazy(() => import('./views/Database').then((m) => ({ default: m.DatabaseView })))
const Settings = lazy(() => import('./views/Settings').then((m) => ({ default: m.Settings })))
const Timeline = lazy(() => import('./views/Timeline').then((m) => ({ default: m.Timeline })))
const Report = lazy(() => import('./views/Report').then((m) => ({ default: m.Report })))

export type ViewId =
  | 'dashboard' | 'findings' | 'actors' | 'logs' | 'hunt' | 'iocbox' | 'files' | 'cms'
  | 'database' | 'evidence' | 'timeline' | 'report' | 'settings'

export type ViewParams = Partial<Record<
  | 'severity' | 'triage' | 'source' | 'search' | 'artifact' | 'retired' | 'request'
  | 'actor' | 'section', string
>>
export type Navigate = (view: ViewId, params?: ViewParams) => void

const VIEW_IDS = new Set<ViewId>([
  'dashboard', 'findings', 'actors', 'logs', 'hunt', 'iocbox', 'files', 'cms',
  'database', 'evidence', 'timeline', 'report', 'settings',
])

interface NavItem { id: ViewId; icon: typeof Bug; experimental?: boolean; step?: number }
const OVERVIEW_NAV: NavItem[] = [{ id: 'dashboard', icon: LayoutDashboard }]
const WORKFLOW_NAV: NavItem[] = [
  { id: 'evidence', icon: FolderCog, step: 1 },
  { id: 'findings', icon: Bug, step: 2 },
  { id: 'iocbox', icon: Box, step: 3 },
  { id: 'report', icon: FileCheck2, step: 4 },
]
const INVESTIGATION_NAV: NavItem[] = [
  { id: 'actors', icon: Users },
  { id: 'files', icon: FolderTree },
  { id: 'timeline', icon: ListChecks },
  { id: 'database', icon: Database },
  { id: 'cms', icon: Puzzle },
  { id: 'hunt', icon: Radar },
  { id: 'logs', icon: ScrollText, experimental: true },
]

export function CaseNavigation({
  view,
  openArtifacts,
  onNavigate,
  onSearch,
}: {
  view: ViewId
  openArtifacts: number
  onNavigate: (view: ViewId) => void
  onSearch: () => void
}) {
  const tr = useT()
  const navItem = ({ id, icon: Icon, experimental, step }: NavItem) => (
    <button
      key={id}
      onClick={() => onNavigate(id)}
      aria-current={view === id ? 'page' : undefined}
      className={clsx(
        'flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium',
        'transition-colors duration-150 cursor-pointer',
        view === id
          ? 'border border-[var(--accent)]/45 bg-[var(--accent-soft)] text-[var(--fg)]'
          : 'border border-transparent text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]')}
    >
      {step ? (
        <span className={clsx('flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold',
          view === id ? 'border-[var(--accent)] text-[var(--accent-text)]' : 'border-[var(--line-strong)]')}>
          {step}
        </span>
      ) : <Icon size={15} />}
      <span className="min-w-0 truncate">{tr(`nav.${id}`)}</span>
      {experimental && (
        <span className="ml-auto rounded bg-[var(--sev-low)]/15 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-[var(--sev-low)]">
          {tr('common.experimental')}
        </span>
      )}
      {id === 'findings' && openArtifacts > 0 && (
        <span className="ml-auto rounded-full bg-[var(--panel-raised)] px-1.5 text-[10px] tabular">
          {openArtifacts}
        </span>
      )}
    </button>
  )

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-2">
      <button
        onClick={onSearch}
        className="mb-1 flex items-center gap-2.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] text-[var(--muted)] transition-colors cursor-pointer hover:border-[var(--accent)]/60 hover:text-[var(--fg)]"
      >
        <Search size={14} />
        {tr('nav.search')}
        <span className="ml-auto rounded border border-[var(--line)] px-1 text-[10px]">
          {tr('nav.shortcut')}
        </span>
      </button>
      <div className="mb-2">
        <div className="px-3 pb-1 pt-2 text-[9.5px] font-bold uppercase tracking-[0.14em] text-[var(--muted)]">
          {tr('nav.phase.overview')}
        </div>
        {OVERVIEW_NAV.map(navItem)}
      </div>
      <div className="mb-2">
        <div className="px-3 pb-1 pt-2 text-[9.5px] font-bold uppercase tracking-[0.14em] text-[var(--muted)]">
          {tr('nav.phase.workflow')}
        </div>
        {WORKFLOW_NAV.map(navItem)}
      </div>
      <div className="mb-2">
        <div className="px-3 pb-1 pt-2 text-[9.5px] font-bold uppercase tracking-[0.14em] text-[var(--muted)]">
          {tr('nav.phase.tools')}
        </div>
        {INVESTIGATION_NAV.map(navItem)}
      </div>
    </div>
  )
}

function viewFromUrl(): ViewId {
  const value = new URLSearchParams(location.search).get('view') as ViewId | null
  return value && VIEW_IDS.has(value) ? value : 'dashboard'
}

function CaseShell({ slug, onBack }: { slug: string; onBack: () => void }) {
  const tr = useT()
  const [view, setView] = useState<ViewId>(viewFromUrl)
  const [liveJobs, setLiveJobs] = useState<Record<number, Partial<Job>>>({})

  // The global search belongs to the shell: it has to be reachable from
  // EVERY view, and its hit opens the artifact window directly -- no matter
  // which view is currently open.
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [paletteArtifact, setPaletteArtifact] = useState<ArtifactStub | null>(null)
  const [paletteTrace, setPaletteTrace] = useState<string[] | null>(null)
  const [paletteMarks, setPaletteMarks] = useState<TraceMarks | undefined>()
  const [paletteViewing, setPaletteViewing] =
    useState<{ path: string; line: number | null } | null>(null)
  const t = useTriage(slug)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useLiveEvents((job) => {
    setLiveJobs((prev) => {
      const next = { ...prev, [job.id]: { ...prev[job.id], ...job } }
      if (job.state && ['done', 'failed', 'cancelled'].includes(job.state)) {
        // keep it briefly so the bar finishes, then drop
        setTimeout(() => setLiveJobs((p) => {
          const rest = { ...p }
          delete rest[job.id]
          return rest
        }), 1500)
      }
      return next
    })
  })

  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const { data: dashboard } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  const { data: jobs } = useQuery({
    queryKey: ['jobs', slug],
    queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    refetchInterval: 4000,
  })

  const gotoView = useCallback<Navigate>((next, params = {}) => {
    const url = new URL(location.href)
    url.searchParams.set('case', slug)
    url.searchParams.set('view', next)
    for (const key of [
      'severity', 'triage', 'source', 'search', 'artifact', 'retired', 'request',
      'actor', 'section',
    ] as const) {
      const value = params[key]
      if (value) url.searchParams.set(key, value)
      else url.searchParams.delete(key)
    }
    history.pushState(null, '', url)
    setView(next)
  }, [slug])

  useEffect(() => {
    const onPopState = () => setView(viewFromUrl())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const running = useMemo(
    () => Object.values(liveJobs).filter((j) => j.state === 'running' || j.state === 'queued'),
    [liveJobs])

  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))
  const props = { slug, gotoView }
  const triage = dashboard?.triage ?? {}
  const openArtifacts = (triage.new ?? 0) + (triage.reviewed ?? 0)
  const decidedArtifacts = (triage.confirmed ?? 0) + (triage.dismissed ?? 0)
  const decisionTotal = openArtifacts + decidedArtifacts
  const completion = decisionTotal ? decidedArtifacts / decisionTotal : 0
  const workflowAction = deriveWorkflowAction(caseInfo, jobs, dashboard)

  return (
    <div className="h-full">
      <div className="flex h-full flex-col md:grid md:grid-cols-[14rem_minmax(0,1fr)] md:grid-rows-[auto_minmax(0,1fr)]">
        <button
          onClick={onBack}
          className="group hidden h-full items-center gap-2 border-b border-r border-[var(--line)] bg-[var(--panel)] px-4 py-3 text-left cursor-pointer md:flex"
        >
          <ArrowLeft size={14} className="text-[var(--muted)] transition-transform group-hover:-translate-x-0.5" />
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold">{caseInfo?.name ?? slug}</div>
            <div className="truncate text-[11px] text-[var(--muted)]">
              {caseInfo?.reference || tr('nav.switchCase')}
            </div>
          </div>
        </button>

        <header className="z-20 hidden border-b border-[var(--line)] bg-[var(--bg)]/95 px-6 py-3 backdrop-blur md:block">
          <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-4 gap-y-2">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-[15px] font-semibold">{caseInfo?.name ?? slug}</span>
                {caseInfo?.reference && (
                  <span className="truncate rounded-md bg-[var(--panel-2)] px-1.5 py-0.5 text-[10.5px] text-[var(--muted)]">
                    {caseInfo.reference}
                  </span>
                )}
              </div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                {tr(`nav.${view}`)}
                {view !== 'dashboard' && <> · {tr('case.progress', { done: decidedArtifacts, total: decisionTotal })}</>}
              </div>
            </div>
            {view !== 'dashboard' && <div className="w-36"><ProgressBar value={completion} /></div>}
            {workflowAction && view !== workflowAction.view && (
              <button onClick={() => gotoView(workflowAction.view,
                workflowAction.id === 'triage' ? { triage: 'new,reviewed' } : {})}
                className="rounded-lg bg-[var(--primary)] px-3 py-1.5 text-[12px] font-semibold text-[var(--primary-text)] transition-colors hover:bg-[var(--primary-hover)] cursor-pointer">
                {tr(workflowAction.label, { n: workflowAction.count ?? 0 })}
              </button>
            )}
          </div>
        </header>

        <nav className="hidden min-h-0 flex-col border-r border-[var(--line)] bg-[var(--panel)] md:flex">
          <CaseNavigation view={view} openArtifacts={openArtifacts}
            onNavigate={gotoView} onSearch={() => setPaletteOpen(true)} />

        {/* Quiet, at the foot. The sidebar HEADER belongs to the case --
            a mark up there would compete with the case name, which is the
            one thing an analyst navigates by. */}
        <div className="mt-auto flex items-center gap-2 px-4 pb-1 pt-3">
          <Mark size={15} tile={false} className="shrink-0 opacity-60" />
          <span className="text-[10.5px] font-semibold tracking-[0.14em] text-[var(--muted)]">
            SHELLHOUND
          </span>
        </div>
        <div className="p-3 pt-1">
          <div className="mb-1">
            <button
              onClick={() => gotoView('settings')}
              className={clsx(
                'mb-1 flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-[12px] cursor-pointer',
                view === 'settings'
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]')}
            >
              <SlidersHorizontal size={14} /> {tr('nav.settings')}
            </button>
            <TimeSwitcher up />
            <LanguageSwitcher up />
            <ThemeSwitcher up />
          </div>
          {running.length > 0 && (
            <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 animate-fade-up">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-[var(--accent-text)]">
                <Activity size={12} className="animate-pulse-soft" />
                {tr('nav.jobsRunning', { n: running.length })}
              </div>
              {running.slice(0, 3).map((j) => (
                <div key={j.id} className="mb-2 last:mb-0">
                  <div className="mb-1 truncate text-[11px] text-[var(--muted)]">
                    {j.message || j.kind || `Job #${j.id}`}
                  </div>
                  <ProgressBar value={j.progress ?? 0} />
                </div>
              ))}
            </div>
          )}
        </div>
        </nav>

        <div className="flex shrink-0 items-center gap-2 border-b border-[var(--line)] bg-[var(--panel)] px-3 py-2 md:hidden">
        <button onClick={onBack} aria-label={tr('nav.switchCase')}
          className="cursor-pointer rounded-lg p-2 text-[var(--muted)] hover:bg-[var(--panel-2)]">
          <ArrowLeft size={16} />
        </button>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12px] font-semibold">{caseInfo?.name ?? slug}</div>
          <select value={view} onChange={(event) => gotoView(event.target.value as ViewId)}
            aria-label={tr('nav.currentView')}
            className="w-full bg-transparent text-[11px] text-[var(--muted)] outline-none">
            <optgroup label={tr('nav.phase.overview')}>
              {OVERVIEW_NAV.map((item) => <option key={item.id} value={item.id}>{tr(`nav.${item.id}`)}</option>)}
            </optgroup>
            <optgroup label={tr('nav.phase.workflow')}>
              {WORKFLOW_NAV.map((item) => <option key={item.id} value={item.id}>{item.step}. {tr(`nav.${item.id}`)}</option>)}
            </optgroup>
            <optgroup label={tr('nav.phase.tools')}>
              {INVESTIGATION_NAV.map((item) => (
                <option key={item.id} value={item.id}>
                  {tr(`nav.${item.id}`)}{item.experimental ? ` · ${tr('common.experimental')}` : ''}
                </option>
              ))}
            </optgroup>
            <option value="settings">{tr('nav.settings')}</option>
          </select>
        </div>
        <button onClick={() => setPaletteOpen(true)} aria-label={tr('nav.search')}
          className="cursor-pointer rounded-lg p-2 text-[var(--muted)] hover:bg-[var(--panel-2)]">
          <Search size={16} />
        </button>
        </div>

        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto md:col-start-2 md:row-start-2">
        <div key={view} className={clsx('mx-auto', view === 'hunt'
          ? 'max-w-none p-2 sm:p-3'
          : 'max-w-[1400px] px-3 py-4 sm:px-6 sm:py-5')}>
          <Suspense fallback={<PageSkeleton />}>
            {view === 'dashboard' && <Dashboard {...props} />}
            {view === 'findings' && <Findings {...props} />}
            {view === 'actors' && <Actors {...props} />}
            {view === 'logs' && <AccessLogs {...props} />}
            {view === 'hunt' && <Hunt {...props} />}
            {view === 'iocbox' && <IocBox {...props} />}
            {view === 'files' && <Files {...props} />}
            {view === 'cms' && <Cms {...props} />}
            {view === 'database' && <DatabaseView {...props} />}
            {view === 'evidence' && <Evidence {...props} />}
            {view === 'timeline' && <Timeline {...props} />}
            {view === 'report' && <Report {...props} onClosed={onBack} />}
            {view === 'settings' && <Settings />}
          </Suspense>
        </div>
        </main>
      </div>

      <CommandPalette
        slug={slug}
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        gotoView={gotoView}
        onOpenArtifact={(stub) => { t.clearCollected(); setPaletteArtifact(stub) }}
      />
      {/* The palette's artifact window lives in the shell: a hit should
          open no matter which view lies below it. */}
      <ArtifactWindow
        slug={slug}
        artifact={paletteArtifact}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setPaletteViewing({ path, line })}
        onTrace={(ips, m) => { setPaletteMarks(m); setPaletteTrace(ips) }}
        onClose={() => { setPaletteArtifact(null); t.clearCollected() }}
        onSave={(state, note) => {
          if (!paletteArtifact) return Promise.reject(new Error('No artifact selected'))
          return t.decideAsync([paletteArtifact.artifact], state, note)
        }}
      />
      <TraceWindow slug={slug} ips={paletteTrace} layer={1} marks={paletteMarks}
        onClose={() => setPaletteTrace(null)} />
      <FileViewer
        slug={slug}
        path={paletteViewing?.path ?? null}
        focusLine={paletteViewing?.line ?? null}
        layer={2}
        onClose={() => setPaletteViewing(null)}
      />
      <TriageFollowUp t={t} roots={roots} onOpenIocs={() => gotoView('iocbox')} />
    </div>
  )
}

function Root() {
  const [slug, setSlug] = useState<string | null>(
    () => new URLSearchParams(location.search).get('case'))

  const open = (s: string) => {
    setSlug(s)
    const url = new URL(location.href)
    url.searchParams.set('case', s)
    url.searchParams.set('view', 'dashboard')
    history.pushState(null, '', url)
  }
  const back = () => {
    setSlug(null)
    const url = new URL(location.href)
    url.searchParams.delete('case')
    url.searchParams.delete('view')
    for (const key of ['severity', 'triage', 'source', 'search', 'artifact', 'retired']) {
      url.searchParams.delete(key)
    }
    history.pushState(null, '', url)
  }

  useEffect(() => {
    const onPopState = () => setSlug(new URLSearchParams(location.search).get('case'))
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  return slug
    ? <CaseShell slug={slug} onBack={back} />
    : <Suspense fallback={<div className="mx-auto max-w-3xl px-6 py-12"><PageSkeleton /></div>}>
        <Start onOpen={open} />
      </Suspense>
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Root />
    </QueryClientProvider>
  )
}
