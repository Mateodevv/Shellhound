// App.tsx — shell: case selection + the left rail with the five views.
import { useT } from './i18n'
import { useEffect, useMemo, useState } from 'react'
import { QueryClientProvider, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity, ArrowLeft, Box, Bug, Database, FolderCog, FolderTree,
  LayoutDashboard, Puzzle, Radar, Search, Users,
} from 'lucide-react'
import { api, type CaseDetail, type Job } from './api'
import { useLiveEvents } from './ws'
import { ProgressBar } from './components/ui'
import { ThemeSwitcher } from './components/ThemeSwitcher'
import { LanguageSwitcher } from './components/LanguageSwitcher'
import { CommandPalette } from './components/CommandPalette'
import { ArtifactWindow, type ArtifactStub } from './components/ArtifactWindow'
import { TraceWindow, type TraceMarks } from './components/TraceWindow'
import { FileViewer } from './components/FileViewer'
import { TriageFollowUp } from './components/triage'
import { useTriage } from './components/useTriage'
import type { EvidenceRoot } from './format'
import { Start } from './views/Start'
import { Dashboard } from './views/Dashboard'
import { Evidence } from './views/Evidence'
import { Findings } from './views/Findings'
import { Actors } from './views/Actors'
import { Hunt } from './views/Hunt'
import { Files } from './views/Files'
import { IocBox } from './views/IocBox'
import { Cms } from './views/Cms'
import { DatabaseView } from './views/Database'
import { queryClient } from './queryClient'

export type ViewId =
  | 'dashboard' | 'findings' | 'actors' | 'hunt' | 'iocbox' | 'files' | 'cms'
  | 'database' | 'evidence'

const NAV: { id: ViewId; icon: typeof Bug }[] = [
  { id: 'dashboard', icon: LayoutDashboard },
  { id: 'findings', icon: Bug },
  { id: 'actors', icon: Users },
  { id: 'hunt', icon: Radar },
  { id: 'iocbox', icon: Box },
  { id: 'database', icon: Database },
  { id: 'cms', icon: Puzzle },
  { id: 'files', icon: FolderTree },
  { id: 'evidence', icon: FolderCog },
]

function CaseShell({ slug, onBack }: { slug: string; onBack: () => void }) {
  const tr = useT()
  const [view, setView] = useState<ViewId>('dashboard')
  const [liveJobs, setLiveJobs] = useState<Record<number, Partial<Job>>>({})

  // Die globale Suche gehört der Shell: sie muss aus JEDER Ansicht heraus
  // erreichbar sein, und ihr Treffer öffnet das Artefakt-Fenster direkt —
  // egal, welche Ansicht gerade offen ist.
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

  const running = useMemo(
    () => Object.values(liveJobs).filter((j) => j.state === 'running' || j.state === 'queued'),
    [liveJobs])

  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))
  const props = { slug, gotoView: setView }

  return (
    <div className="flex h-full">
      <nav className="flex w-56 shrink-0 flex-col border-r border-[var(--line)] bg-[var(--panel)]">
        <button
          onClick={onBack}
          className="group flex items-center gap-2 border-b border-[var(--line)] px-4 py-3 text-left cursor-pointer"
        >
          <ArrowLeft size={14} className="text-[var(--muted)] transition-transform group-hover:-translate-x-0.5" />
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold">{caseInfo?.name ?? slug}</div>
            <div className="truncate text-[11px] text-[var(--muted)]">
              {caseInfo?.reference || tr('nav.switchCase')}
            </div>
          </div>
        </button>

        <div className="flex flex-col gap-0.5 p-2">
          <button
            onClick={() => setPaletteOpen(true)}
            className="mb-1 flex items-center gap-2.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] text-[var(--muted)] transition-colors cursor-pointer hover:border-[var(--accent)]/60 hover:text-[var(--fg)]"
          >
            <Search size={14} />
            {tr('nav.search')}
            <span className="ml-auto rounded border border-[var(--line)] px-1 text-[10px]">
              {tr('nav.shortcut')}
            </span>
          </button>
          {NAV.map(({ id, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setView(id)}
              className={clsx(
                'flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium',
                'transition-colors duration-150 cursor-pointer',
                view === id
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]')}
            >
              <Icon size={15} />
              {tr(`nav.${id}`)}
            </button>
          ))}
        </div>

        <div className="mt-auto p-3">
          <div className="mb-1">
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

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div key={view} className="mx-auto max-w-[1400px] px-6 py-5">
          {view === 'dashboard' && <Dashboard {...props} />}
          {view === 'findings' && <Findings {...props} />}
          {view === 'actors' && <Actors {...props} />}
          {view === 'hunt' && <Hunt {...props} />}
          {view === 'iocbox' && <IocBox {...props} />}
          {view === 'files' && <Files {...props} />}
          {view === 'cms' && <Cms {...props} />}
          {view === 'database' && <DatabaseView {...props} />}
          {view === 'evidence' && <Evidence {...props} onClosed={onBack} />}
        </div>
      </main>

      <CommandPalette
        slug={slug}
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        gotoView={setView}
        onOpenArtifact={(stub) => { t.clearCollected(); setPaletteArtifact(stub) }}
      />
      {/* Das Artefakt-Fenster der Palette lebt in der Shell: ein Treffer
          soll sich öffnen, egal welche Ansicht gerade darunter liegt. */}
      <ArtifactWindow
        slug={slug}
        artifact={paletteArtifact}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setPaletteViewing({ path, line })}
        onTrace={(ips, m) => { setPaletteMarks(m); setPaletteTrace(ips) }}
        onClose={() => { setPaletteArtifact(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (paletteArtifact) t.decide([paletteArtifact.artifact], state, note)
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
      <TriageFollowUp t={t} roots={roots} />
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
    history.replaceState(null, '', url)
  }
  const back = () => {
    setSlug(null)
    const url = new URL(location.href)
    url.searchParams.delete('case')
    history.replaceState(null, '', url)
  }

  return slug ? <CaseShell slug={slug} onBack={back} /> : <Start onOpen={open} />
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Root />
    </QueryClientProvider>
  )
}
