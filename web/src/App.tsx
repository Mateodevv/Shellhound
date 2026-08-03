// App.tsx — shell: case selection + the left rail with the five views.
import { useMemo, useState } from 'react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity, ArrowLeft, Box, Bug, Database, FolderCog, LayoutDashboard,
  Puzzle, Users,
} from 'lucide-react'
import { api, type CaseDetail, type Job } from './api'
import { useLiveEvents } from './ws'
import { ProgressBar } from './components/ui'
import { ThemeSwitcher } from './components/ThemeSwitcher'
import { Start } from './views/Start'
import { Dashboard } from './views/Dashboard'
import { Evidence } from './views/Evidence'
import { Findings } from './views/Findings'
import { Actors } from './views/Actors'
import { IocBox } from './views/IocBox'
import { Cms } from './views/Cms'
import { DatabaseView } from './views/Database'

const qc = new QueryClient({
  defaultOptions: { queries: { staleTime: 5000, retry: 1, refetchOnWindowFocus: false } },
})

export type ViewId =
  | 'dashboard' | 'findings' | 'actors' | 'iocbox' | 'cms' | 'database' | 'evidence'

const NAV: { id: ViewId; label: string; icon: typeof Bug }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: Bug },
  { id: 'actors', label: 'Actors', icon: Users },
  { id: 'iocbox', label: 'IOC Box', icon: Box },
  { id: 'cms', label: 'CMS Inventory', icon: Puzzle },
  { id: 'database', label: 'Database', icon: Database },
  { id: 'evidence', label: 'Evidence & Jobs', icon: FolderCog },
]

function CaseShell({ slug, onBack }: { slug: string; onBack: () => void }) {
  const [view, setView] = useState<ViewId>('dashboard')
  const [liveJobs, setLiveJobs] = useState<Record<number, Partial<Job>>>({})

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
              {caseInfo?.reference || 'Case wechseln'}
            </div>
          </div>
        </button>

        <div className="flex flex-col gap-0.5 p-2">
          {NAV.map(({ id, label, icon: Icon }) => (
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
              {label}
            </button>
          ))}
        </div>

        <div className="mt-auto p-3">
          <div className="mb-1">
            <ThemeSwitcher up />
          </div>
          {running.length > 0 && (
            <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 animate-fade-up">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold text-[var(--accent-text)]">
                <Activity size={12} className="animate-pulse-soft" />
                {running.length} Job{running.length > 1 ? 's' : ''} läuft…
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
          {view === 'iocbox' && <IocBox {...props} />}
          {view === 'cms' && <Cms {...props} />}
          {view === 'database' && <DatabaseView {...props} />}
          {view === 'evidence' && <Evidence {...props} onClosed={onBack} />}
        </div>
      </main>
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
    <QueryClientProvider client={qc}>
      <Root />
    </QueryClientProvider>
  )
}
