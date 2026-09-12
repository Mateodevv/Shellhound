// Start.tsx -- the landing view: pick an open case, create a new one, or
// restore a closed case from the archive.
import { useT } from '../i18n'
import { Mark } from '../components/Mark'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Archive, ArchiveRestore, ChevronRight, FolderSearch, Package, Plus, Settings2, Trash2, TriangleAlert,
} from 'lucide-react'
import {
  api, del, post, type ArchivesResponse, type CaseInfo, type ImportResult,
} from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, Card, ConfirmDialog, EmptyState, Tag } from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { WorkspaceSettingsDialog } from '../components/WorkspaceSettingsDialog'
import { StartGeoBanner } from '../components/GeoBanner'
import { CaseWizard } from '../components/CaseWizard'

interface State { workspace: string; cases: CaseInfo[] }

export function Start({ onOpen }: { onOpen: (slug: string) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['state'],
    queryFn: () => api<State>('/api/state'),
  })
  const { data: archives } = useQuery({
    queryKey: ['archives'],
    queryFn: () => api<ArchivesResponse>('/api/archives'),
  })
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsTab, setSettingsTab] = useState<'themes' | 'geoip'>('themes')
  const [creating, setCreating] = useState(false)
  const [archivesOpen, setArchivesOpen] = useState(false)
  const [importPath, setImportPath] = useState('')
  const [showImport, setShowImport] = useState(false)

  const importCase = useMutation({
    mutationFn: (body: { file?: string; path?: string }) =>
      post<ImportResult>('/api/import', body),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['state'] })
      qc.invalidateQueries({ queryKey: ['archives'] })
      onOpen(result.slug)
    },
  })

  const [confirmation, setConfirmation] = useState<{
    kind: 'archive' | 'delete'; item: CaseInfo
  } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const archiveCase = useMutation({
    mutationFn: (slug: string) => post(`/api/cases/${slug}/archive`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['state'] })
      qc.invalidateQueries({ queryKey: ['archives'] })
      setConfirmation(null)
    },
    onSettled: () => setBusy(null),
  })
  const deleteCase = useMutation({
    mutationFn: (slug: string) => del(`/api/cases/${slug}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['state'] })
      setConfirmation(null)
    },
    onSettled: () => setBusy(null),
  })
  const exitError = archiveCase.error ?? deleteCase.error

  const archiveList = archives?.archives ?? []

  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-4 px-4 py-4 sm:px-6 lg:px-8 animate-fade-up">
        {/* The mark, not a generic shield: this is the one screen where the
            product introduces itself. */}
        <Mark size={44} className="shrink-0 rounded-xl" />
        <div>
          <h1 className="text-xl font-bold tracking-tight">SHELLHOUND</h1>
          <p className="text-[13px] text-[var(--muted)]">
            {tr('start.tagline')}
          </p>
        </div>
        <div className="ml-auto flex flex-wrap items-center justify-end gap-2">
          <Button onClick={() => { setSettingsTab('themes'); setSettingsOpen(true) }}><Settings2 size={14} />{tr('settings.title')}</Button>
        </div>
      </header>

      <main className="mx-auto w-full max-w-6xl flex-1 px-4 pt-8 sm:px-6 lg:pt-12">
      <StartGeoBanner onOpenSettings={() => { setSettingsTab('geoip'); setSettingsOpen(true) }} />
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          {tr('start.openCases')}
          {data && <Tag>{data.cases.length}</Tag>}
        </h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus size={15} /> {tr('start.newCase')}
          </Button>
          <Button onClick={() => setShowImport(!showImport)}>
            <ArchiveRestore size={15} /> {tr('start.importCase')}
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {isLoading && <div className="text-[var(--muted)]">{tr('common.loading')}</div>}
        {data?.cases.map((c, i) => (
          <Card
            key={c.slug}
            className="group animate-fade-up px-4 py-3 transition-colors hover:border-[var(--accent)]/60"
            style={{ animationDelay: `${i * 40}ms` }}
          >
            <div className="flex w-full items-center gap-3">
              <button className="flex min-w-0 flex-1 cursor-pointer flex-col items-start gap-3 rounded-md text-left sm:flex-row sm:items-center sm:justify-between"
                onClick={() => onOpen(c.slug)}>
                <div className="min-w-0">
                  <div className="break-words font-semibold">{c.name}</div>
                  <div className="mt-0.5 text-xs text-[var(--muted)]">
                    {c.reference && <span className="mr-3">{c.reference}</span>}
                    {tr('start.created')} {c.created?.slice(0, 10)}
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--muted)] tabular sm:grid sm:grid-cols-3 sm:text-right">
                  <span>{tr('start.artifacts', { n: c.artifacts ?? 0 })}</span>
                  <span className="text-[var(--danger-text)]">{tr('start.confirmed', { n: c.confirmed ?? 0 })}</span>
                  <span>{c.iocs ?? 0} IOCs</span>
                </div>
              </button>
              <div className="flex shrink-0 items-center gap-1">
                {/* The default exit: everything into a zip in the archive
                    below, restorable from right there. */}
                <Tooltip hint={tr('start.archive.hint')}>
                  <Button variant="ghost" title={tr('start.archive')}
                    className="transition-opacity sm:opacity-0 sm:group-hover:opacity-100 sm:group-focus-within:opacity-100"
                    disabled={busy === c.slug}
                    onClick={() => setConfirmation({ kind: 'archive', item: c })}>
                    {busy === c.slug && archiveCase.isPending
                      ? <span className="text-[11px]">{tr('start.archiving')}</span>
                      : <Archive size={14} />}
                  </Button>
                </Tooltip>
                <Tooltip hint={tr('start.delete.hint')}>
                  <Button variant="ghost"
                    title={tr('common.remove')}
                    className="transition-opacity sm:opacity-0 sm:group-hover:opacity-100 sm:group-focus-within:opacity-100"
                    disabled={busy === c.slug}
                    onClick={() => setConfirmation({ kind: 'delete', item: c })}>
                    <Trash2 size={14} />
                  </Button>
                </Tooltip>
              </div>
            </div>
          </Card>
        ))}

        {exitError != null && (
          <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)] animate-fade-up">
            {String((exitError as Error)?.message ?? exitError)}
          </div>
        )}

        {data && data.cases.length === 0 && !creating && (
          <EmptyState
            icon={<FolderSearch size={40} />}
            title={tr('start.empty.title')}
            sub={archiveList.length ? tr('start.empty') : tr('start.empty.first')}
          />
        )}
      </div>

      {creating && <CaseWizard onClose={() => setCreating(false)} onCreated={info => { setCreating(false); onOpen(info.slug) }} />}

      {showImport && !creating && (
        <Card className="mt-3 flex flex-wrap items-center gap-2 p-4 animate-fade-up">
          <Package size={15} className="text-[var(--muted)]" />
          <input
            value={importPath}
            onChange={(e) => setImportPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && importPath.trim())
                importCase.mutate({ path: importPath })
            }}
            placeholder={tr('start.import.placeholder')}
            className="mono min-w-0 basis-64 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="primary" disabled={!importPath.trim() || importCase.isPending}
            onClick={() => importCase.mutate({ path: importPath })}>
            {tr('start.import')}
          </Button>
        </Card>
      )}

      {importCase.isError && (
        <div className="mt-2 rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)] animate-fade-up">
          {tr('start.import.failed', {
            msg: String((importCase.error as Error)?.message ?? importCase.error),
          })}
        </div>
      )}

      {archiveList.length > 0 && (
        <div className="mt-8 animate-fade-up">
          <div className="mb-2 flex items-baseline justify-between gap-3">
            <h2 className="shrink-0 text-[15px] font-semibold">
              <button type="button" aria-expanded={archivesOpen} aria-controls="closed-cases" onClick={() => setArchivesOpen(value => !value)} className="ui-press flex cursor-pointer items-center gap-2 rounded py-1 hover:text-[var(--accent-text)]">
                <ChevronRight size={15} className={`transition-transform ${archivesOpen ? 'rotate-90' : ''}`} />
                <Archive size={15} className="text-[var(--muted)]" />
                {tr('start.archived')} <Tag>{archiveList.length}</Tag>
              </button>
            </h2>
            {archivesOpen && <span className="mono truncate text-[11px] text-[var(--muted)]"
              title={archives?.archive_dir}>
              {archives?.archive_dir}
            </span>}
          </div>
          <div id="closed-cases" hidden={!archivesOpen}>
          <div className="flex flex-col gap-2">
            {archiveList.map((a) => (
              <Card key={a.file} className="flex items-center gap-3 px-4 py-3">
                <Package size={16} className="shrink-0 text-[var(--muted)]" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium">
                      {a.summary?.name ?? a.file}
                    </span>
                    {a.summary?.reference && <Tag>{a.summary.reference}</Tag>}
                    {!a.readable && (
                      <Tag tone="danger">
                        <TriangleAlert size={11} /> {tr('start.unreadable')}
                      </Tag>
                    )}
                  </div>
                  <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]">
                    {a.file} · {formatBytes(a.size)} · {tr('start.closed')}{' '}
                    {(a.summary?.closed ?? a.modified).slice(0, 16).replace('T', ' ')}
                  </div>
                </div>
                {a.summary && (
                  <div className="hidden shrink-0 items-center gap-4 text-xs text-[var(--muted)] tabular sm:flex">
                    <span>{tr('start.artifacts', { n: formatCount(a.summary.artifacts ?? a.summary.findings) })}</span>
                    <span className="text-[var(--danger-text)]">
                      {tr('start.confirmed', { n: formatCount(a.summary.confirmed) })}
                    </span>
                    <span>{formatCount(a.summary.iocs)} IOCs</span>
                  </div>
                )}
                <Button disabled={!a.readable || importCase.isPending}
                  onClick={() => importCase.mutate({ file: a.file })}>
                  <ArchiveRestore size={14} /> {tr('start.restore')}
                </Button>
              </Card>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-[var(--muted)]">
            {tr('start.archived.note')}
          </p>
          </div>
        </div>
      )}
      </main>
      {data && <footer className="mt-10 px-4 py-4 text-xs text-[var(--muted)] sm:px-6 sm:text-right lg:px-8">
        {tr('start.workspace')} <span className="mono break-all">{data.workspace}</span>
      </footer>}
      {settingsOpen && <WorkspaceSettingsDialog initialTab={settingsTab} onClose={() => setSettingsOpen(false)} />}
      <ConfirmDialog
        open={confirmation?.kind === 'archive'}
        onClose={() => { if (!archiveCase.isPending) setConfirmation(null) }}
        title={tr('start.archive.confirm.title')}
        body={tr('start.archive.confirm.body')}
        confirmLabel={tr('start.archive.confirm.action')}
        pending={archiveCase.isPending}
        onConfirm={() => {
          if (!confirmation) return
          setBusy(confirmation.item.slug)
          archiveCase.mutate(confirmation.item.slug)
        }}
      />
      <ConfirmDialog
        open={confirmation?.kind === 'delete'}
        onClose={() => { if (!deleteCase.isPending) setConfirmation(null) }}
        title={tr('start.delete.confirm.title')}
        body={tr('start.delete.confirm.body')}
        confirmLabel={tr('start.delete.confirm.action')}
        pending={deleteCase.isPending}
        danger
        confirmText={confirmation?.kind === 'delete' ? confirmation.item.name : undefined}
        typeLabel={tr('start.delete.confirm.type')}
        onConfirm={() => {
          if (!confirmation) return
          setBusy(confirmation.item.slug)
          deleteCase.mutate(confirmation.item.slug)
        }}
      />
    </div>
  )
}
