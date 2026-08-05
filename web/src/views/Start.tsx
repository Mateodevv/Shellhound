// Start.tsx — die Landing-View: offenen Fall wählen, neuen anlegen, oder
// einen abgeschlossenen Fall aus dem Archiv zurückholen.
import { useT } from '../i18n'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Archive, ArchiveRestore, FolderSearch, Package, Plus, Shield, TriangleAlert,
} from 'lucide-react'
import {
  api, post, type ArchivesResponse, type CaseInfo, type ImportResult,
} from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, Card, EmptyState, Tag } from '../components/ui'
import { ThemeSwitcher } from '../components/ThemeSwitcher'

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
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [reference, setReference] = useState('')
  const [importPath, setImportPath] = useState('')
  const [showImport, setShowImport] = useState(false)

  const create = useMutation({
    mutationFn: () => post<CaseInfo>('/api/cases', { name, reference }),
    onSuccess: (info) => {
      qc.invalidateQueries({ queryKey: ['state'] })
      onOpen(info.slug)
    },
  })

  const importCase = useMutation({
    mutationFn: (body: { file?: string; path?: string }) =>
      post<ImportResult>('/api/import', body),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['state'] })
      qc.invalidateQueries({ queryKey: ['archives'] })
      onOpen(result.slug)
    },
  })

  const archiveList = archives?.archives ?? []

  return (
    <div className="mx-auto flex min-h-full max-w-3xl flex-col justify-center px-6 py-12">
      <div className="mb-8 flex items-center gap-3 animate-fade-up">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[var(--accent-soft)]">
          <Shield className="text-[var(--accent)]" size={22} />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight">SHELLHOUND</h1>
          <p className="text-[13px] text-[var(--muted)]">
            Webserver-Forensik — Findings · Actors · IOC Box · CMS · Database
          </p>
        </div>
        <div className="ml-auto">
          <ThemeSwitcher />
        </div>
      </div>

      {data && (
        <p className="mb-3 text-xs text-[var(--muted)]">
          Workspace: <span className="mono">{data.workspace}</span>
        </p>
      )}

      <div className="flex flex-col gap-2">
        {isLoading && <div className="text-[var(--muted)]">Lade Cases…</div>}
        {data?.cases.map((c, i) => (
          <Card
            key={c.slug}
            className="animate-fade-up cursor-pointer px-4 py-3 transition-colors hover:border-[var(--accent)]/60 hover:bg-[var(--panel-2)]"
            style={{ animationDelay: `${i * 40}ms` }}
          >
            <button className="flex w-full items-center justify-between text-left cursor-pointer"
              onClick={() => onOpen(c.slug)}>
              <div className="min-w-0">
                <div className="font-semibold">{c.name}</div>
                <div className="mt-0.5 text-xs text-[var(--muted)]">
                  {c.reference && <span className="mr-3">{c.reference}</span>}
                  angelegt {c.created?.slice(0, 10)}
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-4 text-xs text-[var(--muted)] tabular">
                <span>{c.artifacts ?? 0} Artefakte</span>
                <span className="text-[var(--danger-text)]">{c.confirmed ?? 0} bestätigt</span>
                <span>{c.iocs ?? 0} IOCs</span>
              </div>
            </button>
          </Card>
        ))}

        {data && data.cases.length === 0 && !creating && (
          <EmptyState
            icon={<FolderSearch size={40} />}
            title="Kein offener Fall"
            sub={archiveList.length
              ? tr('start.empty')
              : 'Lege den ersten Fall an — danach registrierst du Evidence (Webroot, Access-Logs, SQL-Dump) und startest die Analyse.'}
          />
        )}
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {creating ? (
          <Card className="w-full animate-fade-up p-4">
            <div className="flex flex-col gap-3">
              <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && name.trim()) create.mutate() }}
                placeholder="Case-Name, z.B. Musterfirma GmbH — Joomla"
                className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 outline-none focus:border-[var(--accent)]/70"
              />
              <input
                value={reference}
                onChange={(e) => setReference(e.target.value)}
                placeholder="Referenz / Ticket (optional)"
                className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
              />
              <div className="flex gap-2">
                <Button variant="primary" disabled={!name.trim() || create.isPending}
                  onClick={() => create.mutate()}>
                  Case anlegen
                </Button>
                <Button variant="ghost" onClick={() => setCreating(false)}>Abbrechen</Button>
              </div>
              {create.isError && (
                <div className="text-xs text-[var(--danger-text)]">{String(create.error)}</div>
              )}
            </div>
          </Card>
        ) : (
          <>
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus size={15} /> Neuer Case
            </Button>
            <Button onClick={() => setShowImport(!showImport)}>
              <ArchiveRestore size={15} /> Fall importieren
            </Button>
          </>
        )}
      </div>

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
            placeholder="Pfad zu einem Fall-Archiv (.zip) — z.B. von einem anderen Rechner"
            className="mono min-w-64 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="primary" disabled={!importPath.trim() || importCase.isPending}
            onClick={() => importCase.mutate({ path: importPath })}>
            Importieren
          </Button>
        </Card>
      )}

      {importCase.isError && (
        <div className="mt-2 rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)] animate-fade-up">
          Import fehlgeschlagen: {String((importCase.error as Error)?.message ?? importCase.error)}
        </div>
      )}

      {archiveList.length > 0 && (
        <div className="mt-8 animate-fade-up">
          <div className="mb-2 flex items-baseline justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[15px] font-semibold">
              <Archive size={15} className="text-[var(--muted)]" />
              Abgeschlossene Fälle
            </h2>
            <span className="mono truncate text-[11px] text-[var(--muted)]"
              title={archives?.archive_dir}>
              {archives?.archive_dir}
            </span>
          </div>
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
                        <TriangleAlert size={11} /> unlesbar
                      </Tag>
                    )}
                  </div>
                  <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]">
                    {a.file} · {formatBytes(a.size)} · abgeschlossen{' '}
                    {(a.summary?.closed ?? a.modified).slice(0, 16).replace('T', ' ')}
                  </div>
                </div>
                {a.summary && (
                  <div className="hidden shrink-0 items-center gap-4 text-xs text-[var(--muted)] tabular sm:flex">
                    <span>{formatCount(a.summary.artifacts ?? a.summary.findings)} Artefakte</span>
                    <span className="text-[var(--danger-text)]">
                      {formatCount(a.summary.confirmed)} bestätigt
                    </span>
                    <span>{formatCount(a.summary.iocs)} IOCs</span>
                  </div>
                )}
                <Button disabled={!a.readable || importCase.isPending}
                  onClick={() => importCase.mutate({ file: a.file })}>
                  <ArchiveRestore size={14} /> Zurückholen
                </Button>
              </Card>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-[var(--muted)]">
            Ein abgeschlossener Fall liegt nur noch als ZIP vor. Beim Zurückholen
            kommt alles wieder — Findings, Triage-Entscheidungen, IOC Box, CMS- und
            Datenbank-Ergebnisse. Nur der Log-Index wird nicht mitarchiviert (er ist
            aus der Evidence jederzeit neu baubar) und wird bei der nächsten Analyse
            wieder aufgebaut.
          </p>
        </div>
      )}
    </div>
  )
}
