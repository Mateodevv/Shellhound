// Files.tsx — durch die Evidence klicken und Dateien von Hand als Indikator
// aufnehmen.
//
// Die Regeln finden, was sie kennen. Diese Ansicht ist für alles andere: die
// Datei, die einem beim Durchsehen auffällt, weil sie am falschen Ort liegt,
// weil ihr Name nicht passt, weil das Änderungsdatum in die Nacht des
// Vorfalls fällt. Ein Mensch sieht das — eine Regel hat es nicht gesucht.
//
// Man beginnt bei den registrierten Evidence-Wurzeln, nicht beim Dateisystem:
// was zum Fall gehört, ist die Auswahl. Tiefer geht es nur innerhalb dieser
// Wurzeln (dieselbe Schranke wie der Datei-Viewer, auf dem aufgelösten Pfad).
//
// Jeder Eintrag zeigt gleich, was der Fall über ihn schon weiß — schon in der
// IOC Box, Findings darauf —, damit man nicht von Hand markiert, was längst
// erfasst ist.
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronRight, FileSearch, FileText, FolderOpen, FolderTree, HardDrive,
  Home,
} from 'lucide-react'
import { api, post, type BrowseResponse, type CaseDetail } from '../api'
import {
  TRIAGE_LABEL, formatBytes, formatCount, type EvidenceRoot,
} from '../format'
import {
  Button, Card, EmptyState, SearchInput, SeverityBadge, Tag, TriageBadge,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import { WebrootDiff } from '../components/WebrootDiff'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { EVIDENCE_LABEL } from '../explain'
import type { ViewId } from '../App'

export function Files({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const qc = useQueryClient()
  const [path, setPath] = useState('')
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [note, setNote] = useState('')
  const [filter, setFilter] = useState('')
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // Was der Trace rot markieren soll — kommt aus dem Artefakt-Fenster,
  // das weiß, worum es geht (die Datei bzw. der Alarm des Clients).
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const t = useTriage(slug)

  const { data, isError, error } = useQuery({
    queryKey: ['browse', slug, path],
    queryFn: () => api<BrowseResponse>(
      `/api/cases/${slug}/browse?path=${encodeURIComponent(path)}`),
  })
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  // Der Wechsel des Verzeichnisses verwirft die Auswahl: eine Markierung,
  // die man nicht mehr sieht, würde man später versehentlich mit-flaggen.
  useEffect(() => { setChecked(new Set()); setFilter('') }, [path])

  const flag = useMutation({
    mutationFn: (paths: string[]) =>
      post<{ added: { value: string; type: string }[] }>(
        `/api/cases/${slug}/files/flag`, { paths, note }),
    onSuccess: () => {
      setChecked(new Set())
      setNote('')
      qc.invalidateQueries({ queryKey: ['browse'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  const files = useMemo(() => (data?.files ?? []).filter((f) =>
    !filter || f.name.toLowerCase().includes(filter.toLowerCase())),
    [data, filter])
  const dirs = useMemo(() => (data?.dirs ?? []).filter((d) =>
    !filter || d.name.toLowerCase().includes(filter.toLowerCase())),
    [data, filter])

  const atRoot = !path
  const toggleAll = () => {
    if (checked.size === files.length) setChecked(new Set())
    else setChecked(new Set(files.map((f) => f.path)))
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="Dateien"
          body="Durch die registrierte Evidence klicken — und markieren, was den Regeln entgangen ist."
          hint="Aufgenommen wird der Pfad UND der SHA-256: der Pfad sagt, wo etwas auf diesem Server lag, der Hash erkennt dieselbe Datei überall wieder.">
          <h1 className="mr-2 text-lg font-bold">Dateien</h1>
        </Tooltip>
        {!atRoot && (
          <Button variant="ghost" onClick={() => setPath('')}>
            <Home size={14} /> Evidence-Wurzeln
          </Button>
        )}
        {data?.parent != null && (
          <Button variant="ghost" onClick={() => setPath(data.parent!)}>
            .. übergeordnet
          </Button>
        )}
        {!atRoot && (
          <div className="ml-auto">
            <SearchInput value={filter} onChange={setFilter}
              placeholder="in diesem Ordner filtern…" />
          </div>
        )}
      </div>

      {!atRoot && (
        <div className="mono truncate rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[11.5px] text-[var(--muted)]"
          title={data?.path}>
          {data?.path}
        </div>
      )}

      {checked.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">
            {checked.size} Datei{checked.size === 1 ? '' : 'en'} markiert
          </span>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Notiz (warum? — wandert mit in die IOC Box)"
            className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="primary" disabled={flag.isPending}
            onClick={() => flag.mutate([...checked])}>
            <Box size={14} /> In die IOC Box (Pfad + SHA-256)
          </Button>
          <Button variant="ghost" onClick={() => setChecked(new Set())}>
            Auswahl leeren
          </Button>
        </div>
      )}

      {flag.data && (
        <div className="rounded-lg border border-[var(--ok)]/40 bg-[rgba(12,163,12,0.08)] px-3 py-2 text-[12px] animate-fade-up">
          <span className="font-semibold text-[var(--ok)]">
            {formatCount(flag.data.added.length)} Indikator(en) aufgenommen
          </span>
          <span className="ml-2 text-[var(--muted)]">
            {flag.data.added.filter((a) => a.type === 'hash').length} davon Hashes
          </span>
        </div>
      )}

      {isError && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
          {String((error as Error)?.message ?? error)}
        </div>
      )}

      {/* ---- Einstieg: die Wurzeln des Falls ---- */}
      {atRoot && (
        <div className="grid gap-3 md:grid-cols-2">
          {data?.roots.map((r) => (
            <Card key={r.path}
              className="px-4 py-3 transition-colors hover:border-[var(--accent)]/60">
              <button
                className="flex w-full cursor-pointer items-center gap-3 text-left"
                onClick={() => setPath(r.path)}>
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                  <HardDrive size={16} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-semibold">
                    {r.label?.trim() || EVIDENCE_LABEL[r.kind] || r.kind}
                  </div>
                  <div className="mono truncate text-[11px] text-[var(--muted)]" title={r.path}>
                    {r.path}
                  </div>
                </div>
                <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />
              </button>
            </Card>
          ))}
          {data && !data.roots.length && (
            <div className="md:col-span-2">
              <EmptyState icon={<FolderTree size={36} />} title="Keine Evidence registriert"
                sub="Diese Ansicht blättert durch das, was als Evidence registriert ist — Webroot-Kopie, Log-Ordner, SQL-Dump. Trage sie unter »Evidence & Jobs« ein." />
            </div>
          )}
        </div>
      )}

      {/* ---- Webroot gegen Referenzkopie ---- */}
      {atRoot && (caseInfo?.evidence_items?.length ?? 0) > 0 && (
        <WebrootDiff slug={slug} evidence={caseInfo!.evidence_items}
          onView={(p) => setViewing({ path: p, line: null })} />
      )}

      {/* ---- der Inhalt eines Verzeichnisses ---- */}
      {!atRoot && (
        <Card className="overflow-hidden">
          {files.length > 0 && (
            <div className="flex items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5">
              <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                checked={checked.size > 0 && checked.size === files.length}
                onChange={toggleAll} />
              <span className="text-[11px] uppercase tracking-wider text-[var(--muted)]">
                {formatCount(dirs.length)} Ordner · {formatCount(files.length)} Dateien
              </span>
            </div>
          )}
          {dirs.map((d) => (
            <button key={d.path}
              onClick={() => setPath(d.path)}
              className="group flex w-full cursor-pointer items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-1.5 text-left last:border-0 hover:bg-[var(--panel-2)]">
              <span className="w-4" />
              <FolderOpen size={15} className="shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate text-[13px]">{d.name}</span>
              <ChevronRight size={14} className="shrink-0 text-[var(--muted)] opacity-0 group-hover:opacity-100" />
            </button>
          ))}
          {files.map((f) => (
            <div key={f.path}
              className={clsx(
                'group flex items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-1.5 last:border-0',
                'transition-colors hover:bg-[var(--panel-2)]',
                checked.has(f.path) && 'bg-[var(--accent-soft)]')}>
              <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                checked={checked.has(f.path)}
                onChange={(e) => {
                  const next = new Set(checked)
                  if (e.target.checked) next.add(f.path)
                  else next.delete(f.path)
                  setChecked(next)
                }} />
              <FileText size={15} className="shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate text-[13px]" title={f.name}>
                {f.name}
              </span>
              {/* Was der Fall über diese Datei schon weiß. */}
              {f.flagged > 0 && f.worst != null && (
                <Tooltip hint="Auf diese Datei haben Regeln angesprochen — sie steht in der Arbeitsliste. Klick öffnet das Artefakt.">
                  <button
                    className="shrink-0 cursor-pointer"
                    onClick={() => {
                      t.clearCollected()
                      setSelected({
                        artifact: f.path, artifact_kind: 'file',
                        worst: f.worst!, triage: f.triage ?? 'new',
                        triage_note: '',
                      })
                    }}>
                    <SeverityBadge severity={f.worst} />
                  </button>
                </Tooltip>
              )}
              {f.triage && f.triage !== 'new' && (
                <TriageBadge state={f.triage} label={TRIAGE_LABEL[f.triage]} />
              )}
              {f.in_box && (
                <Tag tone="accent" explain="Diese Datei liegt bereits in der IOC Box.">IOC</Tag>
              )}
              <span className="w-20 shrink-0 text-right tabular text-[11px] text-[var(--muted)]">
                {formatBytes(f.size)}
              </span>
              <Tooltip hint="Den Inhalt ansehen — als Text und als Hex-Dump.">
                <button
                  className="shrink-0 cursor-pointer rounded p-1 text-[var(--muted)] opacity-0 transition-opacity hover:text-[var(--accent)] group-hover:opacity-100"
                  onClick={() => setViewing({ path: f.path, line: null })}>
                  <FileSearch size={15} />
                </button>
              </Tooltip>
            </div>
          ))}
          {!dirs.length && !files.length && (
            <div className="px-4 py-8 text-center text-[13px] text-[var(--muted)]">
              {filter ? 'Kein Eintrag passt zum Filter.' : 'Dieser Ordner ist leer.'}
            </div>
          )}
          {data?.truncated && (
            <div className="border-t border-[var(--line)] px-4 py-2 text-[12px] text-[var(--sev-low)]">
              Sehr viele Einträge — die Liste wurde gekürzt. Der Filter oben
              hilft, wenn das Gesuchte fehlt.
            </div>
          )}
        </Card>
      )}

      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line} layer={2} onClose={() => setViewing(null)} />
      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(p, line) => setViewing({ path: p, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, n) => {
          if (selected) t.decide([selected.artifact], state, n)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}
