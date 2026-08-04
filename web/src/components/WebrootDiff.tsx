// WebrootDiff.tsx — das Webroot gegen eine bekannt saubere Kopie.
//
// Die klassische Handarbeit nach jedem Webserver-Vorfall, als Abfrage: was
// ist ZUSÄTZLICH da (hochgeladene Shells wohnen hier), was ist VERÄNDERT
// (eingeschleuster Code in legitimen Dateien), was FEHLT (oft die Spur
// eines Aufräumversuchs). Ein Treffer ist ein KANDIDAT, kein Fund — jedes
// Upload-Verzeichnis ist voller legitimer Extras. Der Vergleich verkleinert
// den Heuhaufen; ansehen, flaggen oder verwerfen bleibt Handarbeit, und
// genau dafür stehen die Knöpfe an jeder Zeile.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Box, Check, FileSearch, GitCompare, Play } from 'lucide-react'
import { api, post, type EvidenceItem } from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, Card, Chip, Tag } from './ui'
import { InfoDot, Tooltip } from './Tooltip'

interface DiffRow {
  id: number
  status: 'extra' | 'missing' | 'modified' | 'too_big'
  path: string
  size: number
  ref_size: number
  absolute: string
  in_box: boolean
}

interface DiffData {
  total: number
  counts: Record<string, number>
  rows: DiffRow[]
  ran_at: string
  webroot: { path: string } | null
}

const STATUS_LABEL: Record<DiffRow['status'], string> = {
  extra: 'zusätzlich',
  modified: 'verändert',
  missing: 'fehlt',
  too_big: 'ungeprüft',
}

const STATUS_HINT: Record<DiffRow['status'], string> = {
  extra: 'Liegt nur im Webroot, nicht in der Referenz. Hochgeladen, generiert oder von der Referenz nicht abgedeckt — hier wohnen abgelegte Shells, aber auch jede legitime Upload-Datei.',
  modified: 'In beiden Bäumen, aber mit verschiedenem Inhalt (Größe oder SHA-256). Hier wohnt eingeschleuster Code in legitimen Dateien.',
  missing: 'Liegt nur in der Referenz. Gelöschte Kern-Dateien sind selten der Angriff, aber oft die Spur eines Aufräumversuchs.',
  too_big: 'Gleiche Größe, aber zu groß zum Hashen (>32 MB) — der Inhalt wurde NICHT verglichen. »Nicht geprüft« ist eine andere Aussage als »gleich«.',
}

const STATUS_TONE: Record<DiffRow['status'], 'danger' | 'warn' | undefined> = {
  extra: 'warn', modified: 'danger', missing: undefined, too_big: undefined,
}

export function WebrootDiff({ slug, evidence, onView }: {
  slug: string
  evidence: EvidenceItem[]
  onView: (path: string) => void
}) {
  const qc = useQueryClient()
  const webroots = evidence.filter((e) => e.kind === 'webroot')
  const references = evidence.filter((e) => e.kind === 'reference')
  const [webrootId, setWebrootId] = useState<number | ''>('')
  const [referenceId, setReferenceId] = useState<number | ''>('')
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')

  const hide = [...hidden].join(',')
  const { data } = useQuery({
    queryKey: ['diff', slug, hide, search],
    queryFn: () => api<DiffData>(
      `/api/cases/${slug}/diff?hide_status=${hide}&search=${encodeURIComponent(search)}&limit=500`),
  })

  const run = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/diff/run`, {
      webroot_id: webrootId || webroots[0]?.id,
      reference_id: referenceId || references[0]?.id,
    }),
  })

  const flag = useMutation({
    mutationFn: (paths: string[]) => post(`/api/cases/${slug}/files/flag`,
      { paths, note: 'Abweichung von der Referenzkopie' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['diff'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
    },
  })

  // Ohne Referenz gibt es nichts zu vergleichen — dann wirbt die Karte nur
  // dafür, eine zu registrieren, statt tote Bedienelemente zu zeigen.
  if (!references.length && !data?.rows.length) {
    return (
      <Card className="flex items-center gap-3 px-4 py-3">
        <GitCompare size={16} className="shrink-0 text-[var(--muted)]" />
        <div className="min-w-0 flex-1 text-[12.5px] text-[var(--muted)]">
          <span className="font-medium text-[var(--fg)]">Vergleich mit einer Referenzkopie:</span>{' '}
          registriere unter Evidence &amp; Jobs ein bekannt sauberes Release
          derselben CMS-Version als <span className="font-medium">Referenzkopie</span> —
          dann steht hier, welche Dateien zusätzlich, verändert oder gelöscht sind.
        </div>
      </Card>
    )
  }

  const counts = data?.counts ?? {}
  const total = Object.values(counts).reduce((a, b) => a + b, 0)

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2.5">
        <GitCompare size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="text-[13px] font-semibold">Vergleich mit Referenzkopie</span>
        <InfoDot title="Webroot-Diff"
          body="Vergleicht das Webroot Datei für Datei mit einer bekannt sauberen Kopie (Größe, dann SHA-256)."
          hint="Ein Treffer ist ein Kandidat, kein Fund: jedes Upload-Verzeichnis ist voller legitimer Extras. Der Vergleich verkleinert den Heuhaufen — die Bewertung bleibt bei dir." />
        {webroots.length > 1 && (
          <select value={webrootId} onChange={(e) => setWebrootId(Number(e.target.value))}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2 py-1 text-[12px] outline-none cursor-pointer">
            {webroots.map((e) => (
              <option key={e.id} value={e.id}>{e.label || e.path}</option>
            ))}
          </select>
        )}
        {references.length > 1 && (
          <select value={referenceId} onChange={(e) => setReferenceId(Number(e.target.value))}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2 py-1 text-[12px] outline-none cursor-pointer">
            {references.map((e) => (
              <option key={e.id} value={e.id}>{e.label || e.path}</option>
            ))}
          </select>
        )}
        {references.length > 0 && webroots.length > 0 && (
          <Tooltip hint="Läuft als Job — der Fortschritt erscheint links unten. Ein neuer Lauf ersetzt das alte Ergebnis.">
            <Button variant="primary" disabled={run.isPending}
              onClick={() => run.mutate()}>
              <Play size={13} /> Vergleichen
            </Button>
          </Tooltip>
        )}
        {data?.ran_at && (
          <span className="ml-auto text-[11px] text-[var(--muted)]">
            zuletzt: {data.ran_at.replace('T', ' ')}
          </span>
        )}
      </div>

      {total > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--line)] px-4 py-2">
          {(['modified', 'extra', 'missing', 'too_big'] as const).map((s) => (
            counts[s] ? (
              <Tooltip key={s} title={STATUS_LABEL[s]} body={STATUS_HINT[s]}
                hint={hidden.has(s) ? 'Ausgeblendet — Klick holt sie zurück.'
                                    : 'Klick blendet diese Klasse aus.'}>
                <Chip active={false} dimmed={hidden.has(s)} count={counts[s]}
                  onClick={() => setHidden((prev) => {
                    const next = new Set(prev)
                    if (next.has(s)) next.delete(s)
                    else next.add(s)
                    return next
                  })}>
                  {STATUS_LABEL[s]}
                </Chip>
              </Tooltip>
            ) : null
          ))}
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Pfad filtern…"
            className="mono ml-auto w-56 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2.5 py-1 text-[12px] outline-none focus:border-[var(--accent)]/70" />
        </div>
      )}

      {(data?.rows ?? []).map((r) => (
        <div key={r.id}
          className="group flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-1.5 last:border-0 hover:bg-[var(--panel-2)]">
          <Tag tone={STATUS_TONE[r.status]} explain={STATUS_HINT[r.status]}>
            {STATUS_LABEL[r.status]}
          </Tag>
          <span className="mono min-w-0 flex-1 truncate text-[12px]" title={r.path}>
            {r.path}
          </span>
          {r.in_box && <Tag tone="accent">IOC</Tag>}
          <span className="shrink-0 tabular text-[11px] text-[var(--muted)]">
            {r.status === 'missing' ? formatBytes(r.ref_size) : formatBytes(r.size)}
            {r.status === 'modified' && ` (Referenz ${formatBytes(r.ref_size)})`}
          </span>
          <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
            {r.absolute && (
              <Button variant="ghost" onClick={() => onView(r.absolute)}>
                <FileSearch size={13} /> Ansehen
              </Button>
            )}
            {r.absolute && !r.in_box && (
              <Tooltip hint="Pfad + SHA-256 in die IOC Box, mit der Abweichung als Herkunft.">
                <Button variant="ghost" disabled={flag.isPending}
                  onClick={() => flag.mutate([r.absolute])}>
                  <Box size={13} /> IOC
                </Button>
              </Tooltip>
            )}
            {r.in_box && <Check size={13} className="text-[var(--ok)]" />}
          </div>
        </div>
      ))}

      {data && total > 0 && (
        <div className="px-4 py-2 text-[11.5px] text-[var(--muted)]">
          {formatCount(data.total)} Abweichung(en)
          {data.rows.length < data.total && ` — die ersten ${formatCount(data.rows.length)} angezeigt, Filter verfeinern`}
        </div>
      )}
      {data && total === 0 && data.ran_at && (
        <div className={clsx('px-4 py-3 text-[12.5px] text-[var(--muted)]')}>
          Keine Abweichungen — Webroot und Referenz sind Datei für Datei identisch.
        </div>
      )}
    </Card>
  )
}
