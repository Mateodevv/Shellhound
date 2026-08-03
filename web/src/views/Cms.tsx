// Cms.tsx — das Inventar der Installationen: welches CMS, welche Version,
// welche Erweiterungen — und WELCHE DAVON KOMPROMITTIERT IST.
//
// EINE Liste pro Installation statt eines Kachel-Mosaiks: früher wurde jeder
// Engine-Typ eine eigene Karten-Tabelle, und Joomla produziert davon 10-15
// („Plugin (system)", „Plugin (content)" …) — unterschiedlich hohe Kacheln
// ohne Leserichtung. Jetzt falten sich die Typen auf 4-5 Gruppen zusammen
// (die Plugin-Gruppe und Site/Admin sind ein Zusatz an der Zeile, kein
// eigener Typ), und man liest einmal von oben nach unten.
//
// Der Fall-Bezug kommt vom Server: Erweiterungen mit geflaggten Dateien
// darunter tragen ein Badge und öffnen das Artefakt-Fenster — die Frage
// „welche Erweiterung ist es?" beantwortet die Seite selbst, statt den
// Pfad-Abgleich dem Kopf des Analysten zu überlassen.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bug, Puzzle, Server, TriangleAlert } from 'lucide-react'
import clsx from 'clsx'
import { api, type CaseDetail, type CmsInstall, type CmsItem } from '../api'
import { SEVERITY_VAR, formatCount, shortPath, type EvidenceRoot } from '../format'
import { Card, Chip, EmptyState, SearchInput, SeverityBadge, Tag } from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { FIELD_EXPLAIN } from '../explain'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp, useTriage } from '../components/triage'
import { TraceWindow } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

// „Plugin (system)" -> Gruppe Plugin, Zusatz system; „Module (Admin)" ->
// Gruppe Module, Bereich Admin. Der Zusatz gehört an die Zeile, nicht in
// die Gliederung — sonst wird jede Plugin-Gruppe eine eigene Tabelle.
const SCOPES = new Set(['Site', 'Admin'])

function splitType(raw: string): { base: string; qualifier?: string; scope?: string } {
  const m = raw.match(/^(.*?)\s*\((.+)\)$/)
  if (!m) return { base: raw }
  return SCOPES.has(m[2])
    ? { base: m[1], scope: m[2] }
    : { base: m[1], qualifier: m[2] }
}

// Lesereihenfolge: das am häufigsten Manipulierte zuerst.
const TYPE_ORDER: Record<string, number> = {
  Plugin: 1, Theme: 2, Template: 3, Component: 4, Module: 5,
}

export function Cms({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const { data } = useQuery({
    queryKey: ['cms', slug],
    queryFn: () => api<{ installs: CmsInstall[] }>(`/api/cases/${slug}/cms`),
  })
  const [search, setSearch] = useState('')
  // Ausblende-Schalter wie überall: Typen und Versions-Zustand.
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [hiddenVersion, setHiddenVersion] = useState<Set<string>>(new Set())

  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const t = useTriage(slug)

  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  const installs = useMemo(() => data?.installs ?? [], [data])

  // Chip-Zähler über ALLE Installationen — eine Filterleiste für die Seite.
  const typeCounts = useMemo(() => {
    const out = new Map<string, number>()
    for (const inst of installs) {
      for (const i of inst.items) {
        const base = splitType(i.type).base
        out.set(base, (out.get(base) ?? 0) + 1)
      }
    }
    return [...out.entries()].sort(
      (a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99))
  }, [installs])

  const versionCounts = useMemo(() => {
    let known = 0, unknown = 0
    for (const inst of installs) {
      for (const i of inst.items) {
        if (i.version === '(unknown)') unknown += 1
        else known += 1
      }
    }
    return { known, unknown }
  }, [installs])

  const visible = (i: CmsItem) => {
    const base = splitType(i.type).base
    if (hiddenTypes.has(base)) return false
    if (hiddenVersion.has(i.version === '(unknown)' ? 'unknown' : 'known')) return false
    if (search && !i.name.toLowerCase().includes(search.toLowerCase()) &&
        !i.slug.toLowerCase().includes(search.toLowerCase())) return false
    return true
  }

  const toggle = (set: (fn: (prev: Set<string>) => Set<string>) => void, v: string) =>
    set((prev) => {
      const next = new Set(prev)
      if (next.has(v)) next.delete(v)
      else next.add(v)
      return next
    })

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="CMS Inventory"
          body="Welche CMS-Installationen im Webroot stecken und welche Erweiterungen mit welcher Version installiert sind — und welche davon geflaggte Dateien enthalten."
          hint="Die Versionen gleichst du gegen bekannte Lücken ab (WPScan, Joomla VEL). Jeder Chip blendet seine Klasse aus; Klick auf ein Finding-Badge öffnet das Artefakt.">
          <h1 className="mr-2 text-lg font-bold">CMS Inventory</h1>
        </Tooltip>
        {typeCounts.map(([base, n]) => (
          <Tooltip key={base}
            hint={hiddenTypes.has(base)
              ? 'Ausgeblendet — Klick holt diese Einträge zurück.'
              : 'Klick blendet diesen Typ aus.'}>
            <Chip active={false} dimmed={hiddenTypes.has(base)}
              onClick={() => toggle(setHiddenTypes, base)} count={n}>
              {base}
            </Chip>
          </Tooltip>
        ))}
        {typeCounts.length > 0 && <span className="mx-1 h-4 w-px bg-[var(--line)]" />}
        <Tooltip hint="Klick blendet Erweiterungen mit erkannter Version aus — übrig bleiben die ohne Manifest.">
          <Chip active={false} dimmed={hiddenVersion.has('known')}
            onClick={() => toggle(setHiddenVersion, 'known')} count={versionCounts.known}>
            mit Version
          </Chip>
        </Tooltip>
        <Tooltip hint={FIELD_EXPLAIN.unknown_version}>
          <Chip active={false} dimmed={hiddenVersion.has('unknown')}
            onClick={() => toggle(setHiddenVersion, 'unknown')} count={versionCounts.unknown}>
            <TriangleAlert size={12} /> ohne Version
          </Chip>
        </Tooltip>
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder="Extension suchen…" />
        </div>
      </div>

      {installs.map((inst) => (
        <InstallCard key={inst.id} install={inst} visible={visible}
          onOpenArtifact={(stub) => { t.clearCollected(); setSelected(stub) }} />
      ))}

      {data && !installs.length && (
        <EmptyState icon={<Puzzle size={36} />} title="Noch kein CMS erfasst"
          sub="Das Inventar entsteht aus dem Webroot. Registriere die Webroot-Kopie als Evidence und starte die Analyse — WordPress- und Joomla-Installationen werden mitsamt ihren Erweiterungen automatisch erkannt." />
      )}

      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips) => setTraceIps(ips)}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) t.decide([selected.artifact], state, note)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1}
        onClose={() => setTraceIps(null)} />
      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line} layer={2} onClose={() => setViewing(null)} />
      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}

function InstallCard({ install, visible, onOpenArtifact }: {
  install: CmsInstall
  visible: (i: CmsItem) => boolean
  onOpenArtifact: (stub: ArtifactStub) => void
}) {
  const unknown = install.items.filter((i) => i.version === '(unknown)').length
  const flagged = install.items.filter((i) => i.flagged > 0).length

  // Eine Liste, gegliedert nach Basis-Typ — die Plugin-Gruppe steht als
  // Zusatz an der Zeile.
  const sections = useMemo(() => {
    const byBase = new Map<string, CmsItem[]>()
    for (const i of install.items) {
      if (!visible(i)) continue
      const base = splitType(i.type).base
      const list = byBase.get(base) ?? []
      list.push(i)
      byBase.set(base, list)
    }
    for (const list of byBase.values()) {
      // Geflaggtes zuerst — das ist, was man hier sucht.
      list.sort((a, b) => (b.flagged - a.flagged) || a.name.localeCompare(b.name))
    }
    return [...byBase.entries()].sort(
      (a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99))
  }, [install.items, visible])

  const shown = sections.reduce((n, [, list]) => n + list.length, 0)

  return (
    <Card className="overflow-hidden">
      {/* ---- der Kopf: die wichtigste Zahl der Seite ist die Version ---- */}
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
          <Server size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
            {install.cms}
            {install.version === '(unknown)'
              ? <Tag tone="warn" hint="Die Kern-Version ließ sich nicht bestimmen — bei einer manipulierten Installation selbst ein Befund.">Version unbekannt</Tag>
              : <span className="mono text-[var(--accent-text)]">{install.version}</span>}
          </div>
          <div className="mono truncate text-[11.5px] text-[var(--muted)]" title={install.root}>
            {install.root}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2 text-[12px] text-[var(--muted)]">
          <span>{formatCount(install.items.length)} Erweiterung{install.items.length === 1 ? '' : 'en'}</span>
          {unknown > 0 && (
            <Tag tone="warn" hint={FIELD_EXPLAIN.unknown_version}>{unknown} ohne Version</Tag>
          )}
          {flagged > 0 && (
            <Tag tone="danger"
              hint="Erweiterungen, unter deren Pfad geflaggte Dateien liegen — die Kandidaten für den Einstiegspunkt.">
              <Bug size={11} /> {flagged} mit Findings
            </Tag>
          )}
        </div>
      </div>

      {/* ---- eine Liste, Gruppen als Bänder ---- */}
      {sections.map(([base, list]) => (
        <div key={base}>
          <div className="border-b border-[var(--line)] bg-[var(--panel-2)]/60 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {base} <span className="opacity-70">({list.length})</span>
          </div>
          {list.map((item) => {
            const { qualifier, scope } = splitType(item.type)
            const worstHit = item.artifacts[0]
            return (
              <div key={item.id}
                className={clsx(
                  'flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0',
                  'transition-colors hover:bg-[var(--panel-2)]')}>
                {/* Farbkante nur, wenn hier etwas gefunden wurde. */}
                <span className="h-8 w-1 shrink-0 rounded-full"
                  style={{ background: worstHit ? SEVERITY_VAR[worstHit.worst] : 'transparent' }} />
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-[13px] font-medium">{item.name}</span>
                    {qualifier && <Tag>{qualifier}</Tag>}
                    {scope && <Tag>{scope}</Tag>}
                  </div>
                  <div className="mono truncate text-[11px] text-[var(--muted)]" title={item.path}>
                    {item.slug} · {shortPath(item.path, 60)}
                  </div>
                </div>
                {item.flagged > 0 && worstHit && (
                  <Tooltip
                    title={`${item.flagged} geflaggte${item.flagged === 1 ? 's' : ''} Artefakt${item.flagged === 1 ? '' : 'e'} unter diesem Pfad`}
                    body={item.artifacts.map((a) => a.artifact).join('\n')}
                    hint="Klick öffnet das Artefakt — entscheiden wie in Findings."
                    wide>
                    <button
                      className={clsx(
                        'inline-flex shrink-0 cursor-pointer items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium',
                        item.artifacts.some((a) => a.triage === 'confirmed')
                          ? 'bg-[var(--danger-soft)] text-[var(--danger-text)]'
                          : 'bg-[rgba(250,178,25,0.12)] text-[var(--sev-low)]')}
                      onClick={() => onOpenArtifact({
                        artifact: worstHit.artifact, artifact_kind: 'file',
                        worst: worstHit.worst, triage: worstHit.triage,
                        triage_note: '',
                      })}>
                      <Bug size={11} /> {item.flagged} Artefakt{item.flagged === 1 ? '' : 'e'}
                    </button>
                  </Tooltip>
                )}
                <div className="w-28 shrink-0 text-right">
                  {item.version === '(unknown)'
                    ? <Tag tone="warn" hint={FIELD_EXPLAIN.unknown_version}>unbekannt</Tag>
                    : <span className="mono text-[12px]">{item.version}</span>}
                </div>
                {worstHit && <SeverityBadge severity={worstHit.worst} plain />}
              </div>
            )
          })}
        </div>
      ))}

      {shown === 0 && (
        <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
          Kein Eintrag entspricht Filter/Suche — durchgestrichene Chips holen
          Ausgeblendetes zurück.
        </div>
      )}
    </Card>
  )
}
