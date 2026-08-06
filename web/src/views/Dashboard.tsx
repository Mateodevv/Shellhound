// Dashboard.tsx — the case at a glance: severity tiles, coverage chart,
// live jobs, evidence status.
import { useT } from '../i18n'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Server } from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData } from '../api'
import { formatCount, formatDay, type EvidenceRoot } from '../format'
import { Card, ProgressBar, Section, StatTile, Tag } from '../components/ui'
import { TimelineChart } from '../components/TimelineChart'
import { CaseChain } from '../components/CaseChain'
import { GeoBanner } from '../components/GeoBanner'
import { EnrichmentBanners } from '../components/SetupBanners'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import type { ViewId } from '../App'

export function Dashboard({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  // From the chronology one should be able to do the same as everywhere:
  // open the artifact, trace the client. A timeline from which one cannot
  // jump into the evidence is a list of claims.
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const t = useTriage(slug)

  const { data } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))
  if (!data) return <div className="py-16 text-center text-[var(--muted)] animate-pulse-soft">{tr('dashboard.loading')}</div>

  const sev = data.severity
  const triage = data.triage
  const noEvidence = !data.evidence.length

  return (
    <div className="flex flex-col gap-6">
      {noEvidence && (
        <Card className="flex items-center justify-between gap-3 border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-3 animate-fade-up">
          <div className="text-[13px]">
            <span className="font-semibold">{tr('dashboard.empty.title')}</span>{' '}
            {tr('dashboard.empty.sub')}
          </div>
          <button
            onClick={() => gotoView('evidence')}
            className="inline-flex shrink-0 items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline cursor-pointer"
          >
            {tr('dashboard.toEvidence')} <ArrowRight size={14} />
          </button>
        </Card>
      )}

      {/* Like the evidence banner: visible while something is missing,
          gone once it is done. */}
      <GeoBanner onOpenSettings={() => gotoView('settings')} />
      <EnrichmentBanners onOpenSettings={() => gotoView('settings')} />

      {data.jobs_running.length > 0 && (
        <Card className="px-4 py-3 animate-fade-up">
          <div className="mb-2 text-[13px] font-semibold">{tr('dashboard.running')}</div>
          {data.jobs_running.map((j) => (
            <div key={j.id} className="mb-2 last:mb-0">
              <div className="mb-1 flex justify-between text-[12px] text-[var(--muted)]">
                <span className="truncate">{j.message || j.kind}</span>
                <span className="tabular">{Math.round(j.progress * 100)}%</span>
              </div>
              <ProgressBar value={j.progress} />
            </div>
          ))}
        </Card>
      )}

      <Section title={tr('dashboard.artifacts')}
        sub={tr('dashboard.artifacts.sub', { n: formatCount(data.findings_total) })}>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
          <StatTile label={tr('dashboard.high')} value={formatCount(sev['0'] ?? 0)}
            info={tr('dashboard.high.info')}
            sub={tr('dashboard.artifacts')} tone="var(--sev-high)" onClick={() => gotoView('findings')} />
          <StatTile label={tr('dashboard.medium')} value={formatCount(sev['1'] ?? 0)}
            info={tr('dashboard.medium.info')}
            sub={tr('dashboard.artifacts')} tone="var(--sev-medium)" onClick={() => gotoView('findings')} />
          <StatTile label={tr('dashboard.low')} value={formatCount(sev['2'] ?? 0)}
            info={tr('dashboard.low.info')}
            sub={tr('dashboard.artifacts')} tone="var(--sev-low)" onClick={() => gotoView('findings')} />
          <StatTile label={tr('dashboard.truePositive')} value={formatCount(triage['confirmed'] ?? 0)}
            info={tr('dashboard.confirmed.info')}
            sub={tr('dashboard.confirmed.sub')} onClick={() => gotoView('findings')} />
          <StatTile label={tr('dashboard.iocs')} value={formatCount(data.iocs)}
            info={tr('dashboard.iocs.info')}
            sub={tr('dashboard.iocs.sub')} onClick={() => gotoView('iocbox')} />
          <StatTile label={tr('dashboard.adminAccounts')} value={formatCount(data.admins)}
            info={tr('dashboard.admins.info')}
            sub={tr('dashboard.admins.sub', { n: formatCount(data.accounts) })}
            onClick={() => gotoView('database')} />
        </div>
      </Section>

      <CaseChain slug={slug}
        onOpen={(artifact, kind) => setSelected({
          artifact,
          artifact_kind: (kind || 'file') as ArtifactStub['artifact_kind'],
          // The chain only ever shows confirmed artifacts; everything else
          // the window fetches itself through the context endpoint.
          worst: 0, triage: 'confirmed', triage_note: '',
        })}
        onTrace={(ip) => { setTraceMarks(undefined); setTraceIps([ip]) }} />

      {data.logs && (
        <Section
          title={tr('dashboard.logCoverage')}
          sub={tr('dashboard.logCoverage.sub', {
            lines: formatCount(data.logs.lines),
            clients: formatCount(data.logs.clients),
            from: formatDay(data.logs.first_epoch),
            to: formatDay(data.logs.last_epoch),
          }) + (data.logs.unparsed
            ? ` · ${tr('dashboard.logCoverage.unparsed', { n: formatCount(data.logs.unparsed) })}`
            : '')}
          right={
            <button onClick={() => gotoView('actors')}
              className="inline-flex items-center gap-1 text-[13px] font-medium text-[var(--accent-text)] hover:underline cursor-pointer">
              {tr('dashboard.alertedClients', { n: formatCount(data.logs.alerted_clients) })} <ArrowRight size={14} />
            </button>
          }
        >
          <Card className="p-4">
            <TimelineChart data={data.timeline} />
          </Card>
        </Section>
      )}

      {data.cms_installs.length > 0 && (
        <Section title={tr('dashboard.installs')} sub={tr('dashboard.installs.sub')}>
          <div className="grid gap-3 md:grid-cols-2">
            {data.cms_installs.map((inst) => (
              <Card key={inst.id} className="flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors hover:border-[var(--accent)]/60"
                >
                <button className="flex w-full items-center gap-3 text-left cursor-pointer" onClick={() => gotoView('cms')}>
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--accent-soft)]">
                    <Server size={16} className="text-[var(--accent)]" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-semibold">
                      {inst.cms} <span className="text-[var(--muted)]">{inst.version}</span>
                    </div>
                    <div className="mono truncate text-[11px] text-[var(--muted)]">{inst.root}</div>
                  </div>
                  <Tag tone="accent">{tr('dashboard.inventory')}</Tag>
                </button>
              </Card>
            ))}
          </div>
        </Section>
      )}

      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) t.decide([selected.artifact], state, note)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line ?? null}
        layer={2}
        onClose={() => setViewing(null)}
      />
      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}
