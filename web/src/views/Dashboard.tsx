// Dashboard.tsx — the case at a glance: severity tiles, coverage chart,
// live jobs, evidence status.
import { useT } from '../i18n'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, FileText, Server } from 'lucide-react'
import { api, downloadUrl, type Dashboard as DashboardData } from '../api'
import { formatCount, formatDay } from '../format'
import { Card, ProgressBar, Section, StatTile, Tag } from '../components/ui'
import { TimelineChart } from '../components/TimelineChart'
import { LogCoverage } from '../components/LogCoverage'
import { GeoBanner } from '../components/GeoBanner'
import { EnrichmentBanners } from '../components/SetupBanners'
import type { Navigate } from '../App'

export function Dashboard({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const { data } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  if (!data) return <div className="py-16 text-center text-[var(--muted)] animate-pulse-soft">{tr('dashboard.loading')}</div>

  const sev = data.severity
  const triage = data.triage
  const noEvidence = !data.evidence.length
  const nextActions = [
    noEvidence ? {
      label: tr('dashboard.action.evidence'), detail: tr('dashboard.action.evidence.sub'),
      go: () => gotoView('evidence'), tone: 'var(--accent)',
    } : null,
    (triage.new ?? 0) > 0 ? {
      label: tr('dashboard.action.new', { n: formatCount(triage.new ?? 0) }),
      detail: tr('dashboard.action.new.sub'),
      go: () => gotoView('findings', { triage: 'new' }), tone: 'var(--sev-high)',
    } : null,
    (triage.reviewed ?? 0) > 0 ? {
      label: tr('dashboard.action.reviewed', { n: formatCount(triage.reviewed ?? 0) }),
      detail: tr('dashboard.action.reviewed.sub'),
      go: () => gotoView('findings', { triage: 'reviewed' }), tone: 'var(--sev-medium)',
    } : null,
    (triage.confirmed ?? 0) > 0 ? {
      label: tr('dashboard.action.report'), detail: tr('dashboard.action.report.sub'),
      go: () => gotoView('report'), tone: 'var(--ok)',
    } : null,
  ].filter((action): action is NonNullable<typeof action> => action != null)

  return (
    <div className="flex flex-col gap-6">
      <div className="flex justify-end">
        <a href={downloadUrl(`/api/cases/${slug}/report.html`)}
          title={tr('report.download.hint')}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-2 text-[12px] font-semibold transition-colors hover:border-[var(--accent)]/60">
          <FileText size={14} /> {tr('report.download')}
        </a>
      </div>
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

      {nextActions.length > 0 && (
        <Section title={tr('dashboard.nextActions')} sub={tr('dashboard.nextActions.sub')}>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {nextActions.slice(0, 3).map((action) => (
              <button key={action.label} onClick={action.go}
                className="flex cursor-pointer items-center gap-3 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-4 text-left transition-colors hover:border-[var(--accent)]/60 hover:bg-[var(--panel-2)]">
                <span className="h-8 w-1 shrink-0 rounded-full" style={{ background: action.tone }} />
                <span className="min-w-0 flex-1">
                  <span className="block text-[13px] font-semibold">{action.label}</span>
                  <span className="mt-0.5 block text-[11.5px] text-[var(--muted)]">{action.detail}</span>
                </span>
                <ArrowRight size={15} className="shrink-0 text-[var(--muted)]" />
              </button>
            ))}
          </div>
        </Section>
      )}

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
            sub={tr('dashboard.artifacts')} tone="var(--sev-high)"
            onClick={() => gotoView('findings', { severity: '0' })} />
          <StatTile label={tr('dashboard.medium')} value={formatCount(sev['1'] ?? 0)}
            info={tr('dashboard.medium.info')}
            sub={tr('dashboard.artifacts')} tone="var(--sev-medium)"
            onClick={() => gotoView('findings', { severity: '1' })} />
          <StatTile label={tr('dashboard.low')} value={formatCount(sev['2'] ?? 0)}
            info={tr('dashboard.low.info')}
            sub={tr('dashboard.artifacts')} tone="var(--sev-low)"
            onClick={() => gotoView('findings', { severity: '2' })} />
          <StatTile label={tr('dashboard.truePositive')} value={formatCount(triage['confirmed'] ?? 0)}
            info={tr('dashboard.confirmed.info')}
            sub={tr('dashboard.confirmed.sub')}
            onClick={() => gotoView('findings', { triage: 'confirmed' })} />
          <StatTile label={tr('dashboard.iocs')} value={formatCount(data.iocs)}
            info={tr('dashboard.iocs.info')}
            sub={tr('dashboard.iocs.sub')} onClick={() => gotoView('iocbox')} />
          <StatTile label={tr('dashboard.adminAccounts')} value={formatCount(data.admins)}
            info={tr('dashboard.admins.info')}
            sub={tr('dashboard.admins.sub', { n: formatCount(data.accounts) })}
            onClick={() => gotoView('database')} />
        </div>
      </Section>

      {/* The two coverage blocks stand together ABOVE the chronology, and in
          this order: the chart is the period the logs describe, the block
          under it is what is missing from that period. Both are context for
          the sequence below -- reading the order of events without knowing
          six hours of log are gone is reading a sentence with a word cut out
          and not noticing. */}
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

      <LogCoverage slug={slug} />
      <Card className="flex items-center justify-between gap-3 px-4 py-3">
        <div>
          <div className="text-[13px] font-semibold">{tr('dashboard.timeline.title')}</div>
          <div className="text-[11.5px] text-[var(--muted)]">{tr('dashboard.timeline.sub')}</div>
        </div>
        <button onClick={() => gotoView('timeline')}
          className="inline-flex shrink-0 cursor-pointer items-center gap-1 text-[12.5px] font-semibold text-[var(--accent-text)] hover:underline">
          {tr('dashboard.timeline.open')} <ArrowRight size={14} />
        </button>
      </Card>

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

    </div>
  )
}
