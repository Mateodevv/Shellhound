// Dashboard.tsx — the forensic state of the case at a glance.
//
// This is deliberately not a work queue. Triage actions, analysis runs and
// report preparation have their own places in the case shell; the dashboard
// answers four forensic questions only: what is confirmed, when was it
// observed, which entities are involved, and where are the evidential limits.
import { useT } from '../i18n'
import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import clsx from 'clsx'
import {
  Activity, AlertTriangle, ArrowRight, CalendarClock, Database, Fingerprint,
  HardDrive, Radar, ShieldCheck, Users,
} from 'lucide-react'
import { api, type Dashboard as DashboardData } from '../api'
import {
  formatCount, formatDay, formatLogTime, formatSpan, relativeToRoot,
  SEVERITY_LABEL, SEVERITY_VAR, shortPath,
} from '../format'
import { KIND_ICON } from '../artifactKinds'
import { Card, EmptyState, Section, Tag } from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { TimelineChart } from '../components/TimelineChart'
import { LogCoverage } from '../components/LogCoverage'
import type { Navigate } from '../App'

type Observation = DashboardData['chronology']['observations'][number]

const OBSERVATION_ROLE: Record<Observation['role'], string> = {
  first: 'dashboard.observation.first',
  first_success: 'dashboard.observation.firstSuccess',
  account: 'dashboard.observation.account',
  first_alert: 'dashboard.observation.firstAlert',
  last: 'dashboard.observation.last',
}

const KIND_ORDER = ['file', 'client', 'table', 'dump'] as const

function Metric({ label, value, sub, icon, onClick, tone }: {
  label: string
  value: string
  sub: string
  icon: ReactNode
  onClick?: () => void
  tone?: string
}) {
  const content = (
    <>
      <span className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
        <span style={tone ? { color: tone } : undefined}>{icon}</span>
        {label}
      </span>
      <span className="mt-2 block text-2xl font-semibold tabular"
        style={tone ? { color: tone } : undefined}>
        {value}
      </span>
      <span className="mt-0.5 block text-[11.5px] text-[var(--muted)]">{sub}</span>
    </>
  )
  const classes = clsx(
    'min-w-0 px-4 py-3 text-left first:pl-0 last:pr-0',
    'border-l border-[var(--line-soft)] first:border-l-0',
    onClick && 'cursor-pointer rounded-lg transition-colors hover:bg-[var(--panel-2)]')
  return onClick
    ? <button type="button" onClick={onClick} className={classes}>{content}</button>
    : <div className={classes}>{content}</div>
}

function TimeFact({ label, at, explanation }: {
  label: string
  at?: number | null
  explanation: { title: string; body: string; hint?: string }
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-[var(--line-soft)] py-2 last:border-0">
      <span className="inline-flex items-center gap-1.5 text-[12px] text-[var(--muted)]">
        {label}
        <InfoDot {...explanation} wide />
      </span>
      <span className="mono shrink-0 text-[12px] tabular">
        {at ? formatLogTime(at, 0).slice(0, 16) : '—'}
      </span>
    </div>
  )
}

function artifactLabel(
  item: DashboardData['confirmed_artifacts'][number],
  evidence: DashboardData['evidence'],
) {
  if (item.artifact_kind === 'file') {
    const { root, rel } = relativeToRoot(item.artifact, evidence)
    return root ? rel : shortPath(item.artifact, 64)
  }
  if (item.artifact_kind === 'dump') return shortPath(item.artifact, 64)
  return item.artifact
}

export function Dashboard({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const { data } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 30000,
  })
  if (!data) return <div className="py-16 text-center text-[var(--muted)] animate-pulse-soft">{tr('dashboard.loading')}</div>

  const confirmed = data.triage.confirmed ?? 0
  const high = data.confirmed_severity['0'] ?? 0
  const medium = data.confirmed_severity['1'] ?? 0
  const low = data.confirmed_severity['2'] ?? 0
  const info = data.confirmed_severity['3'] ?? 0
  const chronology = data.chronology
  const sources = [...new Set(data.evidence.map((item) => item.kind))]
  const zone = chronology.tz_mixed
    ? chronology.tz_offsets.join(', ')
    : chronology.zone

  if (!data.evidence.length) {
    return (
      <EmptyState
        icon={<HardDrive size={36} />}
        title={tr('dashboard.empty.title')}
        sub={tr('dashboard.empty.sub')}
        action={
          <button onClick={() => gotoView('evidence')}
            className="inline-flex cursor-pointer items-center gap-1 rounded-lg bg-[var(--accent)] px-3 py-2 text-[13px] font-semibold text-white">
            {tr('dashboard.toEvidence')} <ArrowRight size={14} />
          </button>
        }
      />
    )
  }

  return (
    <div className="flex flex-col gap-7">
      <Section title={tr('dashboard.forensic.title')} sub={tr('dashboard.forensic.sub')}>
        <Card className="overflow-hidden px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] pb-4">
            <div className="flex flex-wrap items-center gap-2">
              <ShieldCheck size={17} className="text-[var(--accent)]" />
              <span className="text-[12px] font-semibold">{tr('dashboard.forensic.context')}</span>
              {data.cms_installs.map((install) => (
                <button key={install.id} type="button" onClick={() => gotoView('cms')}
                  className="cursor-pointer">
                  <Tag tone="accent">{install.cms} {install.version}</Tag>
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="mr-1 text-[11px] text-[var(--muted)]">{tr('dashboard.forensic.sources')}</span>
              {sources.map((kind) => (
                <Tag key={kind}>{tr(`evidence.${kind}`)}</Tag>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 pt-2 md:grid-cols-4">
            <Metric label={tr('dashboard.forensic.confirmed')}
              value={formatCount(confirmed)} sub={tr('dashboard.forensic.confirmed.sub')}
              icon={<ShieldCheck size={14} />} tone="var(--sev-high)"
              onClick={() => gotoView('findings', { triage: 'confirmed' })} />
            <Metric label={tr('dashboard.forensic.observations')}
              value={formatCount(chronology.total_events)}
              sub={formatSpan(chronology.event_span.first, chronology.event_span.last)}
              icon={<Activity size={14} />} onClick={() => gotoView('timeline')} />
            <Metric label={tr('dashboard.forensic.clients')}
              value={formatCount(data.logs?.alerted_clients ?? 0)}
              sub={tr('dashboard.forensic.clients.sub', { n: formatCount(data.logs?.clients ?? 0) })}
              icon={<Users size={14} />} onClick={() => gotoView('actors')} />
            <Metric label={tr('dashboard.forensic.iocs')}
              value={formatCount(data.iocs)} sub={tr('dashboard.forensic.iocs.sub')}
              icon={<Fingerprint size={14} />} onClick={() => gotoView('iocbox')} />
          </div>
        </Card>
      </Section>

      <div className="grid gap-4 lg:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.7fr)]">
        <Section title={tr('dashboard.incidentTime.title')} sub={tr('dashboard.incidentTime.sub')}>
          <Card className="px-4 py-3">
            <div className="mb-2 flex items-center justify-between gap-2 border-b border-[var(--line)] pb-2">
              <span className="inline-flex items-center gap-2 text-[12px] font-semibold">
                <CalendarClock size={14} className="text-[var(--accent)]" />
                {formatSpan(chronology.event_span.first, chronology.event_span.last)}
                <InfoDot wide
                  title={tr('dashboard.incidentTime.spanTooltip.title')}
                  body={tr('dashboard.incidentTime.spanTooltip.body')}
                  hint={tr('dashboard.incidentTime.spanTooltip.hint')} />
              </span>
              {zone && <span className="text-[10.5px] text-[var(--muted)]">{tr('time.zone', { zone })}</span>}
            </div>
            <TimeFact label={tr('dashboard.incidentTime.first')} at={chronology.event_span.first}
              explanation={{
                title: tr('dashboard.incidentTime.firstTooltip.title'),
                body: tr('dashboard.incidentTime.firstTooltip.body'),
                hint: tr('dashboard.incidentTime.firstTooltip.hint'),
              }} />
            <TimeFact label={tr('dashboard.incidentTime.firstSuccess')} at={chronology.first_success_at}
              explanation={{
                title: tr('dashboard.incidentTime.successTooltip.title'),
                body: tr('dashboard.incidentTime.successTooltip.body'),
                hint: tr('dashboard.incidentTime.successTooltip.hint'),
              }} />
            <TimeFact label={tr('dashboard.incidentTime.last')} at={chronology.event_span.last}
              explanation={{
                title: tr('dashboard.incidentTime.lastTooltip.title'),
                body: tr('dashboard.incidentTime.lastTooltip.body'),
                hint: tr('dashboard.incidentTime.lastTooltip.hint'),
              }} />
            <button onClick={() => gotoView('timeline')}
              className="mt-3 inline-flex cursor-pointer items-center gap-1 text-[12px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.timeline.open')} <ArrowRight size={13} />
            </button>
          </Card>
        </Section>

        <Section title={tr('dashboard.observations.title')} sub={tr('dashboard.observations.sub')}>
          <Card className="overflow-hidden">
            {chronology.observations.length ? chronology.observations.map((event) => (
              <button key={`${event.role}-${event.at}-${event.title}`} type="button"
                onClick={() => gotoView('timeline')}
                className="grid w-full cursor-pointer grid-cols-[116px_minmax(0,1fr)_auto] items-start gap-3 border-b border-[var(--line-soft)] px-4 py-2.5 text-left transition-colors last:border-0 hover:bg-[var(--panel-2)]">
                <span>
                  <span className="mono block text-[11px] tabular text-[var(--muted)]">
                    {formatLogTime(event.at, 0).slice(0, 16)}
                  </span>
                  <span className="mt-0.5 block text-[10px] font-medium uppercase tracking-wide text-[var(--accent-text)]">
                    {tr(OBSERVATION_ROLE[event.role])}
                  </span>
                </span>
                <span className="min-w-0">
                  <span className="block text-[12.5px] font-semibold">{event.title}</span>
                  {event.detail && (
                    <span className="mt-0.5 block truncate text-[11px] text-[var(--muted)]">{event.detail}</span>
                  )}
                </span>
                <span className="inline-flex items-center gap-1 rounded border border-[var(--line)] px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-[var(--muted)]">
                  {event.source === 'log' ? tr('dashboard.source.log') : tr('dashboard.source.dump')}
                  <ArrowRight size={10} />
                </span>
              </button>
            )) : (
              <div className="px-4 py-8 text-center text-[12px] text-[var(--muted)]">
                {tr('dashboard.observations.empty')}
              </div>
            )}
          </Card>
        </Section>
      </div>

      <Section title={tr('dashboard.entities.title')} sub={tr('dashboard.entities.sub')}>
        <div className="grid gap-4 lg:grid-cols-3">
          <Card className="flex flex-col px-4 py-3">
            <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold">
              <ShieldCheck size={14} className="text-[var(--sev-high)]" />
              {tr('dashboard.entities.artifacts')}
            </div>
            <div className="mb-3 flex h-1.5 overflow-hidden rounded-full bg-[var(--panel-2)]">
              {confirmed > 0 && <>
                <span style={{ width: `${high / confirmed * 100}%`, background: 'var(--sev-high)' }} />
                <span style={{ width: `${medium / confirmed * 100}%`, background: 'var(--sev-medium)' }} />
                <span style={{ width: `${low / confirmed * 100}%`, background: 'var(--sev-low)' }} />
                <span style={{ width: `${info / confirmed * 100}%`, background: 'var(--muted)' }} />
              </>}
            </div>
            <div className="mb-3 flex flex-wrap gap-x-3 gap-y-1 text-[10.5px] text-[var(--muted)]">
              <span><b className="text-[var(--sev-high)]">{formatCount(high)}</b> HIGH</span>
              <span><b className="text-[var(--sev-medium)]">{formatCount(medium)}</b> MEDIUM</span>
              <span><b className="text-[var(--sev-low)]">{formatCount(low)}</b> LOW</span>
              <span><b>{formatCount(info)}</b> INFO</span>
            </div>
            <div className="mb-2 flex flex-wrap gap-x-3 gap-y-1 border-b border-[var(--line-soft)] pb-2 text-[10.5px] text-[var(--muted)]">
              {KIND_ORDER.map((kind) => {
                const count = data.confirmed_kinds[kind] ?? 0
                return count > 0 && <span key={kind}>{formatCount(count)} {tr(`kind.${kind}.many`)}</span>
              })}
            </div>
            <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold text-[var(--muted)]">
              {tr('dashboard.entities.confirmedEntries')}
              <InfoDot wide
                title={tr('dashboard.entities.confirmedEntriesTooltip.title')}
                body={tr('dashboard.entities.confirmedEntriesTooltip.body')}
                hint={tr('dashboard.entities.confirmedEntriesTooltip.hint')} />
            </div>
            <div className="flex flex-1 flex-col">
              {data.confirmed_artifacts.map((item) => {
                const Icon = KIND_ICON[item.artifact_kind]
                return (
                  <button key={`${item.artifact_kind}-${item.artifact}`} type="button"
                    onClick={() => gotoView('findings', {
                      triage: 'confirmed', artifact: item.artifact,
                    })}
                    className="flex min-w-0 cursor-pointer items-center gap-2 rounded-md px-1 py-1.5 text-left hover:bg-[var(--panel-2)]">
                    <Icon size={13} className="shrink-0 text-[var(--muted)]" />
                    <Tooltip wide className="min-w-0 flex-1"
                      title={tr(`kind.${item.artifact_kind}.one`)}
                      body={<span className="mono break-all">{item.artifact}</span>}>
                      <span className="mono block min-w-0 truncate text-[11.5px] font-medium">
                        {artifactLabel(item, data.evidence)}
                      </span>
                    </Tooltip>
                    <span className="shrink-0 text-[9.5px] font-semibold"
                      style={{ color: SEVERITY_VAR[item.worst] }}>
                      {SEVERITY_LABEL[item.worst]}
                    </span>
                  </button>
                )
              })}
            </div>
            {confirmed > data.confirmed_artifacts.length && (
              <button type="button" onClick={() => gotoView('findings', { triage: 'confirmed' })}
                className="mt-2 inline-flex cursor-pointer items-center gap-1 text-[11.5px] font-semibold text-[var(--accent-text)] hover:underline">
                {tr('dashboard.entities.openConfirmed', { n: formatCount(confirmed) })}
                <ArrowRight size={12} />
              </button>
            )}
          </Card>

          <Card className="flex flex-col px-4 py-3">
            <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold">
              <Users size={14} className="text-[var(--accent)]" />
              {tr('dashboard.entities.actors')}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-lg bg-[var(--panel-2)] p-3">
                <div className="text-xl font-semibold tabular">{formatCount(data.confirmed_kinds.client ?? 0)}</div>
                <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">{tr('dashboard.entities.confirmedClients')}</div>
              </div>
              <div className="rounded-lg bg-[var(--panel-2)] p-3">
                <div className="text-xl font-semibold tabular">{formatCount(data.logs?.alerted_clients ?? 0)}</div>
                <div className="mt-0.5 text-[10.5px] text-[var(--muted)]">{tr('dashboard.entities.alertedClients')}</div>
              </div>
            </div>
            <div className="mt-3 flex flex-1 flex-col justify-end gap-1.5 text-[11.5px] text-[var(--muted)]">
              <div className="flex justify-between gap-2">
                <span>{tr('dashboard.entities.logPopulation')}</span>
                <b className="font-medium text-[var(--fg)] tabular">{formatCount(data.logs?.clients ?? 0)}</b>
              </div>
              <div className="flex justify-between gap-2">
                <span>{tr('dashboard.entities.requests')}</span>
                <b className="font-medium text-[var(--fg)] tabular">{formatCount(data.logs?.lines ?? 0)}</b>
              </div>
            </div>
            <button onClick={() => gotoView('actors')}
              className="mt-3 inline-flex cursor-pointer items-center gap-1 text-[12px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.entities.openActors')} <ArrowRight size={13} />
            </button>
          </Card>

          <Card className="flex flex-col px-4 py-3">
            <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold">
              <Database size={14} className="text-[var(--accent)]" />
              {tr('dashboard.entities.accountsIocs')}
            </div>
            <button type="button" onClick={() => gotoView('database')}
              className="grid cursor-pointer grid-cols-2 gap-2 text-left">
              <span className="rounded-lg bg-[var(--panel-2)] p-3 transition-colors hover:bg-[var(--accent-soft)]">
                <span className="block text-xl font-semibold tabular">{formatCount(data.accounts)}</span>
                <span className="mt-0.5 block text-[10.5px] text-[var(--muted)]">{tr('dashboard.entities.accounts')}</span>
              </span>
              <span className="rounded-lg bg-[var(--panel-2)] p-3 transition-colors hover:bg-[var(--accent-soft)]">
                <span className="block text-xl font-semibold tabular text-[var(--sev-high)]">{formatCount(data.admins)}</span>
                <span className="mt-0.5 block text-[10.5px] text-[var(--muted)]">{tr('dashboard.entities.admins')}</span>
              </span>
            </button>
            <button type="button" onClick={() => gotoView('iocbox')}
              className="mt-3 flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-[var(--line)] px-3 py-2.5 text-left transition-colors hover:border-[var(--accent)]/60">
              <span className="inline-flex items-center gap-2 text-[11.5px] text-[var(--muted)]">
                <Fingerprint size={13} /> {tr('dashboard.entities.indicators')}
              </span>
              <span className="text-[15px] font-semibold tabular">{formatCount(data.iocs)}</span>
            </button>
            <p className="mt-3 text-[10.5px] leading-snug text-[var(--muted)]">
              {tr('dashboard.entities.accountsNote')}
            </p>
          </Card>
        </div>
      </Section>

      {data.logs && (
        <Section title={tr('dashboard.evidence.title')}
          sub={tr('dashboard.evidence.sub', {
            lines: formatCount(data.logs.lines),
            clients: formatCount(data.logs.clients),
            from: formatDay(data.logs.first_epoch),
            to: formatDay(data.logs.last_epoch),
          }) + (data.logs.unparsed
            ? ` · ${tr('dashboard.logCoverage.unparsed', { n: formatCount(data.logs.unparsed) })}`
            : '')}
          right={
            <button onClick={() => gotoView('timeline')}
              className="inline-flex cursor-pointer items-center gap-1 text-[12px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.timeline.open')} <ArrowRight size={13} />
            </button>
          }>
          <Card className="p-4"><TimelineChart data={data.timeline} height={170} /></Card>
        </Section>
      )}

      <LogCoverage slug={slug} />

      {(chronology.gaps.length > 0 || chronology.undated > 0) && (
        <Card className="px-4 py-3">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold">
            <Radar size={14} className="text-[var(--muted)]" />
            {tr('dashboard.limitations.title')}
          </div>
          <div className="flex flex-col gap-1.5">
            {chronology.gaps.map((gap) => (
              <div key={gap} className="flex items-start gap-2 text-[11.5px] leading-snug text-[var(--muted)]">
                <AlertTriangle size={12} className="mt-0.5 shrink-0 text-[var(--sev-low)]" />
                <span>{gap}</span>
              </div>
            ))}
            {chronology.undated > 0 && (
              <div className="flex items-start gap-2 text-[11.5px] leading-snug text-[var(--muted)]">
                <Database size={12} className="mt-0.5 shrink-0" />
                <span>{tr('dashboard.limitations.undated', { n: formatCount(chronology.undated) })}</span>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  )
}
