// Dashboard.tsx — a forensic case briefing, not a second navigation page.
//
// The reading order is deliberate: conclusion, evidenced chronology,
// confirmed scope, observed context, and finally the basis and limits of the
// evidence. Only confirmed artifacts are allowed into the compromise scope.
import { useT } from '../i18n'
import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import {
  AlertTriangle, ArrowRight, Database, Fingerprint, HardDrive, Radar,
  ShieldCheck, Users,
} from 'lucide-react'
import { api, type Dashboard as DashboardData } from '../api'
import {
  formatCount, formatDay, formatLogTime, formatSpan, relativeToRoot,
  SEVERITY_LABEL, SEVERITY_VAR, shortPath,
} from '../format'
import { KIND_ICON } from '../artifactKinds'
import { Card, EmptyState, Section, Tag } from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
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

function TimeFact({ label, at, explanation }: {
  label: string
  at?: number | null
  explanation: { title: string; body: string; hint?: string }
}) {
  return (
    <div className="min-w-0 border-t border-[var(--line-soft)] py-3 first:border-t-0 first:pt-0 last:pb-0 sm:border-l sm:border-t-0 sm:px-4 sm:py-0 sm:first:border-l-0 sm:first:pl-0 sm:last:pr-0">
      <span className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-wide text-[var(--muted)]">
        {label}
        <InfoDot {...explanation} wide />
      </span>
      <span className="mono mt-1.5 block truncate text-[12px] tabular">
        {at ? formatLogTime(at, 0).slice(0, 16) : '—'}
      </span>
    </div>
  )
}

function ContextFact({ icon, label, value, sub, onClick }: {
  icon: ReactNode
  label: string
  value: string
  sub: string
  onClick: () => void
}) {
  return (
    <button type="button" onClick={onClick}
      className="group grid min-w-0 cursor-pointer grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-[var(--line-soft)] px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-[var(--panel-2)] lg:border-b-0 lg:border-r lg:last:border-r-0">
      <span className="rounded-lg bg-[var(--panel-2)] p-2 text-[var(--muted)] group-hover:text-[var(--accent-text)]">
        {icon}
      </span>
      <span className="min-w-0">
        <span className="block text-[12.5px] font-semibold">{label}</span>
        <span className="mt-0.5 block truncate text-[10.5px] text-[var(--muted)]">{sub}</span>
      </span>
      <span className="flex items-center gap-1 text-lg font-semibold tabular">
        {value}<ArrowRight size={12} className="text-[var(--muted)]" />
      </span>
    </button>
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
  const zone = chronology.tz_mixed ? chronology.tz_offsets.join(', ') : chronology.zone

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
      <Section title={tr('dashboard.brief.title')} sub={tr('dashboard.brief.sub')}>
        <Card className="overflow-hidden border-[var(--line)]">
          <div className="flex flex-wrap items-start justify-between gap-4 px-5 py-5">
            <div className="flex min-w-0 gap-3">
              <span className="mt-0.5 rounded-lg bg-[var(--accent-soft)] p-2 text-[var(--sev-high)]">
                <ShieldCheck size={19} />
              </span>
              <div className="min-w-0">
                <span className="text-[10.5px] font-semibold uppercase tracking-widest text-[var(--muted)]">
                  {tr('dashboard.brief.verdict')}
                </span>
                <h3 className="mt-1 text-lg font-semibold"
                  style={confirmed > 0 ? { color: 'var(--sev-high)' } : undefined}>
                  {confirmed > 0 ? tr('dashboard.brief.confirmed') : tr('dashboard.brief.unconfirmed')}
                </h3>
                <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-[var(--muted)]">
                  {confirmed > 0
                    ? tr('dashboard.brief.confirmed.sub', {
                        n: formatCount(confirmed),
                        span: formatSpan(chronology.event_span.first, chronology.event_span.last),
                      })
                    : tr('dashboard.brief.unconfirmed.sub')}
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-1.5">
              {data.cms_installs.map((install) => (
                <button key={install.id} type="button" onClick={() => gotoView('cms')} className="cursor-pointer">
                  <Tag tone="accent">{install.cms} {install.version}</Tag>
                </button>
              ))}
              {sources.map((kind) => <Tag key={kind}>{tr(`evidence.${kind}`)}</Tag>)}
            </div>
          </div>

          <div className="grid gap-y-4 border-t border-[var(--line)] bg-[var(--panel-2)]/40 px-5 py-4 sm:grid-cols-3">
            <TimeFact label={tr('dashboard.brief.first')} at={chronology.event_span.first}
              explanation={{
                title: tr('dashboard.incidentTime.firstTooltip.title'),
                body: tr('dashboard.incidentTime.firstTooltip.body'),
                hint: tr('dashboard.incidentTime.firstTooltip.hint'),
              }} />
            <TimeFact label={tr('dashboard.brief.first2xx')} at={chronology.first_success_at}
              explanation={{
                title: tr('dashboard.brief.first2xxTooltip.title'),
                body: tr('dashboard.incidentTime.successTooltip.body'),
                hint: tr('dashboard.brief.first2xxTooltip.hint'),
              }} />
            <TimeFact label={tr('dashboard.brief.last')} at={chronology.event_span.last}
              explanation={{
                title: tr('dashboard.incidentTime.lastTooltip.title'),
                body: tr('dashboard.incidentTime.lastTooltip.body'),
                hint: tr('dashboard.incidentTime.lastTooltip.hint'),
              }} />
          </div>
        </Card>
      </Section>

      <div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(300px,0.9fr)]">
        <Section title={tr('dashboard.brief.incident')} sub={tr('dashboard.brief.incident.sub')}
          right={
            <button onClick={() => gotoView('timeline')}
              className="inline-flex cursor-pointer items-center gap-1 text-[11.5px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.brief.openTimeline')} <ArrowRight size={12} />
            </button>
          }>
          <Card className="overflow-hidden">
            {chronology.observations.length ? chronology.observations.map((event, index) => (
              <button key={`${event.role}-${event.at}-${event.title}`} type="button"
                onClick={() => gotoView('timeline')}
                className="group grid w-full cursor-pointer grid-cols-[28px_108px_minmax(0,1fr)] items-start gap-3 border-b border-[var(--line-soft)] px-4 py-3 text-left transition-colors last:border-0 hover:bg-[var(--panel-2)]">
                <span className="relative flex h-6 w-6 items-center justify-center rounded-full border border-[var(--line)] bg-[var(--panel-2)] text-[10px] font-semibold text-[var(--muted)]">
                  {index + 1}
                </span>
                <span>
                  <span className="mono block text-[10.5px] tabular text-[var(--muted)]">
                    {formatLogTime(event.at, 0).slice(0, 16)}
                  </span>
                  <span className="mt-0.5 block text-[9.5px] font-medium uppercase tracking-wide text-[var(--accent-text)]">
                    {tr(OBSERVATION_ROLE[event.role])}
                  </span>
                </span>
                <span className="min-w-0">
                  <span className="flex items-start justify-between gap-2">
                    <span className="block text-[12.5px] font-semibold">{event.title}</span>
                    <span className="shrink-0 rounded border border-[var(--line)] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-[var(--muted)]">
                      {event.source === 'log'
                        ? tr('dashboard.source.log')
                        : event.source === 'filesystem'
                          ? tr('dashboard.source.filesystem')
                          : tr('dashboard.source.dump')}
                    </span>
                  </span>
                  {event.detail && <span className="mt-0.5 block truncate text-[10.5px] text-[var(--muted)]">{event.detail}</span>}
                </span>
              </button>
            )) : (
              <div className="px-4 py-8 text-center text-[12px] text-[var(--muted)]">
                {tr('dashboard.observations.empty')}
              </div>
            )}
          </Card>
        </Section>

        <Section title={tr('dashboard.brief.scope')} sub={tr('dashboard.brief.scope.sub')}>
          <Card className="flex flex-col px-4 py-3">
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="inline-flex items-center gap-2 text-[12.5px] font-semibold">
                <ShieldCheck size={14} className="text-[var(--sev-high)]" />
                {tr('dashboard.entities.artifacts')}
                <InfoDot wide
                  title={tr('dashboard.entities.confirmedEntriesTooltip.title')}
                  body={tr('dashboard.entities.confirmedEntriesTooltip.body')}
                  hint={tr('dashboard.entities.confirmedEntriesTooltip.hint')} />
              </span>
              <span className="text-xl font-semibold tabular text-[var(--sev-high)]">{formatCount(confirmed)}</span>
            </div>
            <div className="mb-2 flex h-1.5 overflow-hidden rounded-full bg-[var(--panel-2)]">
              {confirmed > 0 && <>
                <span style={{ width: `${high / confirmed * 100}%`, background: 'var(--sev-high)' }} />
                <span style={{ width: `${medium / confirmed * 100}%`, background: 'var(--sev-medium)' }} />
                <span style={{ width: `${low / confirmed * 100}%`, background: 'var(--sev-low)' }} />
                <span style={{ width: `${info / confirmed * 100}%`, background: 'var(--muted)' }} />
              </>}
            </div>
            <div className="mb-3 flex flex-wrap gap-x-3 gap-y-1 text-[9.5px] text-[var(--muted)]">
              <span><b className="text-[var(--sev-high)]">{formatCount(high)}</b> HIGH</span>
              <span><b className="text-[var(--sev-medium)]">{formatCount(medium)}</b> MEDIUM</span>
              <span><b className="text-[var(--sev-low)]">{formatCount(low)}</b> LOW</span>
              <span><b>{formatCount(info)}</b> INFO</span>
            </div>
            <div className="mb-2 flex flex-wrap gap-1.5 border-y border-[var(--line-soft)] py-2">
              {KIND_ORDER.map((kind) => {
                const count = data.confirmed_kinds[kind] ?? 0
                return count > 0 && <Tag key={kind}>{formatCount(count)} {tr(`kind.${kind}.many`)}</Tag>
              })}
            </div>
            <div className="flex flex-col">
              {data.confirmed_artifacts.slice(0, 4).map((item) => {
                const Icon = KIND_ICON[item.artifact_kind]
                return (
                  <button key={`${item.artifact_kind}-${item.artifact}`} type="button"
                    onClick={() => gotoView('findings', { triage: 'confirmed', artifact: item.artifact })}
                    className="flex min-w-0 cursor-pointer items-center gap-2 rounded-md px-1 py-1.5 text-left hover:bg-[var(--panel-2)]">
                    <Icon size={13} className="shrink-0 text-[var(--muted)]" />
                    <Tooltip wide className="min-w-0 flex-1"
                      title={tr(`kind.${item.artifact_kind}.one`)}
                      body={<span className="mono break-all">{item.artifact}</span>}>
                      <span className="mono block min-w-0 truncate text-[11px] font-medium">
                        {artifactLabel(item, data.evidence)}
                      </span>
                    </Tooltip>
                    <span className="shrink-0 text-[9px] font-semibold" style={{ color: SEVERITY_VAR[item.worst] }}>
                      {SEVERITY_LABEL[item.worst]}
                    </span>
                  </button>
                )
              })}
            </div>
            <button type="button" onClick={() => gotoView('findings', { triage: 'confirmed' })}
              className="mt-2 inline-flex cursor-pointer items-center gap-1 self-start text-[11.5px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.brief.openFindings', { n: formatCount(confirmed) })} <ArrowRight size={12} />
            </button>
          </Card>
        </Section>
      </div>

      <Section title={tr('dashboard.brief.context')} sub={tr('dashboard.brief.context.sub')}>
        <Card className="grid overflow-hidden lg:grid-cols-3">
          <ContextFact icon={<Users size={15} />} label={tr('dashboard.brief.context.clients')}
            value={formatCount(data.logs?.alerted_clients ?? 0)}
            sub={tr('dashboard.brief.context.clients.sub', { n: formatCount(data.logs?.clients ?? 0) })}
            onClick={() => gotoView('actors')} />
          <ContextFact icon={<Database size={15} />} label={tr('dashboard.brief.context.accounts')}
            value={formatCount(data.accounts)}
            sub={tr('dashboard.brief.context.accounts.sub', { n: formatCount(data.admins) })}
            onClick={() => gotoView('database')} />
          <ContextFact icon={<Fingerprint size={15} />} label={tr('dashboard.brief.context.iocs')}
            value={formatCount(data.iocs)} sub={tr('dashboard.brief.context.iocs.sub')}
            onClick={() => gotoView('iocbox')} />
        </Card>
      </Section>

      <div className="grid items-start gap-5 lg:grid-cols-2">
        <Section title={tr('dashboard.brief.evidence')} sub={tr('dashboard.brief.evidence.sub')}>
          <Card className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--line-soft)] pb-3">
              <span className="mr-1 text-[10.5px] font-medium text-[var(--muted)]">{tr('dashboard.brief.sources')}</span>
              {sources.map((kind) => <Tag key={kind}>{tr(`evidence.${kind}`)}</Tag>)}
            </div>
            {data.logs ? (
              <div className="grid grid-cols-2 gap-x-4 gap-y-3 py-3 sm:grid-cols-3">
                <div>
                  <span className="block text-base font-semibold tabular">{formatCount(data.logs.lines)}</span>
                  <span className="text-[10.5px] text-[var(--muted)]">{tr('dashboard.brief.requests')}</span>
                </div>
                <div>
                  <span className="block text-base font-semibold tabular">{formatCount(data.logs.clients)}</span>
                  <span className="text-[10.5px] text-[var(--muted)]">{tr('dashboard.brief.logClients')}</span>
                </div>
                <div>
                  <span className="mono block text-[11.5px] font-semibold tabular">
                    {formatDay(data.logs.first_epoch)} → {formatDay(data.logs.last_epoch)}
                  </span>
                  <span className="text-[10.5px] text-[var(--muted)]">{tr('dashboard.brief.logPeriod')}</span>
                </div>
              </div>
            ) : <p className="py-3 text-[11.5px] text-[var(--muted)]">{tr('dashboard.brief.noLogs')}</p>}
            {data.logs?.unparsed ? (
              <p className="border-t border-[var(--line-soft)] pt-2 text-[10.5px] text-[var(--muted)]">
                {tr('dashboard.logCoverage.unparsed', { n: formatCount(data.logs.unparsed) })}
              </p>
            ) : null}
            <button onClick={() => gotoView('timeline')}
              className="mt-2 inline-flex cursor-pointer items-center gap-1 text-[11.5px] font-semibold text-[var(--accent-text)] hover:underline">
              {tr('dashboard.brief.openTimeline')} <ArrowRight size={12} />
            </button>
          </Card>
        </Section>

        <Section title={tr('dashboard.brief.limits')} sub={tr('dashboard.brief.limits.sub')}>
          <Card className="flex flex-col gap-2.5 px-4 py-3">
            <div className="flex items-start gap-2 text-[11.5px] leading-relaxed text-[var(--muted)]">
              <AlertTriangle size={13} className="mt-0.5 shrink-0 text-[var(--sev-low)]" />
              <span>{tr('dashboard.brief.limit2xx')}</span>
            </div>
            {chronology.gaps.map((gap) => (
              <div key={gap} className="flex items-start gap-2 text-[11.5px] leading-relaxed text-[var(--muted)]">
                <Radar size={13} className="mt-0.5 shrink-0" /><span>{gap}</span>
              </div>
            ))}
            {chronology.undated > 0 && (
              <div className="flex items-start gap-2 text-[11.5px] leading-relaxed text-[var(--muted)]">
                <Database size={13} className="mt-0.5 shrink-0" />
                <span>{tr('dashboard.brief.limitUndated', { n: formatCount(chronology.undated) })}</span>
              </div>
            )}
            {chronology.gaps.length === 0 && chronology.undated === 0 && (
              <div className="flex items-start gap-2 text-[11.5px] leading-relaxed text-[var(--muted)]">
                <Radar size={13} className="mt-0.5 shrink-0" /><span>{tr('dashboard.brief.limitNone')}</span>
              </div>
            )}
            {zone && <span className="border-t border-[var(--line-soft)] pt-2 text-[10px] text-[var(--muted)]">{tr('time.zone', { zone })}</span>}
          </Card>
        </Section>
      </div>

      <LogCoverage slug={slug} />
    </div>
  )
}
