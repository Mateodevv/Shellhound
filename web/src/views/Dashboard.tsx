// Dashboard.tsx — the case at a glance: severity tiles, coverage chart,
// live jobs, evidence status.
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Server } from 'lucide-react'
import { api, type Dashboard as DashboardData } from '../api'
import { formatCount, formatDay } from '../format'
import { Card, ProgressBar, Section, StatTile, Tag } from '../components/ui'
import { TimelineChart } from '../components/TimelineChart'
import type { ViewId } from '../App'

export function Dashboard({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const { data } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  if (!data) return <div className="py-16 text-center text-[var(--muted)] animate-pulse-soft">Lade Dashboard…</div>

  const sev = data.severity
  const triage = data.triage
  const noEvidence = !data.evidence.length

  return (
    <div className="flex flex-col gap-6">
      {noEvidence && (
        <Card className="flex items-center justify-between gap-3 border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-3 animate-fade-up">
          <div className="text-[13px]">
            <span className="font-semibold">Dieser Case ist leer.</span>{' '}
            Registriere Evidence (Webroot, Access-Logs, SQL-Dump) und starte die Analyse.
          </div>
          <button
            onClick={() => gotoView('evidence')}
            className="inline-flex shrink-0 items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline cursor-pointer"
          >
            Zu Evidence <ArrowRight size={14} />
          </button>
        </Card>
      )}

      {data.jobs_running.length > 0 && (
        <Card className="px-4 py-3 animate-fade-up">
          <div className="mb-2 text-[13px] font-semibold">Laufende Analyse</div>
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

      <Section title="Artefakte"
        sub={`Gezählt wird, worüber entschieden wird: Dateien, Clients, Tabellen — nach ihrem schwersten Fund, ohne False Positives. Aus ${formatCount(data.findings_total)} Findings. Klick auf eine Kachel öffnet die gefilterte Liste.`}>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
          <StatTile label="High" value={formatCount(sev['0'] ?? 0)}
            info="Kaum harmlos erklärbar — zuerst ansehen."
            sub="Artefakte" tone="var(--sev-high)" onClick={() => gotoView('findings')} />
          <StatTile label="Medium" value={formatCount(sev['1'] ?? 0)}
            info="Auffällig, kann aber legitim sein — braucht Kontext."
            sub="Artefakte" tone="var(--sev-medium)" onClick={() => gotoView('findings')} />
          <StatTile label="Low" value={formatCount(sev['2'] ?? 0)}
            info="Schwaches Signal, meist nur im Zusammenhang interessant."
            sub="Artefakte" tone="var(--sev-low)" onClick={() => gotoView('findings')} />
          <StatTile label="True Positive" value={formatCount(triage['confirmed'] ?? 0)}
            info="Artefakte, die du als real und Teil des Vorfalls entschieden hast."
            sub="Teil des Vorfalls" onClick={() => gotoView('findings')} />
          <StatTile label="IOCs" value={formatCount(data.iocs)}
            info="Indikatoren in der IOC Box — Adressen, Hashes, Pfade, Domains."
            sub="in der IOC Box" onClick={() => gotoView('iocbox')} />
          <StatTile label="Admin-Accounts" value={formatCount(data.admins)}
            info="Konten mit vollen Rechten im Datenbank-Export (Administrator / Super User)."
            sub={`von ${formatCount(data.accounts)} Accounts`}
            onClick={() => gotoView('database')} />
        </div>
      </Section>

      {data.logs && (
        <Section
          title="Log-Abdeckung"
          sub={`${formatCount(data.logs.lines)} indizierte Requests von ${formatCount(data.logs.clients)} Clients — ${formatDay(data.logs.first_epoch)} bis ${formatDay(data.logs.last_epoch)}${data.logs.unparsed ? ` · ${formatCount(data.logs.unparsed)} Zeilen nicht parsebar` : ''}`}
          right={
            <button onClick={() => gotoView('actors')}
              className="inline-flex items-center gap-1 text-[13px] font-medium text-[var(--accent-text)] hover:underline cursor-pointer">
              {formatCount(data.logs.alerted_clients)} auffällige Clients <ArrowRight size={14} />
            </button>
          }
        >
          <Card className="p-4">
            <TimelineChart data={data.timeline} />
          </Card>
        </Section>
      )}

      {data.cms_installs.length > 0 && (
        <Section title="Installationen" sub="Erkannte CMS-Instanzen im Webroot.">
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
                  <Tag tone="accent">Inventar</Tag>
                </button>
              </Card>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}
