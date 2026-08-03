// TraceDrawer.tsx — was ein Client (oder eine Handvoll davon) getan hat:
// jeder Request aus dem Log-Index, älteste zuerst.
//
// Der Trace ist eine ABFRAGE gegen den Index, kein Log-Durchlauf — deshalb
// darf er überall aufgehen, wo eine IP-Adresse steht: in der Actors-Liste,
// im Artefakt-Detail, neben einem Hunt-Treffer. `layer` entscheidet, auf
// welcher Ebene er liegt, wenn er AUS einem anderen Drawer geöffnet wird.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Crosshair, Download } from 'lucide-react'
import { downloadUrl, post, type TraceRow } from '../api'
import { formatCount, formatLogTime } from '../format'
import { Button, Drawer } from './ui'

const CLIENT_COLORS = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#9085e9']

export function TraceDrawer({ slug, ips, onClose, layer = 0 }: {
  slug: string
  ips: string[] | null
  onClose: () => void
  layer?: number
}) {
  const [page, setPage] = useState(0)
  const pageSize = 500
  const { data, isFetching } = useQuery({
    queryKey: ['trace', slug, ips, page],
    queryFn: () => post<{ total: number; rows: TraceRow[] }>(
      `/api/cases/${slug}/trace`,
      { ips, limit: pageSize, offset: page * pageSize }),
    enabled: !!ips?.length,
  })

  const colorByClient = useMemo(() => {
    const map = new Map<string, string>()
    ips?.forEach((ip, i) => map.set(ip, CLIENT_COLORS[i % CLIENT_COLORS.length]))
    return map
  }, [ips])

  if (!ips) return null
  return (
    <Drawer open onClose={onClose} wide layer={layer}
      title={<span className="flex items-center gap-2">
        <Crosshair size={16} className="text-[var(--accent)]" />
        Trace: {ips.length === 1 ? ips[0] : `${ips.length} Clients`}
        {data && <span className="text-[12px] font-normal text-[var(--muted)]">
          {formatCount(data.total)} Requests {isFetching && '· lädt…'}
        </span>}
      </span>}>
      <div className="mb-3 flex items-center gap-2">
        <a
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
          href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${ips.join(',')}`)}
        >
          <Download size={14} /> Vollständigen Trace als CSV
        </a>
        {data && data.total > pageSize && (
          <div className="ml-auto flex items-center gap-2 text-[12px] text-[var(--muted)]">
            <Button variant="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>←</Button>
            Seite {page + 1} / {Math.ceil(data.total / pageSize)}
            <Button variant="ghost" disabled={(page + 1) * pageSize >= data.total}
              onClick={() => setPage(page + 1)}>→</Button>
          </div>
        )}
      </div>
      <div className="overflow-x-auto rounded-lg border border-[var(--line)]">
        <table className="w-full border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-[var(--line)] text-left text-[10px] uppercase tracking-wider text-[var(--muted)]">
              {ips.length > 1 && <th className="px-2 py-1.5">Client</th>}
              <th className="px-2 py-1.5">Zeit</th>
              <th className="px-2 py-1.5">Methode</th>
              <th className="px-2 py-1.5">URI</th>
              <th className="px-2 py-1.5 text-right">Status</th>
              <th className="px-2 py-1.5">User-Agent</th>
            </tr>
          </thead>
          <tbody className="mono">
            {data?.rows.map((r, i) => (
              <tr key={i} className="border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
                {ips.length > 1 && (
                  <td className="whitespace-nowrap px-2 py-1">
                    <span className="mr-1.5 inline-block h-2 w-2 rounded-full"
                      style={{ background: colorByClient.get(r.client) }} />
                    {r.client}
                  </td>
                )}
                <td className="whitespace-nowrap px-2 py-1 text-[var(--muted)]">
                  {formatLogTime(r.epoch, r.tz)}
                </td>
                <td className="px-2 py-1">{r.method}</td>
                <td className="max-w-[420px] truncate px-2 py-1" title={r.uri}>{r.uri}</td>
                <td className={clsx('px-2 py-1 text-right tabular',
                  r.status >= 500 ? 'text-[var(--sev-high)]'
                    : r.status >= 400 ? 'text-[var(--sev-medium)]'
                      : r.status >= 300 ? 'text-[var(--sev-low)]' : 'text-[var(--ok)]')}>
                  {r.status}
                </td>
                <td className="max-w-[220px] truncate px-2 py-1 text-[var(--muted)]" title={r.agent}>
                  {r.agent}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && !data.rows.length && (
          <div className="px-4 py-8 text-center text-[13px] text-[var(--muted)]">
            Keine Requests im Index für diese Auswahl.
          </div>
        )}
      </div>
    </Drawer>
  )
}
