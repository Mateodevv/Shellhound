// GeoHint.tsx — der Weg zu den Länderflaggen, wenn die Datenbank fehlt.
//
// Ohne GeoIP-Datenbank gibt es keine Flaggen, und ohne Erklärung fragt
// sich jeder, warum. Diese Karte sagt es — und bietet den einzigen
// Auslands-Kontakt des ganzen Werkzeugs an: EIN Klick lädt die frei
// lizenzierte DB-IP Country Lite (CC BY 4.0) in den Workspace. Es gehen
// keine Falldaten hinaus; der Request ist ein Datei-Download von
// download.db-ip.com, und der Knopf sagt das dazu.
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Globe } from 'lucide-react'
import { post } from '../api'
import { formatBytes } from '../format'
import { clearGeoCache } from '../geo'
import { Button } from './ui'
import { Tooltip } from './Tooltip'

interface GeoStatus {
  available: boolean
  source: string
  why: string
}

export function GeoHint() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['geo-status'],
    queryFn: () => post<GeoStatus>('/api/geo', { ips: [] }),
    staleTime: 60_000,
  })
  const download = useMutation({
    mutationFn: () => post<{ source: string; size: number; month: string }>(
      '/api/geo/download', {}),
    onSuccess: () => {
      clearGeoCache()
      qc.invalidateQueries({ queryKey: ['geo-status'] })
    },
  })

  if (!data || data.available) return null

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] text-[var(--muted)] animate-fade-up">
      <Globe size={13} className="shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="font-medium text-[var(--fg)]">Keine Länderflaggen:</span>{' '}
        {data.why} Die Zuordnung läuft danach vollständig offline.
      </span>
      <Tooltip title="DB-IP Country Lite laden"
        body="Lädt die frei lizenzierte Länder-Datenbank (CC BY 4.0, ~10 MB) von download.db-ip.com in den Workspace — der einzige Netz-Kontakt dieses Werkzeugs, nur auf diesen Klick."
        hint="Es gehen keine Falldaten hinaus: der Request ist ein einzelner Datei-Download. Alternativ eine GeoLite2-Country.mmdb von MaxMind von Hand in den Workspace legen.">
        <Button variant="primary" disabled={download.isPending}
          onClick={() => download.mutate()}>
          <Download size={13} />
          {download.isPending ? 'lädt…' : 'Länder-Datenbank laden'}
        </Button>
      </Tooltip>
      {download.isSuccess && (
        <span className="text-[var(--ok)]">
          {download.data.source} ({formatBytes(download.data.size)}, Stand {download.data.month})
        </span>
      )}
      {download.isError && (
        <span className="text-[var(--danger-text)]">
          {String((download.error as Error)?.message ?? download.error)}
        </span>
      )}
    </div>
  )
}
