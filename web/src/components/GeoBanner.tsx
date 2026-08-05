// GeoBanner.tsx — der Weg zu den Länderflaggen, wenn die Datenbank fehlt.
//
// Ein Banner wie das für fehlende Evidence: gut sichtbar im Dashboard,
// verschwindet von selbst, sobald es erledigt ist. Der Download selbst
// startet NICHT auf den ersten Klick — vorher sagt ein Fenster, was gleich
// passiert. Das ist der einzige Netz-Kontakt des ganzen Werkzeugs, und
// genau deshalb darf er nicht nebenbei geschehen: wer auf einer
// abgeschotteten Forensik-Maschine arbeitet, muss NEIN sagen können, bevor
// irgendetwas den Rechner verlässt.
//
// »Nicht mehr zeigen« bleibt gemerkt (localStorage): wer bewusst ohne
// GeoIP arbeitet, soll nicht in jedem Fall aufs Neue vertröstet werden.
import { useT } from '../i18n'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Globe, X } from 'lucide-react'
import { post } from '../api'
import { formatBytes } from '../format'
import { clearGeoCache } from '../geo'
import { Button, Card, Modal } from './ui'

interface GeoStatus {
  available: boolean
  source: string
  why: string
}

const HIDE_KEY = 'shellhound.geoBannerHidden'

export function GeoBanner() {
  const tr = useT()
  const qc = useQueryClient()
  const [hidden, setHidden] = useState(() => localStorage.getItem(HIDE_KEY) === '1')
  const [confirming, setConfirming] = useState(false)

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
      setConfirming(false)
      qc.invalidateQueries({ queryKey: ['geo-status'] })
    },
  })

  if (!data || data.available || hidden) return null

  return (
    <>
      <Card className="flex items-center justify-between gap-3 border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-3 animate-fade-up">
        <div className="flex min-w-0 items-center gap-2.5 text-[13px]">
          <Globe size={15} className="shrink-0 text-[var(--accent)]" />
          <span className="min-w-0">
            <span className="font-semibold">{tr('geo.missing.title')}</span>{' '}
            IP-Adressen erscheinen ohne Länderflaggen — eine lokale
            GeoIP-Datenbank lässt sich einmalig laden, danach läuft die
            Zuordnung vollständig offline.
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            onClick={() => setConfirming(true)}
            className="inline-flex items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline cursor-pointer"
          >
            <Download size={14} /> Datenbank laden…
          </button>
          <button
            onClick={() => { localStorage.setItem(HIDE_KEY, '1'); setHidden(true) }}
            title={tr('geo.dismiss.hint')}
            className="cursor-pointer rounded p-1 text-[var(--muted)] transition-colors hover:text-[var(--fg)]"
          >
            <X size={14} />
          </button>
        </div>
      </Card>

      {/* Erst sagen, was passiert — DANN passiert es. */}
      <Modal open={confirming} onClose={() => setConfirming(false)}
        title={<span className="flex items-center gap-2">
          <Globe size={16} className="text-[var(--accent)]" />
          Länder-Datenbank laden?
        </span>}>
        <div className="flex max-w-xl flex-col gap-3 text-[13px]">
          <p>
            SHELLHOUND lädt jetzt <span className="font-semibold">eine Datei</span> von{' '}
            <span className="mono">download.db-ip.com</span>: die frei
            lizenzierte <span className="font-semibold">DB-IP Country Lite</span>{' '}
            (CC BY 4.0, ~8 MB, kein Konto nötig). Sie wird im Workspace
            gespeichert — danach läuft jede Zuordnung vollständig offline.
          </p>
          <p className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12.5px] text-[var(--muted)]">
            Das ist der <span className="font-medium text-[var(--fg)]">einzige
            Netz-Kontakt</span> dieses Werkzeugs, und er passiert nur auf diesen
            Klick. Es gehen <span className="font-medium text-[var(--fg)]">keine
            Falldaten</span> hinaus — der Request enthält nichts als den
            Dateinamen. Auf einer Maschine ohne Internet-Freigabe stattdessen:
            eine <span className="mono">*.mmdb</span> (DB-IP Lite oder
            GeoLite2-Country) von Hand in den Workspace legen.
          </p>
          {download.isError && (
            <p className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[12.5px] text-[var(--danger-text)]">
              {String((download.error as Error)?.message ?? download.error)}
            </p>
          )}
          <div className="flex items-center gap-2">
            <Button variant="primary" disabled={download.isPending}
              onClick={() => download.mutate()}>
              <Download size={14} />
              {download.isPending ? 'lädt…' : 'Jetzt laden'}
            </Button>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              Abbrechen
            </Button>
            {download.isSuccess && (
              <span className="text-[12px] text-[var(--ok)]">
                {download.data.source} ({formatBytes(download.data.size)},
                Stand {download.data.month})
              </span>
            )}
          </div>
        </div>
      </Modal>
    </>
  )
}
