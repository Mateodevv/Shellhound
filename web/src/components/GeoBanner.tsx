// GeoBanner.tsx -- the route to the country flags when the database is
// missing.
//
// A banner like the one for missing evidence: clearly visible in the
// dashboard, disappearing by itself once it is done. The download itself
// does NOT start on the first click -- a window says beforehand what is
// about to happen. This is the only network contact of the entire tool, and
// precisely for that reason it must not happen in passing: whoever works on
// an isolated forensic machine has to be able to say NO before anything
// leaves the computer.
//
// "Do not show again" is remembered (localStorage): whoever deliberately
// works without GeoIP should not be put off anew in every case.
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
            {tr('geo.missing.body')}
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            onClick={() => setConfirming(true)}
            className="inline-flex items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline cursor-pointer"
          >
            <Download size={14} /> {tr('geo.download.cta')}
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

      {/* Say what will happen FIRST — then let it happen. */}
      <Modal open={confirming} onClose={() => setConfirming(false)}
        title={<span className="flex items-center gap-2">
          <Globe size={16} className="text-[var(--accent)]" />
          {tr('geo.confirm.title')}
        </span>}>
        <div className="flex max-w-xl flex-col gap-3 text-[13px]">
          <p>
            {tr('geo.confirm.what.a')}{' '}
            <span className="mono">download.db-ip.com</span>{tr('geo.confirm.what.b')}{' '}
            <span className="font-semibold">DB-IP Country Lite</span>{' '}
            {tr('geo.confirm.what.c')}
          </p>
          <p className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12.5px] text-[var(--muted)]">
            {tr('geo.confirm.privacy.a')}{' '}
            <span className="font-medium text-[var(--fg)]">{tr('geo.confirm.privacy.only')}</span>{' '}
            {tr('geo.confirm.privacy.b')}{' '}
            <span className="font-medium text-[var(--fg)]">{tr('geo.confirm.privacy.nodata')}</span>{' '}
            {tr('geo.confirm.privacy.c')}{' '}
            <span className="mono">*.mmdb</span> {tr('geo.confirm.privacy.d')}
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
              {download.isPending ? tr('common.loading') : tr('geo.download.now')}
            </Button>
            <Button variant="ghost" onClick={() => setConfirming(false)}>
              {tr('common.cancel')}
            </Button>
            {download.isSuccess && (
              <span className="text-[12px] text-[var(--ok)]">
                {download.data.source} ({formatBytes(download.data.size)},
                {' '}{tr('geo.asOf')} {download.data.month})
              </span>
            )}
          </div>
        </div>
      </Modal>
    </>
  )
}
