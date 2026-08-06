// GeoBanner.tsx -- the route to the country flags when the database is
// missing, and the confirmed download behind it.
//
// The download does NOT start on the first click: a window says beforehand
// what is about to happen. This is the only place the tool speaks outward
// without an API key behind it, and precisely for that reason it must not
// happen in passing -- whoever works on an isolated forensic machine has to
// be able to say NO before anything leaves the computer.
//
// The modal is exported because the settings page offers the same download.
// One flow, not two: a second copy is a second place for the confirmation to
// quietly go missing.
import { useT } from '../i18n'
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Globe } from 'lucide-react'
import { post } from '../api'
import { formatBytes } from '../format'
import { clearGeoCache, useGeoStatus } from '../geo'
import { Button, Modal } from './ui'
import { SetupBanner } from './SetupBanners'

export function GeoBanner({ onOpenSettings }: {
  onOpenSettings?: () => void
}) {
  const tr = useT()
  const [confirming, setConfirming] = useState(false)
  const { data } = useGeoStatus()

  if (!data || data.available) return null

  return (
    <>
      <SetupBanner
        id="geo"
        icon={<Globe size={15} className="shrink-0 text-[var(--accent)]" />}
        title={tr('geo.missing.title')}
        body={tr('geo.missing.body')}
        cta={<><Download size={14} /> {tr('geo.download.cta')}</>}
        onCta={() => setConfirming(true)}
        onOpenSettings={onOpenSettings}
      />
      <GeoDownloadModal open={confirming} onClose={() => setConfirming(false)} />
    </>
  )
}

/** Say what will happen FIRST -- then let it happen. */
export function GeoDownloadModal({ open, onClose }: {
  open: boolean
  onClose: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const download = useMutation({
    mutationFn: () => post<{ source: string; size: number; month: string }>(
      '/api/geo/download', {}),
    onSuccess: () => {
      clearGeoCache()
      onClose()
      qc.invalidateQueries({ queryKey: ['geo-status'] })
    },
  })

  return (
    <Modal open={open} onClose={onClose}
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
          <Button variant="ghost" onClick={onClose}>{tr('common.cancel')}</Button>
          {download.isSuccess && (
            <span className="text-[12px] text-[var(--ok)]">
              {download.data.source} ({formatBytes(download.data.size)},
              {' '}{tr('geo.asOf')} {download.data.month})
            </span>
          )}
        </div>
      </div>
    </Modal>
  )
}
