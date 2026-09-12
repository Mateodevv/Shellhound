import { useState } from 'react'
import { Download, Globe } from 'lucide-react'
import { useT } from '../i18n'
import { useGeoStatus } from '../geo'
import { GeoDownloadModal } from './GeoBanner'
import { CtiError } from './CaseProfile'
import { Button, Card, Section, Tag } from './ui'

/** GeoIP is downloaded explicitly, then all country lookups stay local. */
export function GeoSettings() {
  const tr = useT()
  const [confirming, setConfirming] = useState(false)
  const { data, error, isPending } = useGeoStatus()

  return (
    <Section title={tr('settings.geo')} sub={tr('settings.geo.sub')}>
      <CtiError error={error} />
      {isPending && <p role="status">{tr('common.loading')}</p>}
      {data && <Card className="flex flex-wrap items-center gap-3 px-4 py-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--panel-2)]">
          <Globe size={15} className="text-[var(--muted)]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold">
              {tr('settings.geo.db')}
            </span>
            {data?.available
              ? <Tag tone="accent">{tr('settings.geo.present')}</Tag>
              : <Tag>{tr('settings.geo.absent')}</Tag>}
          </div>
          <div className="mt-0.5 text-[12px] text-[var(--muted)]">
            {data?.available ? data.source : tr('settings.geo.absent.body')}
          </div>
        </div>
        <Button variant={data?.available ? 'default' : 'primary'}
          onClick={() => setConfirming(true)}>
          <Download size={14} />
          {data?.available ? tr('settings.geo.refresh') : tr('geo.download.cta')}
        </Button>
      </Card>}
      <GeoDownloadModal open={confirming} onClose={() => setConfirming(false)} />
    </Section>
  )
}
