import { useT } from '../../i18n'
import { safeCtiUrl, type OpenCtiCounts } from '../../opencti'

export function OpenCtiReceipt({ counts, caseUrl }: { counts?: OpenCtiCounts; caseUrl?: string | null }) {
  const tr = useT()
  const url = safeCtiUrl(caseUrl ?? undefined)
  return <span className="inline-flex flex-wrap items-center gap-2">
    {counts && <span>{tr('cti.transferredCounts', {
      ips: tr(counts.ips === 1 ? 'cti.ipCount' : 'cti.ipsCount', { n: counts.ips }),
      cves: tr(counts.cves === 1 ? 'cti.cveCount' : 'cti.cvesCount', { n: counts.cves }),
      hashes: tr(counts.hashes === 1 ? 'cti.hashCount' : 'cti.hashesCount', { n: counts.hashes }),
    })}</span>}
    {url && <a className="underline" href={url} target="_blank" rel="noreferrer">{tr('cti.openCase')}</a>}
  </span>
}
