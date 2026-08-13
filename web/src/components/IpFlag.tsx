// IpFlag.tsx -- the country flag on an IP, with an honest tooltip.
//
// GeoIP is readily over-interpreted, so the tooltip on every flag says what
// it is: an estimate of the REGISTRATION, not a location -- VPNs, proxies,
// Tor and botnet nodes are somewhere else.
//
// Special ranges (private, loopback, documentation) get a dashed
// abbreviation instead of a flag: "the source IP is private" is often the
// more important statement in a log than any country -- it means a proxy in
// front, or traffic from the local network.
//
// Flags are locally bundled SVGs (flag-icons, MIT): Windows does not render
// flag emoji, and a forensic tool loads nothing from CDNs.
import { useT } from '../i18n'
import { useGeo } from '../geo'
import { useFlagUrl } from '../flags'
import { Tooltip } from './Tooltip'

// The server names the range in the interface language, so both spellings
// have to be known here -- with only the German ones, the English interface
// fell through to the catch-all "spez" for almost every special range.
const SPECIAL_SHORT: [string, string][] = [
  ['Dokumentations', 'doc'], ['Documentation', 'doc'],
  ['Privates Netz', 'priv'], ['Private network', 'priv'],
  ['Loopback', 'lo'],
  ['Link-local', 'll'],
  ['Multicast', 'mc'],
  ['Reserviert', 'res'], ['Reserved', 'res'],
]

export function IpFlag({ ip }: { ip?: string | null }) {
  const tr = useT()
  const info = useGeo(ip)
  const src = useFlagUrl(info?.iso ?? undefined)
  if (!info) return null

  if (info.special) {
    const short = SPECIAL_SHORT.find(([k]) => info.name.startsWith(k))?.[1] ?? 'spez'
    return (
      <Tooltip title={info.name.split(' — ')[0]}
        // A cryptic badge with a tooltip that only repeats the badge is
        // still cryptic -- ranges whose name carries no explanation get
        // the generic one.
        hint={info.name.includes(' — ') ? info.name.split(' — ')[1]
                                        : tr('geo.special.hint')}>
        <span className="shrink-0 rounded border border-dashed border-[var(--line)] px-1 text-[9.5px] uppercase leading-[14px] text-[var(--muted)]">
          {short}
        </span>
      </Tooltip>
    )
  }

  if (!info.iso) return null
  if (!src) return null
  return (
    <Tooltip title={`${info.name} (${info.iso.toUpperCase()})`}
      hint={tr('geo.flag.hint')}>
      <img src={src} alt="" aria-label={info.name}
        className="h-[13px] w-[17px] shrink-0 rounded-[2px] object-cover" />
    </Tooltip>
  )
}
