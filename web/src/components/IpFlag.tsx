// IpFlag.tsx — die Länderflagge an einer IP, mit ehrlichem Tooltip.
//
// GeoIP wird gern überinterpretiert, deshalb sagt der Tooltip an jeder
// Flagge dazu, was sie ist: eine Schätzung der REGISTRIERUNG, kein
// Aufenthaltsort — VPNs, Proxys, Tor und Botnetz-Knoten stehen woanders.
//
// Sonderbereiche (privat, Loopback, Dokumentation) bekommen statt einer
// Flagge ein gestricheltes Kürzel: »die Quell-IP ist privat« ist im Log
// oft die wichtigere Aussage als jedes Land — sie heißt Proxy davor oder
// Verkehr aus dem eigenen Netz.
//
// Flaggen sind lokal gebündelte SVGs (flag-icons, MIT): Windows rendert
// Flaggen-Emojis nicht, und ein Forensik-Werkzeug lädt nichts von CDNs.
import { useGeo } from '../geo'
import { Tooltip } from './Tooltip'

const SPECIAL_SHORT: [string, string][] = [
  ['Dokumentations', 'doc'],
  ['Privates Netz', 'priv'],
  ['Loopback', 'lo'],
  ['Link-local', 'll'],
  ['Multicast', 'mc'],
  ['Reserviert', 'res'],
]

export function IpFlag({ ip }: { ip?: string | null }) {
  const info = useGeo(ip)
  if (!info) return null

  if (info.special) {
    const short = SPECIAL_SHORT.find(([k]) => info.name.startsWith(k))?.[1] ?? 'spez'
    return (
      <Tooltip title={info.name.split(' — ')[0]}
        hint={info.name.includes(' — ') ? info.name.split(' — ')[1] : undefined}>
        <span className="shrink-0 rounded border border-dashed border-[var(--line)] px-1 text-[9.5px] uppercase leading-[14px] text-[var(--muted)]">
          {short}
        </span>
      </Tooltip>
    )
  }

  if (!info.iso) return null
  return (
    <Tooltip title={`${info.name} (${info.iso.toUpperCase()})`}
      hint="Laut GeoIP-Datenbank — eine Schätzung der Registrierung, kein Aufenthaltsort. VPNs, Proxys, Tor und Botnetz-Knoten stehen woanders.">
      <span className={`fi fi-${info.iso} shrink-0 rounded-[2px] text-[13px] leading-none`}
        aria-label={info.name} />
    </Tooltip>
  )
}
