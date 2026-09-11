import type { OpenCtiConnector } from '../opencti'
import { useT } from '../i18n'
import { IocTypeBadge } from './IocTypeBadge'
import { InfoDot } from './Tooltip'

// Match Shellhound's enrichment targets; attached samples have no target here.
const targets = [
  { scope: 'ipv4-addr', type: 'ip', value: '192.0.2.1' },
  { scope: 'ipv6-addr', type: 'ip', value: '2001:db8::1' },
  { scope: 'stixfile', type: 'file' },
  { scope: 'stixfile', type: 'hash' },
  { scope: 'domain-name', type: 'domain' },
  { scope: 'url', type: 'url' },
  { scope: 'email-addr', type: 'email' },
  { scope: 'user-account', type: 'user' },
  { scope: 'vulnerability', type: 'vulnerability' },
]

export function connectorTargets(scope: string[]) {
  const supported = new Set(scope.map(value => value.toLowerCase()))
  return targets.filter(target => supported.has(target.scope)
    || (target.type !== 'vulnerability' && supported.has('stix-cyber-observable')))
}

export function ConnectorCapabilities({ connector }: { connector: OpenCtiConnector }) {
  const tr = useT()
  const types = connectorTargets(connector.scope)
  const name = connector.name.toLowerCase().replace(/[^a-z0-9]/g, '')
  const profile = name.includes('virustotal') ? 'virustotal'
    : name.includes('abuseipdb') ? 'abuseipdb'
    : name.includes('shodan') ? 'shodan'
    : name.includes('firstepss') ? 'epss' : 'generic'
  return <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
    {types.map(target => <IocTypeBadge key={`${target.scope}-${target.type}`} type={target.type} value={target.value} />)}
    {!types.length && <span className="text-[11px] text-[var(--muted)]">{tr('cti.connectorHelp.noTypes')}</span>}
    <InfoDot wide body={<>
      <span className="block">{tr(`cti.connectorHelp.${profile}`)}</span>
      {types.some(target => target.type === 'file') && <span className="mt-2 block">{tr('cti.connectorHelp.files')}</span>}
      {types.some(target => target.type === 'user') && <span className="mt-2 block">{tr('cti.connectorHelp.accounts')}</span>}
      <span className="mt-2 block">{tr('cti.connectorHelp.results')}</span>
    </>} />
  </div>
}
