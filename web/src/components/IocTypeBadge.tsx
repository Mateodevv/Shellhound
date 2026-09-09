import { Bug, FileCode, Folder, Hexagon, Link, Mail, Text, UserRound } from 'lucide-react'
import { useT } from '../i18n'

export function IocTypeBadge({ type, value = '' }: { type: string; value?: string }) {
  const tr = useT()
  const key = type === 'ip' ? (value.includes(':') ? 'ipv6' : 'ipv4') : type
  const variants = {
    ipv4: { label: tr('iocBadge.ipv4'), icon: Hexagon, tone: 'rose' },
    ipv6: { label: tr('iocBadge.ipv6'), icon: Hexagon, tone: 'rose' },
    file: { label: tr('iocBadge.file'), icon: Hexagon, tone: 'green' },
    hash: { label: tr('iocBadge.hash'), icon: FileCode, tone: 'green' },
    vulnerability: { label: tr('iocBadge.cve'), icon: Bug, tone: 'yellow' },
    domain: { label: tr('iocBadge.domain'), icon: Hexagon, tone: 'blue' },
    url: { label: tr('iocBadge.url'), icon: Link, tone: 'blue' },
    email: { label: tr('iocBadge.email'), icon: Mail, tone: 'purple' },
    user: { label: tr('iocBadge.user'), icon: UserRound, tone: 'purple' },
    path: { label: tr('iocBadge.path'), icon: Folder, tone: 'yellow' },
    other: { label: tr('iocBadge.context'), icon: Text, tone: 'neutral' },
  }
  const { label, icon: Icon, tone } = variants[key as keyof typeof variants] || variants.other
  return <span className={`ioc-type-badge ioc-tone-${tone}`}><Icon size={13} aria-hidden="true" />{label}</span>
}
