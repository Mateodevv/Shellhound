import { CircleHelp, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react'
import { useT } from '../i18n'

export function IocAssessmentBadge({ assessment }: { assessment?: string }) {
  const tr = useT()
  const variants = {
    malicious: { icon: ShieldAlert, tone: 'rose', label: tr('iocBadge.malicious') },
    suspicious: { icon: TriangleAlert, tone: 'yellow', label: tr('iocBadge.suspicious') },
    benign: { icon: ShieldCheck, tone: 'green', label: tr('iocBadge.benign') },
    unassessed: { icon: CircleHelp, tone: 'neutral', label: tr('iocBadge.unassessed') },
  }
  const { icon: Icon, tone, label } = variants[assessment as keyof typeof variants] || variants.unassessed
  return <span className={`ioc-type-badge ioc-tone-${tone}`}><Icon size={13} aria-hidden="true" />{label}</span>
}
