import { translate } from '../i18n'
import type { Ioc } from '../api'
import type { OpenCtiLookup } from '../opencti'

export const iocName = (ioc: Ioc) => ioc.file?.names[0] || ioc.value
export const assessmentTone = (state?: string) => state === 'malicious' ? 'text-[var(--danger-text)]' : state === 'suspicious' ? 'text-[var(--review-text)]' : state === 'benign' ? 'text-[var(--ok)]' : 'text-[var(--muted)]'
export const ctiLabel = (lookup?: OpenCtiLookup) => lookup?.stale ? 'Outdated result' : lookup ? ({ known: 'Known in OpenCTI', own: 'Own exports only', unknown: 'No visible match', unsupported: 'Context only', error: 'Check failed' }[lookup.status]) : 'Not checked'
export const descriptions: Record<string, string> = {
  Tags: translate('iocTags.help'),
  'First observed': translate('iocWorkspace.help.first_observed'),
  'Last observed': translate('iocWorkspace.help.last_observed'),
  Origin: translate('iocWorkspace.help.origin'),
  'Matching requests': translate('iocWorkspace.help.matching_requests'),
  'Evidence sources': translate('iocWorkspace.help.evidence_sources'),
  'Case assessment': translate('iocWorkspace.help.case_assessment'),
  Relationships: translate('iocWorkspace.help.relationships'),
  'Transfer status': translate('iocWorkspace.help.transfer_status'),
  'Last checked': translate('iocWorkspace.help.last_checked'),
  'OpenCTI match': translate('iocWorkspace.help.opencti_match'),
  Classification: translate('iocWorkspace.help.classification'),
  Size: translate('iocWorkspace.help.size'),
  Hashes: translate('iocWorkspace.help.hashes'),
  Context: translate('iocWorkspace.help.context'),
  Evidence: translate('iocWorkspace.help.evidence'),
}

export const observationTime = (value?: string | null) => value ? value.replace('T', ' ').replace(/\+00:00$/, ' UTC') : 'Not recorded'

export function iocOrigins(
  ioc: Ioc,
  observations: { kind: string; detail: string; finding_id: number | null; active: boolean }[],
  findings: { id: number; rule: string; triage: string; retired?: boolean }[],
): string[] {
  const origins = new Set<string>()
  const active = observations.filter(o => o.active)
  for (const o of active) {
    if (o.kind === 'pattern-hunt') {
      // collect_hunt_cves records the name at test time before this delimiter.
      // Keep that historical name, including semicolons, when a rule is renamed.
      const marker = o.detail.lastIndexOf('; CVE metadata: ')
      const name = marker >= 0 ? o.detail.slice(0, marker).trim() : ''
      origins.add(name ? translate('iocWorkspace.origin_pattern', { name }) : translate('iocWorkspace.pattern_hunt'))
    }
  }
  for (const finding of findings) {
    if (finding.retired || finding.triage === 'dismissed' || !finding.rule.trim()) continue
    if (active.some(o => o.finding_id === finding.id) || (!active.length && ioc.tags.includes('finding'))) {
      origins.add(translate('iocWorkspace.origin_finding', { name: finding.rule }))
    }
  }
  return origins.size ? [...origins] : [ioc.origin || translate('iocWorkspace.origin_analyst')]
}
