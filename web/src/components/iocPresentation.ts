import { translate } from '../i18n'
import type { Ioc } from '../api'
import type { OpenCtiLookup } from '../opencti'

export const iocName = (ioc: Ioc) => ioc.file?.names[0] || ioc.value
export const assessmentTone = (state?: string) => state === 'malicious' ? 'text-[var(--danger-text)]' : state === 'suspicious' ? 'text-[var(--review-text)]' : state === 'benign' ? 'text-[var(--ok)]' : 'text-[var(--muted)]'
export const ctiLabel = (lookup?: OpenCtiLookup) => lookup?.stale ? 'Outdated result' : lookup ? ({ known: 'Known in OpenCTI', own: 'Own exports only', unknown: 'No visible match', unsupported: 'Context only', error: 'Check failed' }[lookup.status]) : 'Not checked'
export const descriptions: Record<string, string> = {
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
