import type { CaseProfileChanges as Changes } from '../opencti'
import { useT } from '../i18n'

const labels: Record<string, string> = {
  reference: 'cti.caseId', summary: 'cti.summary', organization_name: 'cti.organizationName',
  sectors: 'cti.sectors', subsectors: 'cti.subsectors', countries: 'cti.country', state: 'cti.state',
  city: 'cti.city', first_seen: 'cti.firstSeen', last_seen: 'cti.lastSeen', marking: 'cti.marking',
  software: 'cti.software', vulnerabilities: 'cti.vulns',
}
export function CaseProfileChanges({ changes, updating = false }: { changes?: Changes; updating?: boolean }) {
  const tr = useT()
  if (!changes && !updating) return null
  const values = (lines: string[]) => lines.length ? <ul className="space-y-1">{lines.map(line => <li key={line} className="whitespace-pre-wrap break-words">{line}</li>)}</ul> : <span className="text-[var(--muted)]">{tr('profileChanges.empty')}</span>
  return <section aria-label={tr('profileChanges.title')} className="rounded-lg border border-[var(--line)]">
    <header className="space-y-1 border-b border-[var(--line)] px-4 py-3">
      <h3 className="text-[13px] font-semibold">{tr('profileChanges.title')}</h3>
      <p className="text-[12px] text-[var(--muted)]">{tr('profileChanges.help')}</p>
      {!updating && changes?.exported_at && <p className="text-[11px] text-[var(--muted)]">{tr('profileChanges.baseline', { at: changes.exported_at })}</p>}
    </header>
    {updating ? <p role="status" className="p-4">{tr('cti.previewUpdating')}</p> : changes?.status !== 'changed' ? <p className="p-4 text-[13px] text-[var(--muted)]">{tr(`profileChanges.${changes?.status}`)}</p> :
      <div className="overflow-x-auto"><table className="w-full table-fixed text-left text-[12px]">
        <thead className="bg-[var(--panel-2)] text-[var(--muted)]"><tr><th className="w-1/4 px-4 py-2">{tr('profileChanges.field')}</th><th className="px-4 py-2">{tr('profileChanges.before')}</th><th className="px-4 py-2">{tr('profileChanges.after')}</th></tr></thead>
        <tbody>{changes.entries.map(entry => <tr key={entry.field} className="border-t border-[var(--line)] align-top"><th scope="row" className="px-4 py-3 font-medium">{tr(labels[entry.field] || entry.field)}</th><td className="px-4 py-3 text-[var(--muted)]">{values(entry.before)}</td><td className="px-4 py-3">{entry.included ? values(entry.after) : tr('profileChanges.excluded')}</td></tr>)}</tbody>
      </table></div>}
  </section>
}
