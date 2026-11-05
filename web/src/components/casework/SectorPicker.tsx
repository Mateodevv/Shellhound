import type { Dispatch, SetStateAction } from 'react'
import type { CaseProfile } from '../../opencti'
import { useT } from '../../i18n'

export function SectorPicker({ sectors, profile, onChange, required }: {
  sectors: string[]; profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; required: boolean
}) {
  const tr = useT()
  return <details className="rounded-lg border border-[var(--line)] p-3">
    <summary className="cursor-pointer text-[13px] font-medium">{tr('cti.mainSectors', { n: profile.sectors.length })}{required ? ' *' : ''}</summary>
    <div className="mt-3 grid gap-2 sm:grid-cols-3">{[...new Set([...sectors, ...profile.sectors])].map(sector => <label key={sector} className="flex items-center gap-2 text-[13px]">
      <input type="checkbox" checked={profile.sectors.includes(sector)} onChange={event => onChange(previous => ({ ...previous,
        sectors: event.target.checked ? [...previous.sectors, sector] : previous.sectors.filter(value => value !== sector),
        subsectors: event.target.checked ? previous.subsectors : previous.subsectors?.filter(item => item.sector !== sector),
      }))} />{sector}
    </label>)}</div>
  </details>
}
