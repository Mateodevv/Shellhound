import type { Dispatch, SetStateAction } from 'react'
import type { CaseProfile } from '../../opencti'
import { useT } from '../../i18n'

export function SectorPicker({ sectors, profile, onChange, required }: {
  sectors: string[]; profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; required: boolean
}) {
  const tr = useT()
  return <fieldset className="rounded-lg border border-[var(--line)] p-3">
    <legend className="px-1 text-[12px] text-[var(--muted)]">{tr('cti.sectors')}{required ? ' *' : ''}</legend>
    <div className="grid gap-2 sm:grid-cols-2">{[...new Set([...sectors, ...profile.sectors])].map(sector => <label key={sector} className="flex items-center gap-2 text-[13px]">
      <input type="checkbox" checked={profile.sectors.includes(sector)} onChange={event => onChange(previous => ({ ...previous,
        sectors: event.target.checked ? [...previous.sectors, sector] : previous.sectors.filter(value => value !== sector),
        subsectors: event.target.checked ? previous.subsectors : previous.subsectors?.filter(item => item.sector !== sector),
      }))} />{sector}
    </label>)}</div>
  </fieldset>
}
