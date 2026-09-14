import { useId, useRef, useState, type Dispatch, type SetStateAction } from 'react'
import { Check, ChevronDown, Plus, Search } from 'lucide-react'
import type { CaseProfile } from '../opencti'
import { useT } from '../i18n'
import { IocTag } from './IocTags'

export interface Sector { id: string; name: string; parents: string[]; subsector: boolean }

export function SectorPicker({ sectors, profile, onChange, required, loading, onCreate }: {
  sectors: Sector[]; profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>
  required: boolean; loading: boolean; onCreate: (kind: 'sector' | 'subsector', name: string) => void
}) {
  const tr = useT()
  const id = useId()
  const input = useRef<HTMLInputElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [highlight, setHighlight] = useState(-1)
  const subs = profile.subsectors ?? []
  const roots = [...new Set([...sectors.filter(item => !item.subsector).map(item => item.name), ...sectors.flatMap(item => item.parents), ...profile.sectors])].sort((a, b) => a.localeCompare(b))
  const children = [...new Map([
    ...sectors.flatMap(item => item.parents.map(sector => ({ name: item.name, sector }))), ...subs,
  ].map(item => [JSON.stringify([item.sector, item.name]), item])).values()]
  const options = roots.flatMap(name => [
    { name, sector: '', label: name },
    ...children.filter(item => item.sector === name).sort((a, b) => a.name.localeCompare(b.name)).map(item => ({ ...item, label: `${item.sector} → ${item.name}` })),
  ]).filter(item => item.label.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()))
  const createName = [...roots, ...children.map(item => item.name)].some(name => name.toLocaleLowerCase() === query.trim().toLocaleLowerCase()) ? '' : query.trim()
  const selected = (item: typeof options[number]) => item.sector
    ? subs.some(sub => sub.name === item.name && sub.sector === item.sector)
    : profile.sectors.includes(item.name)
  const removeSector = (name: string) => onChange(previous => ({ ...previous,
    sectors: previous.sectors.filter(value => value !== name),
    subsectors: previous.subsectors?.filter(item => item.sector !== name),
  }))
  const removeSubsector = (name: string, sector: string) => onChange(previous => ({ ...previous,
    subsectors: previous.subsectors?.filter(item => item.name !== name || item.sector !== sector),
  }))
  const toggle = (item: typeof options[number]) => {
    if (selected(item)) {
      if (item.sector) removeSubsector(item.name, item.sector)
      else removeSector(item.name)
    } else onChange(previous => ({ ...previous,
      sectors: [...new Set([...previous.sectors, item.sector || item.name])],
      ...(item.sector ? { subsectors: [...(previous.subsectors ?? []), { name: item.name, sector: item.sector }] } : {}),
    }))
  }
  const close = () => { setOpen(false); setHighlight(-1) }
  const create = (kind: 'sector' | 'subsector') => { close(); onCreate(kind, createName); setQuery('') }
  return <div className="relative min-w-0" onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) close() }}
    onKeyDown={event => { if (event.key === 'Escape' && open) { event.preventDefault(); event.stopPropagation(); input.current?.focus(); close() } }}>
    <label htmlFor={id} className="mb-1.5 block text-[12px] text-[var(--muted)]">{tr('cti.sectorPicker')}{required ? ' *' : ''}</label>
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 focus-within:border-[var(--accent)]">
      {profile.sectors.map(name => <IocTag key={name} value={name} onRemove={() => removeSector(name)} />)}
      {subs.map(item => <IocTag key={JSON.stringify(item)} value={`${item.sector} → ${item.name}`} onRemove={() => removeSubsector(item.name, item.sector)} />)}
      <div className="flex min-w-0 basis-48 grow items-center gap-2">
        <Search size={15} aria-hidden className="shrink-0 text-[var(--muted)]" />
        <input ref={input} id={id} role="combobox" aria-autocomplete="list" aria-expanded={open} aria-controls={`${id}-options`}
          aria-required={required} aria-describedby={`${id}-hint`} aria-activedescendant={open && options[highlight] ? `${id}-option-${highlight}` : undefined}
          className="w-full min-w-0 bg-transparent py-0.5 text-[13px]" style={{ outline: 'none' }} placeholder={tr('cti.searchSectors')} value={query}
          onFocus={() => setOpen(true)} onClick={() => setOpen(true)} onChange={event => { setQuery(event.target.value); setHighlight(-1); setOpen(true) }}
          onKeyDown={event => {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
              event.preventDefault(); setOpen(true)
              const next = !options.length ? -1 : highlight < 0 ? (event.key === 'ArrowDown' ? 0 : options.length - 1) : (highlight + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length
              setHighlight(next)
              list.current?.querySelector<HTMLElement>(`[data-index="${next}"]`)?.scrollIntoView?.({ block: 'nearest' })
            } else if (event.key === 'Enter') {
              event.preventDefault()
              if (open && options[highlight]) toggle(options[highlight])
              else setOpen(true)
            }
          }} />
        <button type="button" aria-label={tr('cti.toggleSectors')} aria-expanded={open} aria-controls={`${id}-options`}
          className="shrink-0 rounded p-0.5 text-[var(--muted)] hover:text-[var(--fg)]" onClick={() => { if (open) close(); else { setOpen(true); input.current?.focus() } }}>
          <ChevronDown size={16} aria-hidden className={open ? 'rotate-180' : ''} />
        </button>
      </div>
    </div>
    <p id={`${id}-hint`} className="mt-1.5 text-[11px] text-[var(--muted)]">{tr('cti.sectorPickerHint')}</p>
    {open && <div className="absolute inset-x-0 z-30 mt-1 overflow-hidden rounded-lg border border-[var(--line)] bg-[var(--panel)] shadow-xl">
      <div ref={list} id={`${id}-options`} role="listbox" aria-label={tr('cti.sectorPicker')} aria-multiselectable="true" aria-busy={loading}
        className="max-h-56 overflow-y-auto overscroll-contain p-1">
        {options.map((item, index) => <div key={JSON.stringify([item.sector, item.name])} id={`${id}-option-${index}`} role="option" aria-label={item.label} aria-selected={selected(item)} data-index={index}
          className={`flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-[13px] hover:bg-[var(--panel-2)] ${highlight === index ? 'bg-[var(--panel-2)]' : ''}`}
          onMouseDown={event => event.preventDefault()} onClick={() => { toggle(item); setHighlight(index); input.current?.focus() }}>
          <span aria-hidden className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border ${selected(item) ? 'border-[var(--accent)] bg-[var(--accent)] text-white' : 'border-[var(--line)]'}`}>{selected(item) && <Check size={12} />}</span>
          <span className="min-w-0 break-words">{item.sector && <span className="text-[var(--muted)]">{item.sector} → </span>}{item.name}</span>
          {!item.sector && <span className="ml-auto text-[11px] text-[var(--muted)]">{tr('cti.sectorType')}</span>}
        </div>)}
      </div>
      {!options.length && <p role="status" className="px-3 py-3 text-xs text-[var(--muted)]">{tr(loading ? 'cti.loadingSectors' : 'cti.noSectorMatches')}</p>}
      <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)] px-3 py-2">
        {createName && <span className="w-full break-words text-xs text-[var(--muted)]">{tr('cti.createSectorQuery', { name: createName })}</span>}
        <button type="button" className="ioc-tag-add" onClick={() => create('sector')}><Plus size={12} />{tr('cti.newSector')}</button>
        <button type="button" className="ioc-tag-add" disabled={!roots.length} onClick={() => create('subsector')}><Plus size={12} />{tr('cti.newSubsector')}</button>
      </div>
    </div>}
  </div>
}
