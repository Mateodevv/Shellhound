import { useEffect, useRef } from 'react'
import { useT } from '../i18n'

export function SelectColumn({ label, states, onChange }: { label: string; states: boolean[]; onChange: (checked: boolean) => void }) {
  const tr = useT()
  const ref = useRef<HTMLInputElement>(null)
  const count = states.filter(Boolean).length
  const mixed = count > 0 && count < states.length
  useEffect(() => { if (ref.current) ref.current.indeterminate = mixed }, [mixed])
  return <input ref={ref} type="checkbox" aria-label={tr('cti.selectColumn', { column: label })}
    title={tr('cti.selectColumnScope')} disabled={!states.length} checked={states.length > 0 && count === states.length}
    onChange={e => onChange(e.target.checked)} />
}
