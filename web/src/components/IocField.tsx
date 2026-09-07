import type { ReactNode } from 'react'
import { InfoDot } from './Tooltip'
import { descriptions } from './iocPresentation'
export function IocField({ name, children }: { name: string; children: ReactNode }) {
  return <div className="min-w-0 space-y-2 py-3">
    <div className="flex items-center gap-2 text-[12px] text-[var(--muted)]">
      {name}
      <InfoDot body={descriptions[name]} />
    </div>
    <div className="break-words text-[13px]">{children}</div>
  </div>
}
