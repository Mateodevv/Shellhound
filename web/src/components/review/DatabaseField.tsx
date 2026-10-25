import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type DatabaseFieldPage, type DatabaseFieldMatch, type DatabaseRow, type Finding } from '../../api'
import { useT } from '../../i18n'
import { Button, CopyButton, Modal } from '../ui/ui'

export function MatchText({ match, finding }: { match: { before: string; text: string; after: string }; finding?: Finding | null }) {
  const style = finding?.triage === 'confirmed' ? 'bg-[var(--danger-soft)] text-[var(--danger-text)]'
    : finding?.triage === 'dismissed' ? 'bg-[var(--panel-2)] text-[var(--muted)] line-through'
    : 'bg-[var(--review-soft)] text-[var(--review-text)]'
  return <>{match.before}<mark className={`rounded px-0.5 ${style}`}>{match.text}</mark>{match.after}</>
}

export function DatabaseField({ slug, record, columnIndex, match, finding, onClose }: {
  slug: string; record: DatabaseRow; columnIndex: number; match?: DatabaseFieldMatch; finding?: Finding | null; onClose: () => void
}) {
  const tr = useT()
  const [offset, setOffset] = useState(Math.max(0, (match?.start ?? 0) - 512))
  const { data, error, isPending } = useQuery({
    queryKey: ['database-field', slug, record.table_id, record.row, columnIndex, record.record_version, finding?.id, offset],
    queryFn: () => api<DatabaseFieldPage>(`/api/cases/${slug}/database/field?table_id=${record.table_id}&row=${record.row}&column_index=${columnIndex}&offset=${offset}&record_version=${encodeURIComponent(record.record_version!)}${finding ? `&finding_id=${finding.id}` : ''}`),
  })
  return <Modal open layer={3} contained onClose={onClose} title={`${record.table} · ${match?.column_name ?? record.columns.find((column, index) => (column.index ?? index) === columnIndex)?.name ?? ''}`}>
    <div className="flex min-h-0 flex-1 flex-col gap-3 text-[12px]">
      {isPending && <p role="status">{tr('common.loading')}</p>}
      {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}
      {data && <>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span>{tr('database.row.position', { from: data.total_characters ? data.offset + 1 : 0, to: data.next_offset ?? data.total_characters, total: data.total_characters })}</span>
          <CopyButton value={data.value ?? 'NULL'} label={tr('database.row.copyVisible')} />
        </div>
        <pre tabIndex={0} className="mono min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--line)] p-3">{data.highlight ? <MatchText match={data.highlight} finding={finding} /> : data.value ?? 'NULL'}</pre>
        <div className="flex flex-wrap gap-2">
          <Button disabled={!data.offset} onClick={() => setOffset(0)}>{tr('database.row.first')}</Button>
          <Button disabled={!data.offset} onClick={() => setOffset(Math.max(0, data.offset - 8192))}>{tr('review.previousPage')}</Button>
          <Button disabled={data.next_offset == null} onClick={() => setOffset(data.next_offset!)}>{tr('review.nextPage')}</Button>
          <Button disabled={data.next_offset == null} onClick={() => setOffset(Math.max(0, data.total_characters - 8192))}>{tr('database.row.last')}</Button>
        </div>
      </>}
    </div>
  </Modal>
}
