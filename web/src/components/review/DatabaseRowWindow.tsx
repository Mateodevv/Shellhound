import type { DatabaseRowSource, Finding } from '../../api'
import { useT } from '../../i18n'
import { Modal } from '../ui/ui'
import { TableRecord } from './ReviewEvidence'

export function DatabaseRowWindow({ slug, finding, sources, tableName, initialRow, sourceId, onSourceChange, onClose }: {
  slug: string; finding?: Finding | null; sources: DatabaseRowSource[]; tableName?: string; initialRow?: number
  sourceId?: number | null; onSourceChange?: (id: number | null) => void; onClose: () => void
}) {
  const tr = useT()
  const table = tableName ?? finding?.artifact ?? ''
  return <Modal open onClose={onClose} layer={2} contained title={tr('database.row.title', { table, row: initialRow ?? finding?.line ?? 1 })}>
    <TableRecord slug={slug} finding={finding} sources={sources} tableName={table} initialRow={initialRow} sourceId={sourceId} onSourceChange={onSourceChange} />
  </Modal>
}
