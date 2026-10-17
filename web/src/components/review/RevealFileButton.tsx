import { useMutation } from '@tanstack/react-query'
import { FolderOpen } from 'lucide-react'
import { post } from '../../api'
import { useT } from '../../i18n'
import { Button } from '../ui/ui'

export function RevealFileButton({ slug, path, disabled = false }: {
  slug: string; path: string; disabled?: boolean
}) {
  const tr = useT()
  const reveal = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/reveal-file`, { path }),
  })
  return <div className="min-w-0">
    <Button variant="ghost" disabled={disabled || !path || reveal.isPending} onClick={() => reveal.mutate()}>
      <FolderOpen size={13} />{tr('artifact.showInFileManager')}
    </Button>
    {reveal.error && <p role="alert" className="mt-2 break-words text-xs text-[var(--danger-text)]">
      {tr('artifact.revealError')}: {reveal.error.message}
    </p>}
  </div>
}
