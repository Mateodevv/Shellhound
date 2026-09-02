import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { CheckCircle2, Eye, FileDown, TriangleAlert } from 'lucide-react'
import { api, downloadUrl, patch, type CaseDetail, type Dashboard, type Job } from '../api'
import { useT } from '../i18n'
import { Button, Card, Section, Tag } from '../components/ui'
import { CloseCase } from './Evidence'
import type { Navigate } from '../App'

const REPORT_SECTIONS = [
  'notes', 'evidence', 'decisions', 'chronology', 'limitations',
  'indicators', 'hunts', 'cross',
] as const

export function Report({ slug, onClosed }: {
  slug: string
  gotoView: Navigate
  onClosed?: () => void
}) {
  const tr = useT()
  const [sections, setSections] = useState<Set<string>>(() => new Set(REPORT_SECTIONS))
  const [preview, setPreview] = useState(false)
  const [notes, setNotes] = useState('')
  const { data: caseInfo, refetch: refetchCase } = useQuery({
    queryKey: ['case', slug], queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  useEffect(() => setNotes(caseInfo?.notes ?? ''), [caseInfo?.notes])
  const saveNotes = useMutation({
    mutationFn: () => patch(`/api/cases/${slug}`, { notes }),
    onSuccess: () => { refetchCase(); setPreview(false) },
  })
  const { data: dashboard } = useQuery({
    queryKey: ['dashboard', slug], queryFn: () => api<Dashboard>(`/api/cases/${slug}/dashboard`),
  })
  const { data: jobs } = useQuery({
    queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
  })
  const sectionParam = [...sections].join(',')
  const reportPath = `/api/cases/${slug}/report.html?sections=${encodeURIComponent(sectionParam)}`
  const previewUrl = downloadUrl(`${reportPath}&preview=1`)
  const download = downloadUrl(reportPath)

  const checks = useMemo(() => {
    const triage = dashboard?.triage ?? {}
    const open = (triage.new ?? 0) + (triage.reviewed ?? 0)
    return [
      { ok: Boolean(caseInfo?.evidence_items.length), text: tr('report.check.evidence') },
      { ok: !(jobs ?? []).some((job) => job.state === 'running' || job.state === 'queued'),
        text: tr('report.check.jobs') },
      { ok: !(jobs ?? []).some((job) => job.state === 'failed'), text: tr('report.check.failures') },
      { ok: open === 0, text: tr('report.check.triage', { n: open }) },
      { ok: (triage.confirmed ?? 0) > 0, text: tr('report.check.confirmed') },
    ]
  }, [caseInfo, dashboard, jobs, tr])
  const ready = checks.every((check) => check.ok)

  return (
    <div className="flex flex-col gap-6">
      <Section title={tr('report.builder.title')} sub={tr('report.builder.sub')}>
        <Card surface="raised" className="mb-4 flex flex-wrap items-center gap-3 px-4 py-3">
          {ready
            ? <CheckCircle2 size={18} className="shrink-0 text-[var(--ok)]" />
            : <TriangleAlert size={18} className="shrink-0 text-[var(--sev-low)]" />}
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold">
              {tr(ready ? 'report.ready.title' : 'report.needsReview.title')}
            </div>
            <div className="mt-0.5 text-[11.5px] text-[var(--muted)]">
              {tr(ready ? 'report.ready.sub' : 'report.needsReview.sub', {
                n: checks.filter((check) => !check.ok).length,
              })}
            </div>
          </div>
          <Tag tone={ready ? 'ok' : 'warn'}>
            {ready ? tr('report.ready') : tr('report.needsReview')}
          </Tag>
        </Card>
        <Card className="mb-4 p-4">
          <label className="text-[13px] font-semibold" htmlFor="case-report-notes">
            {tr('report.caseNotes')}
          </label>
          <p className="mb-2 mt-0.5 text-[11.5px] text-[var(--muted)]">{tr('report.caseNotes.hint')}</p>
          <textarea id="case-report-notes" value={notes} rows={4}
            onChange={(event) => setNotes(event.target.value)}
            className="w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70" />
          <div className="mt-2 flex items-center gap-2">
            <Button onClick={() => saveNotes.mutate()}
              disabled={saveNotes.isPending || notes === (caseInfo?.notes ?? '')}>
              {tr('common.save')}
            </Button>
            {saveNotes.isSuccess && notes === (caseInfo?.notes ?? '') && (
              <span className="text-[11.5px] text-[var(--ok)]">{tr('report.caseNotes.saved')}</span>
            )}
          </div>
        </Card>
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.7fr)]">
          <Card className="p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="text-[13px] font-semibold">{tr('report.sections')}</div>
              <Tag tone={ready ? 'accent' : 'warn'}>
                {ready ? tr('report.ready') : tr('report.needsReview')}
              </Tag>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {REPORT_SECTIONS.map((section) => (
                <label key={section}
                  className="flex cursor-pointer items-center gap-2 rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12.5px]">
                  <input type="checkbox" checked={sections.has(section)}
                    className="accent-[var(--accent)]"
                    onChange={(event) => {
                      const next = new Set(sections)
                      if (event.target.checked) next.add(section)
                      else next.delete(section)
                      setSections(next)
                      setPreview(false)
                    }} />
                  {tr(`report.section.${section}`)}
                </label>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button onClick={() => setPreview((value) => !value)} disabled={!sections.size}>
                <Eye size={14} /> {preview ? tr('report.hidePreview') : tr('report.showPreview')}
              </Button>
              <a href={download} className="inline-flex" aria-disabled={!sections.size}>
                <Button variant="primary" disabled={!sections.size}>
                  <FileDown size={14} /> {tr('report.download')}
                </Button>
              </a>
            </div>
          </Card>
          <Card className="p-4">
            <div className="mb-3 text-[13px] font-semibold">{tr('report.closeChecklist')}</div>
            <div className="flex flex-col gap-2">
              {checks.map((check) => (
                <div key={check.text} className="flex items-start gap-2 text-[12.5px]">
                  {check.ok
                    ? <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-[var(--ok)]" />
                    : <TriangleAlert size={15} className="mt-0.5 shrink-0 text-[var(--sev-low)]" />}
                  <span className={check.ok ? 'text-[var(--muted)]' : ''}>{check.text}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
        {preview && (
          <Card className="mt-4 overflow-hidden">
            <iframe title={tr('report.preview')} src={previewUrl}
              className="h-[70vh] w-full bg-white" />
          </Card>
        )}
      </Section>
      <CloseCase slug={slug} caseName={caseInfo?.name ?? slug} onClosed={onClosed} />
    </div>
  )
}
