import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Archive, CheckCircle2, LoaderCircle, TriangleAlert } from 'lucide-react'
import { api, post, type CaseInfo, type CaseSummary, type Ioc, type Job } from '../../api'
import { useT } from '../../i18n'
import { initialExportOptions, transferableIoc, openCtiKey, useOpenCtiSettings, type OpenCtiState, type OpenCtiOptions, type OpenCtiPreview } from '../../opencti'
import { Button } from '../ui/ui'
import { CtiError } from '../casework/CaseProfile'
import { OpenCtiExportDialog } from './OpenCtiExport'
import { OpenCtiReceipt } from './OpenCtiReceipt'

const activeJob = (job: Job) => ['queued', 'running'].includes(job.state)
type TransferResult = { job_id: number; export_id?: string }

export function ReportTransfer({ slug, caseInfo, onClosed, onExit }: { slug: string; caseInfo?: CaseInfo; onClosed?: () => void; onExit?: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useOpenCtiSettings()
  const configured = settings.data?.configured === true
  const [step, setStep] = useState(1)
  const [draft, setDraft] = useState<{ data: OpenCtiPreview; options: OpenCtiOptions } | null>(null)
  const [result, setResult] = useState<TransferResult | null>(null)
  const [typed, setTyped] = useState('')
  const preparing = useRef(false)
  const jobs = useQuery({ queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`), refetchInterval: step >= 2 ? 2000 : false })
  const status = useQuery({ queryKey: openCtiKey(slug), queryFn: () => api<OpenCtiState>(`/api/cases/${slug}/opencti`), enabled: configured, refetchInterval: step >= 2 && configured ? 2000 : false })
  const summary = useQuery({ queryKey: ['close-summary', slug], queryFn: () => api<CaseSummary>(`/api/cases/${slug}/summary`), enabled: step === 3 })
  const active = jobs.data?.some(activeJob) ?? false
  const currentJob = jobs.data?.find(job => job.id === result?.job_id)
  const receiptId = result?.export_id || (typeof currentJob?.stats?.export_id === 'string' ? currentJob.stats.export_id : undefined)
  const receipt = configured ? status.data?.exports.find(entry => entry.id === receiptId) : undefined
  const settled = Boolean(currentJob && !activeJob(currentJob)) && !active && jobs.isSuccess
  const successful = settled && status.isSuccess && currentJob?.state === 'done' && receipt?.state === 'complete'
  const acceptResult = (value: TransferResult) => {
    setResult(value); setStep(2)
    qc.invalidateQueries({ queryKey: openCtiKey(slug) }); qc.invalidateQueries({ queryKey: ['jobs', slug] })
  }
  // Reopening the page resumes monitoring an active transfer instead of submitting it again.
  useEffect(() => {
    const running = jobs.data?.find(job => job.kind === 'opencti-export' && activeJob(job))
    if (configured && running && !result) { setResult({ job_id: running.id }); setStep(2) }
  }, [jobs.data, configured, result])
  const prepare = useMutation({ mutationFn: async () => {
    const iocs = await api<Ioc[]>(`/api/cases/${slug}/iocs`)
    const options = initialExportOptions(iocs.filter(ioc => transferableIoc(ioc.type)).map(ioc => ioc.id))
    return { options, data: await post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, options) }
  }, onSuccess: setDraft })
  const retry = useMutation({ mutationFn: () => post<TransferResult>(`/api/cases/${slug}/opencti/retry`, { export_id: receiptId }), onSuccess: acceptResult })
  const archive = useMutation({ mutationFn: async () => {
    const latest = await jobs.refetch()
    if (latest.error) throw latest.error
    if (!latest.data || latest.data.some(activeJob)) throw new Error(tr('closeWizard.running'))
    return post(`/api/cases/${slug}/archive?require_idle=true`, {})
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ['state'] }); qc.invalidateQueries({ queryKey: ['archives'] }); onClosed?.() } })
  const busy = prepare.isPending || retry.isPending || archive.isPending
  useEffect(() => {
    if (settings.isSuccess && !configured) setStep(3)
    else if (configured && jobs.isSuccess && step === 1 && !draft && !result && !prepare.isPending && !prepare.isError &&
      !preparing.current && !jobs.data.some(job => job.kind === 'opencti-export' && activeJob(job))) {
      preparing.current = true
      prepare.mutate()
    }
  }, [settings.isSuccess, configured, jobs.isSuccess, jobs.data, step, draft, result, prepare])
  const field = (label: string, value?: string) => <div><dt className="text-[12px] font-semibold text-[var(--muted)]">{label}</dt><dd className="mt-1 whitespace-pre-wrap break-words text-[13px]">{value || tr('wizard.unknown')}</dd></div>
  if (settings.isPending || !caseInfo) return <p role="status">{tr('common.loading')}</p>
  if (settings.error) return <CtiError error={settings.error} />
  return <section aria-label={tr('nav.report')} className="flex h-[calc(100dvh-80px)] min-h-[540px] flex-col gap-4 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-4">
    <header className="flex shrink-0 items-center justify-between gap-2"><h1 className="text-xl font-semibold">{tr('nav.report')}</h1><span className="text-[13px] text-[var(--muted)]">{caseInfo.name}</span></header>
    <CtiError error={prepare.error || retry.error || archive.error} />
    {step === 1 && !draft && <div className="space-y-3">
      {prepare.isError ? <Button onClick={() => prepare.mutate()}>{tr('common.retry')}</Button> : <p role="status">{tr('cti.previewUpdating')}</p>}
      <CtiError error={jobs.error} />
      {(prepare.isError || jobs.isError) && <Button onClick={() => setStep(3)}>{tr('closeWizard.skip')}</Button>}
    </div>}
    {draft && <div hidden={step !== 1 || Boolean(result)} className="min-h-0 flex-1"><OpenCtiExportDialog embedded slug={slug} caseInfo={caseInfo} initial={draft.data} initialOptions={draft.options} onClose={onExit || (() => {})} onQueued={acceptResult} onSkipTransfer={() => setStep(3)} /></div>}
    {step === 2 && result && <>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto">
        <h2 className="flex items-center gap-2 text-lg font-semibold">{successful ? <CheckCircle2 className="text-[var(--ok)]" size={20} /> : settled ? <TriangleAlert className="text-[var(--review-text)]" size={20} /> : <LoaderCircle className="animate-spin" size={20} />}{tr(successful ? 'closeWizard.success' : settled ? 'closeWizard.incomplete' : 'closeWizard.transferring')}</h2>
        <p className="text-[13px]">{currentJob?.message || tr('closeWizard.wait')}</p>
        {!settled && <progress aria-label={tr('ctiActivity.progress')} max={1} value={currentJob?.progress ?? 0} className="h-2 w-full accent-[var(--accent)]" />}
        <CtiError error={currentJob?.error || receipt?.error || jobs.error || status.error} />
        {receipt && <p className="text-[13px] text-[var(--muted)]">{successful ? <OpenCtiReceipt counts={receipt.stats.counts} caseUrl={receipt.case_url} /> : <>{tr('ctiActivity.transfer', { n: Number(receipt.stats?.objects ?? 0) })} · {receipt.state}</>}</p>}
        {settled && !successful && receiptId && <Button disabled={busy} onClick={() => retry.mutate()}>{tr('cti.retry')}</Button>}
      </div>
      <footer className="flex shrink-0 justify-end gap-2 border-t border-[var(--line)] pt-3"><Button disabled={busy} onClick={onExit}>{tr('closeWizard.leave')}</Button><Button variant="primary" disabled={!settled || busy} onClick={() => setStep(3)}>{tr(successful ? 'wizard.next' : 'closeWizard.continueIncomplete')}</Button></footer>
    </>}
    {step === 3 && <>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto">
        <h2 className="text-lg font-semibold">{tr('closeWizard.step.close')}</h2>
        <p className="text-[13px]">{tr(result ? successful ? 'closeWizard.transferredClose' : 'closeWizard.incompleteClose' : 'closeWizard.skippedClose')}</p>
        <p className="text-[13px] text-[var(--muted)]">{tr('evidence.close.sub')}</p>
        {summary.data && <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">{field(tr('nav.findings'), String(summary.data.artifacts ?? summary.data.findings))}{field(tr('triage.confirmed'), String(summary.data.confirmed))}{field(tr('cti.iocs'), String(summary.data.iocs))}{field(tr('nav.evidence'), String(summary.data.evidence.length))}</dl>}
        <CtiError error={jobs.error || summary.error || (active ? tr('closeWizard.running') : null)} />
        <label className="block text-[13px]">{tr('evidence.close.typeName')}: <strong>{caseInfo.name}</strong><input aria-label={tr('closeWizard.confirmName')} className="mt-2 block w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2" autoComplete="off" disabled={archive.isPending} value={typed} onChange={event => setTyped(event.target.value)} /></label>
      </div>
      <footer className="flex shrink-0 flex-wrap justify-end gap-2 border-t border-[var(--line)] pt-3"><Button disabled={busy} onClick={() => result ? setStep(2) : configured ? setStep(1) : onExit?.()}>{tr('wizard.back')}</Button><Button disabled={busy} onClick={onExit}>{tr('closeWizard.keepOpen')}</Button><Button variant="danger" disabled={busy || active || !jobs.isSuccess || !summary.isSuccess || typed.trim() !== caseInfo.name.trim()} onClick={() => archive.mutate()}><Archive size={14} />{tr('evidence.close.cta')}</Button></footer>
    </>}
  </section>
}
