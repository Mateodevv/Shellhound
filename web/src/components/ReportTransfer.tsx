import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Archive, CheckCircle2, LoaderCircle, TriangleAlert } from 'lucide-react'
import { api, post, type CaseInfo, type CaseSummary, type Ioc, type Job } from '../api'
import { useT } from '../i18n'
import { initialExportOptions, openCtiKey, useOpenCtiSettings, type OpenCtiState, type OpenCtiOptions, type OpenCtiPreview } from '../opencti'
import { Button, Tag } from './ui'
import { CaseProfileButton, CtiError } from './CaseProfile'
import { OpenCtiExportDialog } from './OpenCtiExport'

const activeJob = (job: Job) => ['queued', 'running'].includes(job.state)
type TransferResult = { job_id: number; export_id?: string }

export function ReportTransfer({ slug, caseInfo, onClosed, onExit }: { slug: string; caseInfo?: CaseInfo; onClosed?: () => void; onExit?: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useOpenCtiSettings()
  const configured = settings.data?.configured === true
  const [step, setStep] = useState(0)
  const [includeTransfer, setIncludeTransfer] = useState(true)
  const [draft, setDraft] = useState<{ data: OpenCtiPreview; options: OpenCtiOptions } | null>(null)
  const [result, setResult] = useState<TransferResult | null>(null)
  const [typed, setTyped] = useState('')
  const jobs = useQuery({ queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`), refetchInterval: step >= 3 ? 2000 : false })
  const status = useQuery({ queryKey: openCtiKey(slug), queryFn: () => api<OpenCtiState>(`/api/cases/${slug}/opencti`), enabled: configured, refetchInterval: step >= 3 && configured ? 2000 : false })
  const summary = useQuery({ queryKey: ['close-summary', slug], queryFn: () => api<CaseSummary>(`/api/cases/${slug}/summary`), enabled: step === 4 })
  const active = jobs.data?.some(activeJob) ?? false
  const currentJob = jobs.data?.find(job => job.id === result?.job_id)
  const receiptId = result?.export_id || (typeof currentJob?.stats?.export_id === 'string' ? currentJob.stats.export_id : undefined)
  const receipt = configured ? status.data?.exports.find(entry => entry.id === receiptId) : undefined
  const settled = Boolean(currentJob && !activeJob(currentJob)) && !active && jobs.isSuccess
  const successful = settled && status.isSuccess && currentJob?.state === 'done' && receipt?.state === 'complete'
  const steps = configured && includeTransfer ? [0, 1, 2, 3, 4] : [0, 4]
  const names = ['context', 'iocs', 'samples', 'transfer', 'close']
  const acceptResult = (value: TransferResult) => {
    setResult(value); setStep(3)
    qc.invalidateQueries({ queryKey: openCtiKey(slug) }); qc.invalidateQueries({ queryKey: ['jobs', slug] })
  }
  // Reopening the page resumes monitoring an active transfer instead of submitting it again.
  useEffect(() => {
    const running = jobs.data?.find(job => job.kind === 'opencti-export' && activeJob(job))
    if (configured && running && !result) { setResult({ job_id: running.id }); setStep(3) }
  }, [jobs.data, configured, result])
  const prepare = useMutation({ mutationFn: async () => {
    const iocs = await api<Ioc[]>(`/api/cases/${slug}/iocs`)
    if (!iocs.length) throw new Error(tr('closeWizard.noIocs'))
    const options = initialExportOptions(iocs.map(ioc => ioc.id))
    return { options, data: await post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, options) }
  }, onSuccess: value => { setDraft(value); setStep(1) } })
  const retry = useMutation({ mutationFn: () => post<TransferResult>(`/api/cases/${slug}/opencti/retry`, { export_id: receiptId }), onSuccess: acceptResult })
  const archive = useMutation({ mutationFn: async () => {
    const latest = await jobs.refetch()
    if (latest.error) throw latest.error
    if (!latest.data || latest.data.some(activeJob)) throw new Error(tr('closeWizard.running'))
    return post(`/api/cases/${slug}/archive?require_idle=true`, {})
  }, onSuccess: () => { qc.invalidateQueries({ queryKey: ['state'] }); qc.invalidateQueries({ queryKey: ['archives'] }); onClosed?.() } })
  const busy = prepare.isPending || retry.isPending || archive.isPending
  const advance = () => {
    if (!configured || !includeTransfer) setStep(4)
    else if (draft) setStep(1)
    else prepare.mutate()
  }
  const field = (label: string, value?: string) => <div><dt className="text-[12px] font-semibold text-[var(--muted)]">{label}</dt><dd className="mt-1 whitespace-pre-wrap break-words text-[13px]">{value || tr('wizard.unknown')}</dd></div>
  if (settings.isPending || !caseInfo) return <p role="status">{tr('common.loading')}</p>
  if (settings.error) return <CtiError error={settings.error} />
  return <section aria-label={tr('nav.report')} className="flex h-[calc(100dvh-80px)] min-h-[540px] flex-col gap-4 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-4">
    <header className="flex shrink-0 items-center justify-between gap-2"><h1 className="text-xl font-semibold">{tr('nav.report')}</h1><Tag>{caseInfo.reference || caseInfo.name}</Tag></header>
    <nav aria-label={tr('closeWizard.steps')} className="shrink-0 border-b border-[var(--line)] pb-3"><ol className="flex flex-wrap gap-2">{steps.map((index, position) => <li key={index}><button type="button" aria-current={step === index ? 'step' : undefined} disabled={busy || index > step || Boolean(result) && index < 3} onClick={() => setStep(index)} className={`ui-press flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] ${index === step ? 'bg-[var(--accent-soft)] font-semibold text-[var(--accent-text)]' : 'text-[var(--muted)] disabled:opacity-50'}`}><span className="flex h-5 w-5 items-center justify-center rounded-full border border-current text-[11px]">{position + 1}</span>{tr(`closeWizard.step.${names[index]}`)}</button></li>)}</ol></nav>
    <CtiError error={prepare.error || retry.error || archive.error} />
    {step === 0 && <>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-2">
        <div className="flex items-center justify-between gap-2"><h2 className="text-lg font-semibold">{caseInfo.name}</h2>{configured && <CaseProfileButton slug={slug} />}</div>
        <dl className="grid gap-4 sm:grid-cols-2">{field(tr('cti.caseId'), caseInfo.reference)}{field(tr('cti.marking'), caseInfo.profile?.marking)}<div className="sm:col-span-2">{field(tr('cti.summary'), caseInfo.profile?.summary || caseInfo.notes)}</div>{field(tr('cti.organizationName'), caseInfo.profile?.organization_name || caseInfo.profile?.pseudonym)}{field(tr('cti.sectors'), caseInfo.profile?.sectors.join(', '))}{field(tr('cti.country'), caseInfo.profile?.countries.join(', '))}{field(tr('cti.city'), caseInfo.profile?.city)}</dl>
        {configured && <label className="flex items-start gap-3 rounded-lg border border-[var(--line)] p-3 text-[13px]"><input type="checkbox" checked={includeTransfer} disabled={busy} onChange={event => setIncludeTransfer(event.target.checked)} /><span><strong>{tr('closeWizard.includeTransfer')}</strong><span className="mt-1 block text-[var(--muted)]">{tr('closeWizard.optional')}</span></span></label>}
        <p className="text-[13px] text-[var(--muted)]">{tr('closeWizard.intro')}</p>
      </div>
      <footer className="flex shrink-0 justify-end gap-2 border-t border-[var(--line)] pt-3"><Button disabled={busy} onClick={onExit}>{tr('closeWizard.leave')}</Button><Button variant="primary" disabled={busy} onClick={advance}>{prepare.isPending && <LoaderCircle size={14} className="animate-spin" />}{tr('wizard.next')}</Button></footer>
    </>}
    {draft && <div hidden={step === 0 || step === 4 || Boolean(result)} className="min-h-0 flex-1"><OpenCtiExportDialog embedded wizard activeStep={step} onStepChange={setStep} slug={slug} caseInfo={caseInfo} initial={draft.data} initialOptions={draft.options} onClose={onExit || (() => {})} onQueued={acceptResult} onSkipTransfer={() => setStep(4)} /></div>}
    {step === 3 && result && <>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto">
        <h2 className="flex items-center gap-2 text-lg font-semibold">{successful ? <CheckCircle2 className="text-[var(--ok)]" size={20} /> : settled ? <TriangleAlert className="text-[var(--review-text)]" size={20} /> : <LoaderCircle className="animate-spin" size={20} />}{tr(successful ? 'closeWizard.success' : settled ? 'closeWizard.incomplete' : 'closeWizard.transferring')}</h2>
        <p className="text-[13px]">{currentJob?.message || tr('closeWizard.wait')}</p>
        {!settled && <progress aria-label={tr('ctiActivity.progress')} max={1} value={currentJob?.progress ?? 0} className="h-2 w-full accent-[var(--accent)]" />}
        <CtiError error={currentJob?.error || receipt?.error || jobs.error || status.error} />
        {receipt && <p className="text-[13px] text-[var(--muted)]">{tr('ctiActivity.transfer', { n: Number(receipt.stats?.objects ?? 0) })} · {receipt.state}</p>}
        {settled && !successful && receiptId && <Button disabled={busy} onClick={() => retry.mutate()}>{tr('cti.retry')}</Button>}
      </div>
      <footer className="flex shrink-0 justify-end gap-2 border-t border-[var(--line)] pt-3"><Button disabled={busy} onClick={onExit}>{tr('closeWizard.leave')}</Button><Button variant="primary" disabled={!settled || busy} onClick={() => setStep(4)}>{tr(successful ? 'wizard.next' : 'closeWizard.continueIncomplete')}</Button></footer>
    </>}
    {step === 4 && <>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto">
        <h2 className="text-lg font-semibold">{tr('closeWizard.step.close')}</h2>
        <p className="text-[13px]">{tr(result ? successful ? 'closeWizard.transferredClose' : 'closeWizard.incompleteClose' : 'closeWizard.skippedClose')}</p>
        <p className="text-[13px] text-[var(--muted)]">{tr('evidence.close.sub')}</p>
        {summary.data && <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">{field(tr('nav.findings'), String(summary.data.artifacts ?? summary.data.findings))}{field(tr('triage.confirmed'), String(summary.data.confirmed))}{field(tr('cti.iocs'), String(summary.data.iocs))}{field(tr('nav.evidence'), String(summary.data.evidence.length))}</dl>}
        <CtiError error={jobs.error || summary.error || (active ? tr('closeWizard.running') : null)} />
        <label className="block text-[13px]">{tr('evidence.close.typeName')}: <strong>{caseInfo.name}</strong><input aria-label={tr('closeWizard.confirmName')} className="mt-2 block w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2" autoComplete="off" disabled={archive.isPending} value={typed} onChange={event => setTyped(event.target.value)} /></label>
      </div>
      <footer className="flex shrink-0 flex-wrap justify-end gap-2 border-t border-[var(--line)] pt-3"><Button disabled={busy} onClick={() => setStep(result ? 3 : draft && configured && includeTransfer ? 3 : 0)}>{tr('wizard.back')}</Button><Button disabled={busy} onClick={onExit}>{tr('closeWizard.keepOpen')}</Button><Button variant="danger" disabled={busy || active || !jobs.isSuccess || !summary.isSuccess || typed.trim() !== caseInfo.name.trim()} onClick={() => archive.mutate()}><Archive size={14} />{tr('evidence.close.cta')}</Button></footer>
    </>}
  </section>
}
