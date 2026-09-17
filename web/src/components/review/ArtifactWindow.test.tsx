// Artifact review preserves stored notes while exposing only decisions and file classifications.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  api, post, type ArtifactContext, type FileContent, type Finding, type SettingsInfo, type TriageResult,
} from '../../api'
import { renderWithProviders, testQueryClient } from '../../test/setup'
import { ArtifactWindow, type ArtifactStub } from './ArtifactWindow'

// The network is cut at the api layer rather than at `fetch`. A test that
// stubs `fetch` is also testing the URL builder, the token header and the
// error mapping, and a change to any of those breaks tests about the note
// box for no reason the name of the test would explain.
vi.mock('../logview/TraceWindow', () => ({ TraceWindow: () => <div>Embedded trace</div> }))

vi.mock('../../api', async (orig) => ({
  ...(await orig<typeof import('../../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))
vi.mock('../../geo', () => ({ useGeo: () => null }))

const SHELL = '/var/www/Images/shell.php'

function stub(over: Partial<ArtifactStub> = {}): ArtifactStub {
  return {
    artifact: SHELL,
    artifact_kind: 'file',
    worst: 0,
    triage: 'new',
    // What the seven call sites hand in. The whole point is that this is a
    // placeholder and not a fact about the artifact.
    triage_note: '',
    ...over,
  }
}

function context(over: Partial<ArtifactContext> = {}): ArtifactContext {
  return {
    artifact: SHELL,
    kind: 'file',
    findings: [],
    triage: 'new',
    triage_note: '',
    triaged_at: '',
    worst: 0,
    sources: ['webshell'],
    related_ips: [],
    ...over,
  }
}

const NO_COLLECTED: TriageResult['collected'] = []
const SAVED: TriageResult = {
  updated: 1,
  artifacts: 1,
  collected: [],
  linked: [],
  suggested: [],
  retained_iocs: [],
}

/** The window with everything but the artifact and the triage callback held
 *  fixed -- those two are what the tests here are about. */
function window_(artifact: ArtifactStub | null,
                 onSave: (state: 'reviewed' | 'confirmed' | 'dismissed', note: string) =>
                   Promise<TriageResult> = async () => SAVED,
                 onSavedNext?: (result: TriageResult) => void,
                 onClose = () => {}) {
  return (
    <ArtifactWindow
      slug="case" artifact={artifact} roots={[]} collected={NO_COLLECTED}
      onClose={onClose} onSave={onSave} onSavedNext={onSavedNext} onView={() => {}}
      onTrace={() => {}} />
  )
}

function mount(artifact: ArtifactStub | null = stub(), queue = false) {
  const onSave = vi.fn().mockResolvedValue(SAVED)
  const onSavedNext = queue ? vi.fn() : undefined
  const onClose = vi.fn()
  return {
    onSave, onSavedNext, onClose,
    ...renderWithProviders(window_(artifact, onSave, onSavedNext, onClose), testQueryClient()),
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(post).mockResolvedValue({})
})

describe('case review progress', () => {
  it('shows full-case totals and refreshes after saved decisions without losing a draft', async () => {
    const initial = context({ review_progress: { total: 2500, reviewed: 1700, remaining: 800, skipped: 2 } })
    vi.mocked(api).mockResolvedValue(initial)
    const qc = testQueryClient()
    renderWithProviders(window_(stub()), qc)
    const bar = await screen.findByRole('progressbar', { name: 'Case review' })
    expect(bar).toHaveAttribute('aria-valuemax', '2500')
    expect(bar).toHaveAttribute('aria-valuenow', '1700')
    expect(bar).toHaveAttribute('aria-valuetext', expect.stringMatching(/1,700.*2,500 reviewed.*800 remaining/))
    await userEvent.click(screen.getByRole('button', { name: 'Dropper' }))

    vi.mocked(api).mockResolvedValue(context({
      review_progress: { total: 2500, reviewed: 1701, remaining: 799, skipped: 2 },
    }))
    await act(async () => { await qc.invalidateQueries({ queryKey: ['artifact', 'case'] }) })
    await waitFor(() => expect(bar).toHaveAttribute('aria-valuenow', '1701'))
    expect(screen.getByRole('button', { name: 'Dropper' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('does not advance when a decision is only selected or fails to save', async () => {
    vi.mocked(api).mockResolvedValue(context({
      review_progress: { total: 10, reviewed: 4, remaining: 6, skipped: 1 },
    }))
    const { onSave } = mount()
    onSave.mockRejectedValue(new Error('Could not save'))
    const bar = await screen.findByRole('progressbar', { name: 'Case review' })
    const user = userEvent.setup()
    await user.click(screen.getByRole('radio', { name: 'False positive: Discard' }))
    expect(bar).toHaveAttribute('aria-valuenow', '4')
    await user.click(screen.getByRole('button', { name: 'Save decision' }))
    expect(await screen.findByText(/Could not save/)).toBeVisible()
    expect(bar).toHaveAttribute('aria-valuenow', '4')
  })

  it('shows completed review without suggesting every finding was harmless', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage: 'confirmed',
      review_progress: { total: 10, reviewed: 10, remaining: 0, skipped: 0 },
    }))
    mount()
    const bar = await screen.findByRole('progressbar', { name: 'Case review' })
    expect(bar).toHaveAttribute('aria-valuenow', '10')
    expect(bar).toHaveAttribute('aria-valuetext', '10 / 10 reviewed · 0 remaining')
    expect(screen.getByText('true positive')).toBeVisible()
  })

  it('does not present missing or failed counts as completed review', async () => {
    vi.mocked(api).mockRejectedValue(new Error('Context unavailable'))
    mount()
    await waitFor(() => expect(api).toHaveBeenCalled())
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    expect(screen.queryByText(/0 remaining/)).not.toBeInTheDocument()
  })
})

describe('artifact context and classification', () => {
  it.each(['file', 'table'] as const)('marks linked IPs already in this case IOC box and clears the cue after removal for %s', async kind => {
    const ip = { ip: '192.0.2.1', why: 'Synthetic relation', hits: 3, ok_hits: 1, in_box: false }
    const ctx = context({ kind, related_ips: [ip] })
    vi.mocked(api).mockResolvedValue(ctx)
    const { qc } = mount(stub({ artifact_kind: kind }))
    const tab = await screen.findByRole('tab', { name: kind === 'file' ? 'Linked IPs · 1' : 'Related objects · 1' })
    expect(tab).not.toHaveAttribute('title')
    await act(async () => { qc.setQueryData(['artifact', 'case', SHELL], { ...ctx, related_ips: [{ ...ip, in_box: true }] }) })
    expect(tab).toHaveAttribute('title', 'Includes IP addresses already in the IOC box.')
    await userEvent.click(tab)
    expect(tab).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel', { name: 'Linked IPs' })).toBeVisible()
    expect(tab).toHaveAttribute('title', 'Includes IP addresses already in the IOC box.')
    await act(async () => { qc.setQueryData(['artifact', 'case', SHELL], ctx) })
    await waitFor(() => expect(tab).not.toHaveAttribute('title'))
  })

  it.each(['file', 'client', 'table', 'dump'] as const)('removes analyst reasoning for %s and preserves the stored note on save', async kind => {
    vi.mocked(api).mockResolvedValue(context({ kind, triage_note: 'Historical analyst note', file: kind === 'file' ? { exists: true } : undefined }))
    const { onSave } = mount(stub({ artifact_kind: kind }))
    const decision = screen.getByRole('radio', { name: 'Skip for now' })
    await waitFor(() => expect(decision).toBeEnabled())
    expect(screen.queryByText('Optional analyst reasoning')).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText(/Reasoning/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    await userEvent.click(decision)
    await userEvent.click(screen.getByRole('button', { name: 'Save decision' }))
    expect(onSave).toHaveBeenCalledWith('reviewed', 'Historical analyst note', ...(kind === 'file' ? [['webshell']] : []))
  })

  it('preserves the latest stored note after the context is refreshed', async () => {
    vi.mocked(api).mockResolvedValue(context({ kind: 'client', triage_note: 'Original note' }))
    const { qc, onSave } = mount(stub({ artifact_kind: 'client' }))
    const decision = screen.getByRole('radio', { name: 'Skip for now' })
    await waitFor(() => expect(decision).toBeEnabled())
    await userEvent.click(decision)
    await act(async () => {
      qc.setQueryData(['artifact', 'case', SHELL], context({ kind: 'client', triage_note: 'Updated elsewhere' }))
    })
    await userEvent.click(screen.getByRole('button', { name: 'Save decision' }))
    expect(onSave).toHaveBeenCalledWith('reviewed', 'Updated elsewhere')
  })

  it.each([
    { slug: 'case', artifact: '/evidence/another-item' },
    { slug: 'other-case', artifact: SHELL },
  ])('waits for the new context when switching to $slug / $artifact', async next => {
    vi.mocked(api).mockResolvedValue(context({ kind: 'client', triage_note: 'First note' }))
    const { rerender, onSave } = mount(stub({ artifact_kind: 'client' }))
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeEnabled())
    let release: (value: ArtifactContext) => void = () => {}
    vi.mocked(api).mockImplementation(() => new Promise<ArtifactContext>(resolve => { release = resolve }))
    rerender(<ArtifactWindow slug={next.slug} artifact={stub({ artifact_kind: 'client', artifact: next.artifact })}
      roots={[]} collected={[]} onSave={onSave} onClose={() => {}} onView={() => {}} onTrace={() => {}} />)
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeDisabled()
    fireEvent.keyDown(window, { key: '1' })
    fireEvent.keyDown(window, { key: 'Enter' })
    expect(onSave).not.toHaveBeenCalled()
    await act(async () => release(context({ kind: 'client', artifact: next.artifact, triage_note: 'Second note' })))
    await userEvent.click(screen.getByRole('radio', { name: 'Skip for now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save decision' }))
    expect(onSave).toHaveBeenCalledWith('reviewed', 'Second note')
  })

  it('keeps reasons compact, focuses the selected code and preserves drafts across the IP tab', async () => {
    const finding: Finding = {
      id: 1, fingerprint: 'first', artifact: SHELL, artifact_kind: 'file' as const,
      source: 'webshell' as const, rule: 'Synthetic first rule', severity: 0,
      evidence: 'Duplicate code excerpt', line: 2, retired: 0, last_seen: '', created: '',
      triage: 'new' as const, triage_note: '',
    }
    const ctx = context({
      findings: [finding, { ...finding, id: 2, fingerprint: 'second', rule: 'Synthetic distant rule', line: 90 }],
      file: { exists: true, hashes: { sha256: '3'.repeat(64) }, preview: { lines: ['safe first line', 'safe second line'], from_line: 1, focus: 2 } },
      related_ips: [{ ip: '192.0.2.1', why: 'Requested the exact file path', hits: 3, ok_hits: 1, in_box: true,
        first_epoch: 1000, last_epoch: 2000 }],
    })
    vi.mocked(api).mockImplementation(async path => path.includes('/file-preview?')
      ? { from_line: 90, focus: 90, lines: ['safe distant line'] }
      : path.includes('/file?') ? { mode: 'raw', size: 1000, offset: 0, length: 1000, window: 262144, eof: true, from_line: 1, lines: Array.from({length: 90}, (_, i) => i === 89 ? 'safe distant line' : i === 1 ? 'safe second line' : `safe line ${i + 1}`) } : ctx)
    const onTrace = vi.fn()
    renderWithProviders(<ArtifactWindow slug="case" artifact={stub()} roots={[]} collected={[]}
      onSave={async () => SAVED} onClose={() => {}} onView={() => {}} onTrace={onTrace} />)
    await screen.findByRole('tab', { name: 'Findings · 2' })
    expect(screen.queryByText('Duplicate code excerpt')).not.toBeInTheDocument()
    expect(screen.queryByText(/Historical results remain available/)).not.toBeInTheDocument()
    const distant = screen.getByRole('button', { name: /Synthetic distant rule/ })
    expect(distant).toHaveAttribute('aria-expanded', 'false')
    await userEvent.click(distant)
    expect((await screen.findAllByText('safe distant line')).length).toBe(2)
    expect(screen.getAllByText('safe distant line').some(el => el.parentElement?.getAttribute('data-focus-line') === '90')).toBe(true)
    expect(distant).toHaveAttribute('aria-expanded', 'true')
    expect(screen.queryByText('Duplicate code excerpt')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('radio', { name: 'Skip for now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Dropper' }))
    await userEvent.click(screen.getByRole('tab', { name: 'Linked IPs · 1' }))
    const ips = screen.getByRole('tabpanel', { name: 'Linked IPs' })
    expect(within(ips).getByText('192.0.2.1')).toBeVisible()
    expect(within(ips).getByText('3 matching requests')).toBeVisible()
    expect(within(ips).queryByText(/First request/)).not.toBeInTheDocument()
    expect(within(ips).getByRole('table')).toBeVisible()
    await userEvent.click(within(ips).getByRole('button', { name: 'Trace' }))
    expect(onTrace).toHaveBeenCalledWith(['192.0.2.1'], expect.objectContaining({ contains: [SHELL] }))
    await userEvent.click(screen.getByRole('tab', { name: 'Findings · 2' }))
    expect(screen.getByRole('button', { name: 'Dropper' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeChecked()
    expect(screen.getByText('safe distant line')).toBeVisible()
    await userEvent.click(screen.getByRole('button', { name: /Synthetic first rule/ }))
    await waitFor(() => expect(screen.getAllByText('safe second line').some(el => el.parentElement?.getAttribute('data-focus-line') === '2')).toBe(true))
    expect(vi.mocked(api).mock.calls.filter(([url]) => url.includes('/file-preview?'))).toHaveLength(1)
  })

  it('enables decisions after an intentionally empty server note has loaded', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: '' }))
    mount()

    await waitFor(() =>
      expect(screen.getByRole('radio', { name: /True positive: Collect/i })).toBeEnabled())
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeEnabled()
    expect(screen.getByRole('radio', { name: 'False positive: Discard' })).toBeEnabled()
  })



  it('keeps the decision and save action after a changed context and stub refresh', async () => {
    vi.mocked(api).mockResolvedValue(context({ worst: 1 }))
    const { qc, rerender } = mount(stub({ artifact_kind: 'client' }))
    await userEvent.click(await screen.findByRole('radio', { name: 'Skip for now' }))
    await act(async () => {
      qc.setQueryData(['artifact', 'case', SHELL], context({ worst: 0 }))
    })
    // Wait for the actual query rerender, not just the cache write.
    expect(await screen.findByText('HIGH')).toBeVisible()
    rerender(window_(stub({ artifact_kind: 'client', worst: 0 })))
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeChecked()
    expect(screen.getByRole('button', { name: 'Save decision' })).toBeEnabled()
  })




})

describe('deliberate decision submission', () => {
  function fileLookup({ configured = false, keyAvailable = true, hash = 'a'.repeat(64) } = {}) {
    vi.mocked(api).mockImplementation(async path => {
      if (path === '/api/opencti/settings') return { configured } as never
      if (path === '/api/settings') return { services: { virustotal: { configured: keyAvailable } } } as never
      if (path.endsWith('/enrichment')) return { entries: [] } as never
      return context({ file: { exists: false, hashes: { sha256: hash } } }) as never
    })
    return mount()
  }

  it('asks and refreshes VirusTotal with V without repeated requests or changing the decision', async () => {
    const { onSave } = fileLookup()
    fireEvent.keyDown(window, { key: 'v' })
    expect(post).not.toHaveBeenCalled()
    const button = await screen.findByRole('button', { name: 'Ask VirusTotal' })
    await waitFor(() => expect(button).toBeEnabled())
    expect(button).toHaveAttribute('aria-keyshortcuts', 'V')
    await userEvent.click(screen.getByRole('radio', { name: 'Skip for now' }))
    let finish!: (value: unknown) => void
    vi.mocked(post).mockImplementation(() => new Promise(resolve => { finish = resolve }))
    act(() => {
      fireEvent.keyDown(window, { key: 'v' })
      fireEvent.keyDown(window, { key: 'v' })
      fireEvent.keyDown(window, { key: 'v', repeat: true })
    })
    await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/enrich', {
      service: 'virustotal', kind: 'hash', value: 'a'.repeat(64), refresh: false,
    }))
    fireEvent.keyDown(window, { key: 'v' })
    expect(post).toHaveBeenCalledTimes(1)
    const report = { service: 'virustotal', kind: 'hash', value: 'a'.repeat(64), fetched: '2026-09-17T12:00:00Z', result: { known: true, score: 0, of: 72 } }
    await act(async () => finish(report))
    expect(await screen.findByRole('button', { name: 'Refresh VirusTotal' })).toBeEnabled()
    vi.mocked(post).mockResolvedValue(report)
    fireEvent.keyDown(window, { key: 'v' })
    await waitFor(() => expect(post).toHaveBeenLastCalledWith('/api/cases/case/enrich', expect.objectContaining({ refresh: true })))
    expect(onSave).not.toHaveBeenCalled()
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeChecked()
  })

  it('ignores V while typing, with modifiers, during composition, and behind another dialog', async () => {
    const { unmount } = fileLookup()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Ask VirusTotal' })).toBeEnabled())
    for (const flag of ['ctrlKey', 'metaKey', 'shiftKey', 'altKey', 'repeat', 'isComposing']) {
      fireEvent.keyDown(window, { key: 'v', [flag]: true })
    }
    const input = document.createElement('textarea')
    screen.getByRole('dialog').append(input)
    fireEvent.keyDown(input, { key: 'v' })
    input.remove()
    const overlay = document.createElement('div')
    overlay.setAttribute('role', 'dialog')
    document.body.append(overlay)
    fireEvent.keyDown(window, { key: 'v' })
    overlay.remove()
    expect(post).not.toHaveBeenCalled()
    unmount()
    fireEvent.keyDown(window, { key: 'v' })
    expect(post).not.toHaveBeenCalled()
  })

  it.each([
    { configured: true }, { keyAvailable: false }, { hash: 'invalid-hash' },
  ])('does not bypass unavailable direct lookup settings with V: %j', async settings => {
    fileLookup(settings)
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeEnabled())
    fireEvent.keyDown(window, { key: 'v' })
    expect(post).not.toHaveBeenCalled()
  })

  it('scrolls the active pane with held arrow keys without changing the decision', async () => {
    vi.mocked(api).mockImplementation(async url => url.includes('/file?')
      ? { mode: 'raw', size: 20, offset: 0, length: 20, window: 262144, eof: true, from_line: 1, lines: ['Safe preview'] }
      : context({ file: { exists: true, preview: { lines: ['Safe preview'], from_line: 1 } } }))
    mount()
    const code = await screen.findByRole('region', { name: 'File content' })
    Object.defineProperties(code, {
      scrollHeight: { value: 1000 }, clientHeight: { value: 200 },
      scrollWidth: { value: 1000 }, clientWidth: { value: 300 },
    })
    await userEvent.click(screen.getByRole('radio', { name: 'Skip for now' }))
    fireEvent.pointerOver(code)
    fireEvent.keyDown(window, { key: 'ArrowDown' })
    fireEvent.keyDown(window, { key: 'ArrowDown', repeat: true })
    expect(code.scrollTop).toBe(96)
    fireEvent.keyDown(window, { key: 'ArrowUp' })
    expect(code.scrollTop).toBe(48)
    fireEvent.keyDown(window, { key: 'ArrowRight' })
    expect(code.scrollLeft).toBe(48)
    fireEvent.keyDown(window, { key: 'ArrowLeft' })
    expect(code.scrollLeft).toBe(0)
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeChecked()
    const metadata = screen.getByText('File').closest('[data-artifact-scroll]') as HTMLElement
    Object.defineProperties(metadata, { scrollHeight: { value: 900 }, clientHeight: { value: 200 } })
    fireEvent.pointerOver(metadata)
    fireEvent.keyDown(window, { key: 'ArrowDown' })
    expect(metadata.scrollTop).toBe(48)
    expect(code.scrollTop).toBe(48)
    code.scrollTop = 800
    fireEvent.focus(code)
    fireEvent.keyDown(window, { key: 'ArrowDown' })
    expect(code.scrollTop).toBe(800)
    expect(metadata.scrollTop).toBe(48)
  })

  it('defaults files to Webshell, saves multiple tags and keeps historical notes', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'Existing historical note', file: { exists: true } }))
    const { onSave } = mount()
    const webshell = await screen.findByRole('button', { name: 'Webshell' })
    await waitFor(() => expect(webshell).toBeEnabled())
    expect(webshell).toHaveAttribute('aria-pressed', 'true')
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Dropper' }))
    await userEvent.keyboard('1')
    expect(onSave).not.toHaveBeenCalled()
    await userEvent.keyboard('{Enter}')
    await waitFor(() => expect(onSave).toHaveBeenCalledWith('confirmed', 'Existing historical note', ['webshell', 'dropper'], true))
  })

  it('restores saved classifications including an empty selection and resets between artifacts', async () => {
    vi.mocked(api).mockResolvedValue(context({ file: { exists: true, classifications: ['seo-spam'] } }))
    const { rerender } = mount()
    await waitFor(() => expect(screen.getByRole('button', { name: 'SEO-Spam' })).toHaveAttribute('aria-pressed', 'true'))
    expect(screen.getByRole('button', { name: 'Webshell' })).toHaveAttribute('aria-pressed', 'false')
    const other = '/var/www/other.txt'
    vi.mocked(api).mockResolvedValue(context({ artifact: other, file: { exists: true, classifications: [] } }))
    rerender(window_(stub({ artifact: other })))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Webshell' })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Webshell' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByRole('button', { name: 'SEO-Spam' })).toHaveAttribute('aria-pressed', 'false')
  })

  it('supports file expansion, three decisions, save-next and save-close without duplicate saves', async () => {
    const ctx = context({ file: { exists: true, classifications: ['dropper'] } })
    vi.mocked(api).mockImplementation(async path => path.includes('/file?') ? {
      path: SHELL, mode: 'raw', size: 12, window: 262144, offset: 0, length: 12,
      eof: true, binary: false, hashes: {}, hashes_limited: false, from_line: 1, lines: ['safe preview'],
    } : ctx)
    const { onSave, onSavedNext, onClose } = mount(stub(), true)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Dropper' })).toBeEnabled())
    await userEvent.keyboard('f')
    expect(await screen.findByRole('button', { name: 'Back to evidence' })).toBeVisible()
    const expandedCode = (await screen.findByText('safe preview')).closest('pre')!
    Object.defineProperties(expandedCode, { scrollHeight: { value: 1000 }, clientHeight: { value: 200 } })
    fireEvent.keyDown(window, { key: 'ArrowDown' })
    expect(expandedCode.scrollTop).toBe(48)
    await userEvent.keyboard('f')
    expect(screen.getByRole('tab', { name: 'Findings · 0' })).toBeVisible()
    await userEvent.keyboard('1')
    expect(screen.getByRole('radio', { name: /True positive: Collect/ })).toBeChecked()
    await userEvent.keyboard('2')
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeChecked()
    await userEvent.keyboard('3')
    expect(screen.getByRole('radio', { name: 'False positive: Discard' })).toBeChecked()
    let resolveSave: (value: TriageResult) => void = () => {}
    onSave.mockImplementationOnce(() => new Promise<TriageResult>(resolve => { resolveSave = resolve }))
    fireEvent.keyDown(window, { key: 'Enter' })
    fireEvent.keyDown(window, { key: 'Enter' })
    fireEvent.keyDown(window, { key: 'Enter', repeat: true })
    expect(onSave).toHaveBeenCalledTimes(1)
    await act(async () => resolveSave(SAVED))
    expect(onSavedNext).toHaveBeenCalledOnce()
    await userEvent.keyboard('2{Control>}{Shift>}{Enter}{/Shift}{/Control}')
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
  })

  it('ignores decision shortcuts while loading context or composing input', async () => {
    let resolveContext: (value: ArtifactContext) => void = () => {}
    vi.mocked(api).mockImplementation(() => new Promise<ArtifactContext>(resolve => { resolveContext = resolve }))
    const { onSave } = mount(stub({ artifact_kind: 'client' }))
    fireEvent.keyDown(window, { key: '1' })
    expect(screen.getByRole('radio', { name: /True positive: Collect/ })).not.toBeChecked()
    await act(async () => resolveContext(context()))
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeEnabled())
    expect(screen.getByRole('radio', { name: /True positive: Collect/ })).not.toBeChecked()
    fireEvent.keyDown(window, { key: '1', isComposing: true })
    expect(onSave).not.toHaveBeenCalled()
  })

  it('keeps the selectors exclusive and submits only from Save & next', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'initial note' }))
    const { onSave, onSavedNext } = mount(stub({ artifact_kind: 'client' }), true)

    const confirmed = await screen.findByRole('radio', { name: /True positive: Collect/i })
    const reviewed = screen.getByRole('radio', { name: 'Skip for now' })
    await userEvent.click(confirmed)
    await userEvent.click(reviewed)

    expect(confirmed).not.toBeChecked()
    expect(reviewed).toBeChecked()
    expect(onSave).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Save & next' }))

    await waitFor(() => expect(onSave).toHaveBeenCalledWith(
      'reviewed', 'initial note'))
    expect(onSavedNext).toHaveBeenCalledWith(SAVED)
  })

  it('waits for Save & close to succeed before closing', async () => {
    vi.mocked(api).mockResolvedValue(context())
    let finish: ((result: TriageResult) => void) | undefined
    const pending = new Promise<TriageResult>((resolve) => { finish = resolve })
    const onSave = vi.fn().mockReturnValue(pending)
    const onClose = vi.fn()
    renderWithProviders(window_(stub({ artifact_kind: 'client' }), onSave, undefined, onClose), testQueryClient())

    await userEvent.click(await screen.findByRole('radio', { name: 'Skip for now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save & close' }))
    expect(onClose).not.toHaveBeenCalled()

    await act(async () => { finish?.(SAVED); await pending })
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
  })

  it('retains the selected decision and stored note after a failed save', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'known maintenance helper' }))
    const { onSave } = mount(stub({ artifact_kind: 'client' }))
    onSave.mockRejectedValueOnce(new Error('local request failed'))

    const dismissed = await screen.findByRole('radio', { name: 'False positive: Discard' })
    await userEvent.click(dismissed)
    await userEvent.click(screen.getByRole('button', { name: 'Save decision' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/local request failed/i)
    expect(dismissed).toBeChecked()
    expect(onSave).toHaveBeenCalledWith('dismissed', 'known maintenance helper')
  })

  it('closes without saving when no draft is submitted', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'leave this untouched' }))
    const { onSave, onClose } = mount(stub({ artifact_kind: 'client' }))

    await waitFor(() => expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeEnabled())
    await userEvent.click(screen.getByRole('button', { name: /Close \(Esc\)/i }))

    expect(onClose).toHaveBeenCalledOnce()
    expect(onSave).not.toHaveBeenCalled()
  })
})

describe('what the window states about the artifact', () => {
  it('shows the recorded UTC modification time, with relative time available on focus', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-09-17T12:00:00Z'))
    vi.mocked(api).mockResolvedValue(context({ file: {
      exists: true, mtime: '2026-06-17T14:00:00', modified_at: '2026-06-17T12:00:00Z',
    } }))
    mount()
    const stamp = await screen.findByText('2026-06-17 12:00:00 UTC')
    expect(stamp).toHaveAttribute('datetime', '2026-06-17T12:00:00Z')
    expect(screen.queryByText('3 months ago')).not.toBeInTheDocument()
    await userEvent.click(stamp.parentElement!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('3 months ago')
    const help = screen.getByLabelText('About review decisions')
    await userEvent.click(help)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Skip for now keeps the artifact open')
  })

  it('shows all available forensic file hashes in full', async () => {
    const artifactContext = context({
      file: {
        exists: true,
        size: 42,
        mtime: '2026-08-28T10:00:00',
        hashes: {
          md5: '1'.repeat(32),
          sha1: '2'.repeat(40),
          sha256: '3'.repeat(64),
        },
      },
    })
    const settings: SettingsInfo = { services: {}, enrichment_ack: false, path: '' }
    vi.mocked(api).mockImplementation(async (path: string) =>
      (path === '/api/settings' ? settings : artifactContext) as never)

    mount()

    expect(await screen.findByText('1'.repeat(32))).toBeInTheDocument()
    expect(screen.getByText('2'.repeat(40))).toBeInTheDocument()
    expect(screen.getByText('3'.repeat(64))).toBeInTheDocument()
  })

  it('expands the inert paged viewer inside the same review window', async () => {
    const artifactContext = context({
      file: { exists: true, size: 15, preview: { binary: false, lines: ['safe text'], from_line: 1 } },
    })
    const fileContent: FileContent = {
      path: SHELL, size: 15, offset: 0, length: 15, eof: true, mode: 'raw', window: 262144,
      binary: false, created_at: null, modified_at: null, accessed_at: null, changed_at: null,
      hashes: {}, hashes_limited: false, from_line: 1, lines: ['safe text'],
    }
    vi.mocked(api).mockImplementation(async (path: string) =>
      (path.includes('/file?') ? fileContent : artifactContext) as never)

    const { qc } = mount()
    await userEvent.click((await screen.findAllByRole('button', { name: 'Expand file' }))[0])

    expect(await screen.findByRole('button', { name: 'Back to evidence' })).toBeVisible()
    expect(await screen.findByText('safe text')).toBeVisible()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.getByText('safe text').closest('[data-expanded-file-viewer]')).not.toBeNull()
    expect(screen.getByText('File classification')).toBeVisible()
    expect(screen.getByRole('radio', { name: 'Skip for now' })).toBeVisible()
    await act(async () => {
      qc.setQueryData(['artifact', 'case', SHELL], { ...artifactContext, worst: 1 })
    })
    expect(await screen.findByText('MEDIUM')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Back to evidence' })).toBeVisible()
  })

  it('does not open unavailable evidence through either buttons or the keyboard', async () => {
    vi.mocked(api).mockResolvedValue(context({
      file: { exists: true, available: false, unavailable_reason: 'Evidence source is no longer registered.' },
    }))
    mount()
    expect(await screen.findByText('Evidence source is no longer registered.')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Expand file' })).not.toBeInTheDocument()
    fireEvent.keyDown(window, { key: 'f' })
    expect(screen.queryByRole('button', { name: 'Back to evidence' })).not.toBeInTheDocument()
    expect(vi.mocked(api).mock.calls.some(([url]) => url.includes('/file?') || url.includes('/file-preview?'))).toBe(false)
  })

  it('offers a hash lookup in file context before collection, without an Enrichment tab', async () => {
    vi.mocked(api).mockImplementation(async path => {
      if (path === '/api/opencti/settings') return { configured: false } as never
      if (path === '/api/settings') return { services: { virustotal: { configured: true } } } as never
      return context({ file: { exists: true, sha256: 'a'.repeat(64) } }) as never
    })
    mount()
    const lookup = await screen.findByRole('button', { name: 'Ask VirusTotal' })
    expect(lookup).toBeEnabled()
    expect(within(screen.getByRole('complementary')).getByRole('button', { name: 'Ask VirusTotal' })).toBe(lookup)
    expect(screen.queryByRole('tab', { name: 'Enrichment' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('reveals explicitly and never starts enrichment on mount', async () => {
    const artifactContext = context({
      file: { exists: true, size: 42, sha256: 'a'.repeat(64) },
    })
    const settings: SettingsInfo = {
      enrichment_ack: true, path: '',
      services: {
        virustotal: { configured: true, hint: '', sends: 'SHA-256', url: '' },
      },
    }
    vi.mocked(api).mockImplementation(async (path: string) =>
      (path === '/api/settings' ? settings : artifactContext) as never)

    mount()
    expect(await screen.findByText('a'.repeat(64))).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Open IOC Box' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Open…' }))
    await userEvent.click(screen.getByRole('button', { name: 'Show in file manager' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      '/api/cases/case/reveal-file', { path: SHELL }))
    expect(vi.mocked(post).mock.calls.some(([url]) => String(url).includes('/enrich'))).toBe(false)
  })

  it('prefers the server triage state over the stub the caller guessed', async () => {
    // Actors opens this window knowing only an IP; it guesses `new`. If the
    // window believed the guess, an artifact already ruled a false positive
    // would present itself as undecided.
    vi.mocked(api).mockResolvedValue(context({ triage: 'dismissed' }))
    mount(stub({ triage: 'new' }))

    await waitFor(() => expect(screen.getByText('false positive')).toBeInTheDocument())
  })

  it('places evidence before classification and decisions', async () => {
    vi.mocked(api).mockResolvedValue(context({
      findings: [{
        id: 1, fingerprint: 'synthetic-finding', artifact: SHELL, artifact_kind: 'file',
        source: 'webshell', rule: 'Synthetic review rule', severity: 0,
        evidence: 'Harmless synthetic evidence marker', line: 12, retired: 0, last_seen: '', created: '',
        triage: 'new', triage_note: '',
      }],
    }))

    mount()
    const evidenceHeading = await screen.findByRole('tab', { name: /Findings/ })
    const reasoningHeading = screen.getByText('File classification')

    expect(evidenceHeading.compareDocumentPosition(reasoningHeading) & Node.DOCUMENT_POSITION_FOLLOWING)
      .toBeTruthy()
  })

  it('renders nothing at all when no artifact is open', () => {
    // The parent keeps the window mounted with `artifact={null}`. A window
    // that painted a shell in that state would cover the view it was opened
    // from.
    vi.mocked(api).mockResolvedValue(context())
    const { container } = mount(null)
    expect(container).toBeEmptyDOMElement()
  })

  it('does not ask the server for a context it has no artifact for', () => {
    vi.mocked(api).mockResolvedValue(context())
    mount(null)
    expect(api).not.toHaveBeenCalled()
  })
})
