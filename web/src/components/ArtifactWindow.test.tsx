// ArtifactWindow.test.tsx -- the note box, which is where a decision is
// written down.
//
// THE DEFECT THIS FILE GUARDS. Seven of the places that open this window
// build the artifact stub by hand and cannot know the note; they hard-code
// `triage_note: ''`. A box seeded from the stub therefore showed an empty
// note next to an artifact that had one -- and because the triage buttons
// send whatever is in the box, the next click wrote that emptiness over the
// reasoning somebody had already recorded. Nothing on screen said so.
//
// The other half of the same problem is the correction: the box is filled
// from the server, so a later refetch must NOT re-fill it while the analyst
// is typing. Both halves are asserted here, because a fix for one that
// breaks the other is a fix that loses text either way.
import { describe, expect, it, vi } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, type ArtifactContext, type TriageResult } from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { ArtifactWindow, type ArtifactStub } from './ArtifactWindow'

// The network is cut at the api layer rather than at `fetch`. A test that
// stubs `fetch` is also testing the URL builder, the token header and the
// error mapping, and a change to any of those breaks tests about the note
// box for no reason the name of the test would explain.
vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

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

/** The window with everything but the artifact and the triage callback held
 *  fixed -- those two are what the tests here are about. */
function window_(artifact: ArtifactStub | null, onTriage = () => {}) {
  return (
    <ArtifactWindow
      slug="case" artifact={artifact} roots={[]} collected={NO_COLLECTED}
      onClose={() => {}} onTriage={onTriage} onView={() => {}}
      onTrace={() => {}} />
  )
}

function mount(artifact: ArtifactStub | null = stub()) {
  const onTriage = vi.fn()
  return { onTriage, ...renderWithProviders(window_(artifact, onTriage), testQueryClient()) }
}

const noteBox = () =>
  screen.getByPlaceholderText(/Reasoning/i) as HTMLTextAreaElement

describe('the note box', () => {
  it('enables decisions after an intentionally empty server note has loaded', async () => {
    vi.mocked(api).mockResolvedValue(context({ triage_note: '' }))
    mount()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Confirm & collect/i })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Reviewed' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'False positive' })).toBeEnabled()
  })

  it('shows the note the server has, not the empty one the caller passed', async () => {
    // The bug in one assertion: opened from a view that knows no note, the
    // box must still end up carrying the reasoning already on record.
    vi.mocked(api).mockResolvedValue(
      context({ triage_note: 'dropper, uploaded via the media form' }))

    mount(stub({ triage_note: '' }))

    await waitFor(() =>
      expect(noteBox().value).toBe('dropper, uploaded via the media form'))
  })

  it('does not write an empty note back over a recorded one', async () => {
    // The consequence, and the reason this mattered enough to find: the
    // triage buttons send the contents of the box. A box that never caught
    // up with the server sent '' and erased the note server-side.
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'confirmed by hash' }))

    const { onTriage } = mount(stub({ triage_note: '' }))
    await waitFor(() => expect(noteBox().value).toBe('confirmed by hash'))

    await userEvent.click(screen.getByRole('button', { name: /Confirm & collect/i }))
    expect(onTriage).toHaveBeenCalledWith('confirmed', 'confirmed by hash')
  })

  it('keeps what the analyst is typing when the context is refetched', async () => {
    // Every triage decision invalidates the artifact query, so a refetch
    // lands in the middle of writing more or less constantly. Re-seeding on
    // each answer would delete the sentence being written.
    vi.mocked(api).mockResolvedValue(context({ triage_note: 'first pass' }))
    const { qc } = mount()
    await waitFor(() => expect(noteBox().value).toBe('first pass'))

    await userEvent.clear(noteBox())
    await userEvent.type(noteBox(), 'second pass: same hash as the other host')

    await act(async () => { await qc.refetchQueries({ queryKey: ['artifact'] }) })

    expect(noteBox().value).toBe('second pass: same hash as the other host')
  })

  it('replaces the note when a different artifact is opened', async () => {
    // The window stays mounted across artifacts. Carrying the previous
    // one's note over would attach somebody's reasoning to the wrong file --
    // and the next click would then save it there.
    const other = '/var/www/uploads/avatar.php'
    vi.mocked(api).mockImplementation(async (path: string) =>
      path.includes(encodeURIComponent(other))
        ? context({ artifact: other, triage_note: 'second file, unrelated' })
        : context({ triage_note: 'first file' }))

    const { rerender } = mount()
    await waitFor(() => expect(noteBox().value).toBe('first file'))

    rerender(window_(stub({ artifact: other })))

    await waitFor(() => expect(noteBox().value).toBe('second file, unrelated'))
  })

  it("shows no note while the new artifact's context is still in flight", async () => {
    // Between opening the second artifact and its answer arriving, the only
    // context the component has is the first artifact's. An empty box for a
    // moment is honest; the previous file's reasoning under the new file's
    // name is not, and one triage click would then save it there.
    const other = '/var/www/uploads/avatar.php'
    let release: ((c: ArtifactContext) => void) | null = null
    vi.mocked(api).mockImplementation((path: string) =>
      path.includes(encodeURIComponent(other))
        ? new Promise<ArtifactContext>((res) => { release = res })
        : Promise.resolve(context({ triage_note: 'first file' })))

    const { rerender } = mount()
    await waitFor(() => expect(noteBox().value).toBe('first file'))

    rerender(window_(stub({ artifact: other })))
    expect(noteBox().value).toBe('')
    expect(noteBox()).toBeDisabled()
    expect(screen.getByRole('button', { name: /Confirm & collect/i })).toBeDisabled()

    await act(async () => {
      release?.(context({ artifact: other, triage_note: 'its own note' }))
    })
    await waitFor(() => expect(noteBox().value).toBe('its own note'))
    expect(noteBox()).toBeEnabled()
    expect(screen.getByRole('button', { name: /Confirm & collect/i })).toBeEnabled()
  })
})

describe('what the window states about the artifact', () => {
  it('shows all available forensic file hashes in full', async () => {
    vi.mocked(api).mockResolvedValue(context({
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
    }))

    mount()

    expect(await screen.findByText('1'.repeat(32))).toBeInTheDocument()
    expect(screen.getByText('2'.repeat(40))).toBeInTheDocument()
    expect(screen.getByText('3'.repeat(64))).toBeInTheDocument()
  })

  it('prefers the server triage state over the stub the caller guessed', async () => {
    // Actors opens this window knowing only an IP; it guesses `new`. If the
    // window believed the guess, an artifact already ruled a false positive
    // would present itself as undecided.
    vi.mocked(api).mockResolvedValue(context({ triage: 'dismissed' }))
    mount(stub({ triage: 'new' }))

    await waitFor(() => expect(screen.getByText('false positive')).toBeInTheDocument())
  })

  it('places evidence before analyst reasoning and decisions', async () => {
    vi.mocked(api).mockResolvedValue(context({
      findings: [{
        id: 1, fingerprint: 'synthetic-finding', artifact: SHELL, artifact_kind: 'file',
        source: 'webshell', rule: 'Suspicious PHP execution', severity: 0,
        evidence: 'eval($_POST["x"]);', line: 12, retired: 0, last_seen: '', created: '',
        triage: 'new', triage_note: '',
      }],
    }))

    mount()
    const evidenceHeading = await screen.findByText(/Why this artifact was flagged/)
    const reasoningHeading = screen.getByText('Analyst reasoning')

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
