// useTriage.test.tsx -- what has to happen everywhere else when one
// artifact is decided.
//
// THE DEFECT THIS FILE GUARDS. A triage state is drawn in nine places, and
// the decision is taken in four of them. The hook is the only thing that
// knows a decision happened, so every list that draws the badge has to be
// invalidated from here. The file browser, the database inventory and the
// CMS inventory were not, and they went on showing the state from before the
// decision until something unrelated happened to refetch them -- an analyst
// looking at two views of the same artifact saw two different answers, with
// nothing to say which was current.
//
// The tests below assert the invalidation against the ACTUAL set of query
// keys in web/src rather than against a copy of the list inside the hook. A
// test that re-types the list it is guarding passes against the broken code.
import { describe, expect, it, vi } from 'vitest'
import { type ReactNode } from 'react'
import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import { post, type TriageLink, type TriageResult } from '../api'
import { testQueryClient } from '../test/setup'
import { useTriage } from './useTriage'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

/** Every query in web/src whose answer contains a triage state, with the key
 *  exactly as the component that owns it writes it -- trailing filter
 *  arguments included, because the invalidation matches on the prefix and a
 *  key with five parts is where that would quietly stop working.
 *
 *  Kept as a table with the owning file named, so that adding a tenth view
 *  that draws the badge means adding a line here and watching it fail. */
const SHOWS_A_TRIAGE_STATE: [owner: string, key: readonly unknown[]][] = [
  ['views/Findings.tsx', ['findings', 'case', { q: '' }]],
  ['components/ArtifactWindow.tsx', ['artifact', 'case', '/var/www/shell.php']],
  ['views/Dashboard.tsx', ['dashboard', 'case']],
  ['views/IocBox.tsx', ['iocs', 'case']],
  ['views/Actors.tsx', ['actors', 'case', '', false, 'requests']],
  ['components/CaseChain.tsx', ['chain', 'case']],
  ['views/Files.tsx', ['browse', 'case', '/var/www']],
  ['views/Database.tsx', ['database', 'case']],
  ['views/Cms.tsx', ['cms', 'case']],
  ['components/FileViewer.tsx', ['file', 'case', '/var/www/shell.php', 'text', 0]],
  ['components/CommandPalette.tsx', ['search', 'case', 'shell']],
]

const RESULT: TriageResult = {
  updated: 3, artifacts: 1, collected: [], linked: [], suggested: [], retained_iocs: [],
}

function link(artifact: string): TriageLink {
  return {
    artifact, kind: 'file', why: 'requested by the same client',
    previous: { state: 'new', note: '' },
  } as TriageLink
}

function mount(onDecided?: () => void) {
  const qc = testQueryClient()
  const wrapper = ({ children }: { children: ReactNode }) =>
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  const { result } = renderHook(() => useTriage('case', onDecided), { wrapper })
  return { qc, result }
}

describe('what a decision invalidates', () => {
  it('marks every cached answer that carries a triage state as stale', async () => {
    // The bug in one assertion, stated over the real keys: after a decision
    // nothing that draws the badge may still be considered fresh.
    const { qc, result } = mount()
    for (const [, key] of SHOWS_A_TRIAGE_STATE) qc.setQueryData(key, { seeded: true })
    vi.mocked(post).mockResolvedValue(RESULT)

    act(() => { result.current.decide(['/var/www/shell.php'], 'confirmed') })

    for (const [owner, key] of SHOWS_A_TRIAGE_STATE) {
      await waitFor(() => expect(
        qc.getQueryState(key)?.isInvalidated,
        `${owner} kept showing the state from before the decision`,
      ).toBe(true))
    }
  })

  it('leaves alone the answers a decision cannot have changed', async () => {
    // Invalidating everything would be the easy fix and the wrong one: the
    // log trace is thousands of rows and the settings answer costs a file
    // read, and neither carries a triage state. A cache that empties itself
    // on every click is a tool that feels broken.
    const untouched: [string, readonly unknown[]][] = [
      ['components/TraceWindow.tsx', ['trace', 'case', ['203.0.113.9'], 0]],
      ['views/Settings.tsx', ['settings']],
      ['geo.ts', ['geo-status']],
      ['components/LogCoverage.tsx', ['coverage', 'case']],
    ]
    const { qc, result } = mount()
    for (const [, key] of untouched) qc.setQueryData(key, { seeded: true })
    vi.mocked(post).mockResolvedValue(RESULT)

    await act(async () => { result.current.decide(['/var/www/shell.php'], 'confirmed') })
    await waitFor(() => expect(post).toHaveBeenCalled())

    for (const [owner, key] of untouched) {
      expect(qc.getQueryState(key)?.isInvalidated,
             `${owner} was thrown away for a decision that cannot affect it`)
        .toBe(false)
    }
  })

  it('invalidates the same set again when a propagation is taken back', async () => {
    // An undo moves artifacts back to the state the server supplied. That is
    // as much a change to every badge on screen as the decision was, and it
    // arrives through a different code path -- which is exactly how one of
    // the two ends up not refreshing.
    const { qc, result } = mount()
    for (const [, key] of SHOWS_A_TRIAGE_STATE) qc.setQueryData(key, { seeded: true })
    vi.mocked(post).mockResolvedValue(RESULT)

    await act(async () => { await result.current.undo([link('/var/www/other.php')]) })

    for (const [owner, key] of SHOWS_A_TRIAGE_STATE) {
      expect(qc.getQueryState(key)?.isInvalidated,
             `${owner} still showed the propagated state after the undo`)
        .toBe(true)
    }
  })
})

describe('the decision itself', () => {
  it('sends one call per previous state when a propagation is undone', async () => {
    // Everything that stood at `new` goes back to `new`, everything that
    // stood at `reviewed` back to `reviewed`. Grouping is not an
    // optimisation here: one call with a single state would flatten
    // artifacts onto a state they were never in.
    const { result } = mount()
    vi.mocked(post).mockResolvedValue(RESULT)

    await act(async () => {
      await result.current.undo([
        { ...link('/a.php'), previous: { state: 'new', note: '' } },
        { ...link('/b.php'), previous: { state: 'reviewed', note: 'seen' } },
        { ...link('/c.php'), previous: { state: 'new', note: '' } },
      ])
    })

    const bodies = vi.mocked(post).mock.calls.map((c) => c[1])
    expect(bodies).toHaveLength(2)
    expect(bodies).toContainEqual({
      artifacts: ['/a.php', '/c.php'], state: 'new', note: '', propagate: false,
    })
    expect(bodies).toContainEqual({
      artifacts: ['/b.php'], state: 'reviewed', note: 'seen', propagate: false,
    })
  })

  it('never propagates from an undo', async () => {
    // An undo that propagated would trigger the very wave it is taking back,
    // and the two would fight.
    const { result } = mount()
    vi.mocked(post).mockResolvedValue(RESULT)

    await act(async () => { await result.current.undo([link('/a.php')]) })

    expect(vi.mocked(post).mock.calls[0][1])
      .toMatchObject({ propagate: false })
  })

  it('says so when the server recorded nothing', async () => {
    // The server answers 200 with `updated: 0` for an artifact that carries
    // no findings -- an actor picked out of the search exists in the log
    // index but not in the work list. Reported as success, the analyst walks
    // away believing the decision was filed.
    const { result } = mount()
    vi.mocked(post).mockResolvedValue({ ...RESULT, updated: 0 })

    act(() => { result.current.decide(['203.0.113.9'], 'confirmed') })

    await waitFor(() => expect(result.current.nothingToDecide).toBe(true))
  })

  it('stops saying so once a decision does record something', async () => {
    const { result } = mount()
    vi.mocked(post).mockResolvedValue({ ...RESULT, updated: 0 })
    act(() => { result.current.decide(['203.0.113.9'], 'confirmed') })
    await waitFor(() => expect(result.current.nothingToDecide).toBe(true))

    vi.mocked(post).mockResolvedValue({ ...RESULT, updated: 2 })
    act(() => { result.current.decide(['/var/www/shell.php'], 'confirmed') })
    await waitFor(() => expect(result.current.nothingToDecide).toBe(false))
  })

  it('reports what was decided along with it', async () => {
    const { result } = mount()
    vi.mocked(post).mockResolvedValue({ ...RESULT, linked: [link('/b.php')] })

    act(() => { result.current.decide(['/a.php'], 'confirmed') })

    await waitFor(() => expect(result.current.notice?.linked).toHaveLength(1))
  })

  it('drops the previous notice when a decision propagates nothing', async () => {
    const { result } = mount()
    vi.mocked(post).mockResolvedValue({ ...RESULT, linked: [link('/b.php')] })
    act(() => { result.current.decide(['/a.php'], 'confirmed') })
    await waitFor(() => expect(result.current.notice?.linked).toHaveLength(1))

    vi.mocked(post).mockResolvedValue({ ...RESULT, linked: [], suggested: [] })
    act(() => { result.current.decide(['/c.php'], 'dismissed') })
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))

    expect(result.current.notice).toBeNull()
  })

  it('tells the view a decision landed, so it can close what it opened', async () => {
    const onDecided = vi.fn()
    const { result } = mount(onDecided)
    vi.mocked(post).mockResolvedValue(RESULT)

    act(() => { result.current.decide(['/a.php'], 'confirmed') })

    await waitFor(() => expect(onDecided).toHaveBeenCalledTimes(1))
  })
})
