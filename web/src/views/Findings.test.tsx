import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, post, type ArtifactContext, type FindingsResponse, type TriageResult } from '../api'
import { renderWithProviders } from '../test/setup'
import { firstReviewArtifact, nextReviewArtifact } from '../reviewQueue'
import { Findings } from './Findings'

vi.mock('../api', async (original) => ({
  ...(await original<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

// jsdom has no layout. Render the virtual rows so selections can be tested
// through their checkboxes and the real bulk-decision controls.
vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () => Array.from({ length: count }, (_, index) => ({
      index, start: index * 68, size: 68,
    })),
    getTotalSize: () => count * 68,
    scrollToIndex: () => {},
  }),
}))

const RESPONSE: FindingsResponse = {
  total: 0,
  artifacts: [],
  findings: [],
  findings_total: 0,
  muted_hidden: 0,
  retired_hidden: 0,
  muted_rules: 0,
  counts: {
    severity: { '0': 2, '1': 3, '2': 4, '3': 5 },
    triage: { new: 5, reviewed: 2, confirmed: 1, dismissed: 6 },
    source: { webshell: 2, sqldb: 3, logs: 4, yara: 1, analyst: 0 },
    total: 14,
  },
  roots: [],
}

describe('folder selection in Findings', () => {
  const paths = [
    '/evidence/site/plugins/a.php',
    '/evidence/site/plugins/nested/b.php',
    '/evidence/site/plugins/nested/deeper/c.php',
    '/evidence/site/plugins-extra/d.php',
    '/evidence/other/plugins/e.php',
    '/evidence/site/plugins/obfuscated.php',
  ]
  const artifacts: FindingsResponse['artifacts'] = paths.map((artifact) => ({
    artifact, artifact_kind: 'file', worst: 1, source: 'webshell', findings: 1,
    retired: 0, triage: 'new', triage_note: '', triaged_at: null, last_seen: '',
  }))
  const response: FindingsResponse = {
    ...RESPONSE, total: paths.length, artifacts,
    roots: [
      { kind: 'webroot', path: '/evidence/site', label: 'Site' },
      { kind: 'webroot', path: '/evidence/other', label: 'Other site' },
    ],
    findings: artifacts.map((artifact, index) => ({
      id: index + 1, fingerprint: `file-${index}`, artifact: artifact.artifact,
      artifact_kind: 'file', source: 'webshell',
      rule: index === 5 ? 'Obfuscation decode chain' : 'Command execution on request input',
      severity: 1, evidence: 'synthetic finding', line: null, created: '',
      last_seen: '', retired: 0, triage: 'new', triage_note: '',
    })),
  }

  beforeEach(() => {
    vi.clearAllMocks()
    history.replaceState(null, '', '/?case=case-1&view=findings&search=php')
    vi.mocked(api).mockResolvedValue(response)
    vi.mocked(post).mockResolvedValue({
      updated: 3, artifacts: 3, collected: [], linked: [], suggested: [], retained_iocs: [],
    } satisfies TriageResult)
  })

  it('decides all nested files even when collapsed, without selecting neighboring folders, roots or categories', async () => {
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)
    const folder = await screen.findByRole('checkbox', { name: 'Select folder plugins (3 files)' })
    // Collapse this specific folder; the other evidence root has its own plugins folder.
    fireEvent.click(folder.parentElement!.querySelector('button')!)
    fireEvent.click(folder)
    expect(screen.getByRole('button', { name: 'Expand folder plugins' })).toBeVisible()
    expect(screen.getByText('3 artifact(s) selected')).toBeVisible()
    fireEvent.change(screen.getByPlaceholderText('Note for all marked (optional)'), {
      target: { value: 'Reviewed together' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'skipped for now' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/triage', {
      artifacts: paths.slice(0, 3), state: 'reviewed', note: 'Reviewed together', propagate: undefined,
    }))
    await waitFor(() => expect(screen.queryByText('3 artifact(s) selected')).not.toBeInTheDocument())
  })

  it('reflects partial selections and toggles nested groups without losing unrelated selections or counting duplicates', async () => {
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)
    const folder = await screen.findByRole('checkbox', { name: 'Select folder plugins (3 files)' })
    const nested = screen.getByRole('checkbox', { name: 'Select folder plugins/nested (2 files)' })
    const other = screen.getByRole('checkbox', { name: 'Select folder plugins-extra (1 file)' })
    fireEvent.click(other)
    fireEvent.click(nested)
    expect(folder).toBePartiallyChecked()
    fireEvent.click(folder)
    expect(folder).toBeChecked()
    expect(nested).toBeChecked()
    expect(screen.getByText('4 artifact(s) selected')).toBeVisible()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select file /evidence/site/plugins/a.php' }))
    expect(folder).toBePartiallyChecked()
    fireEvent.click(folder)
    fireEvent.click(folder)
    expect(folder).not.toBeChecked()
    expect(folder).not.toBePartiallyChecked()
    expect(nested).not.toBeChecked()
    expect(other).toBeChecked()
    expect(screen.getByText('1 artifact(s) selected')).toBeVisible()
  })

  it('selects only files returned for the current filters and keeps the list-limit warning visible', async () => {
    vi.mocked(api).mockResolvedValue({
      ...response, total: 2100, artifacts: artifacts.slice(0, 1), findings: response.findings.slice(0, 1),
    })
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select folder plugins (1 file)' }))
    expect(screen.getByText('1 artifact(s) selected')).toBeVisible()
    expect(screen.getByText(/showing the first 2[,.\s]?000/i)).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'skipped for now' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/triage', {
      artifacts: [paths[0]], state: 'reviewed', note: '', propagate: undefined,
    }))
  })
})

describe('findings filter workbench', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    history.replaceState(null, '', '/?case=case-1&view=findings')
    vi.mocked(api).mockResolvedValue(RESPONSE)
  })

  it('keeps the existing defaults and updates URL semantics from explicit checkboxes', async () => {
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    fireEvent.click(await screen.findByRole('button', { name: 'Filters (2)' }))
    expect(screen.getByRole('checkbox', { name: /Info/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /false positive/i })).not.toBeChecked()

    fireEvent.click(screen.getByRole('checkbox', { name: /Info/ }))
    await waitFor(() => expect(new URL(location.href).searchParams.get('severity')).toBe('0,1,2,3'))
    expect(new URL(location.href).searchParams.get('triage')).toBe('new,reviewed,confirmed')

    fireEvent.click(screen.getByRole('button', { name: 'show everything' }))
    await waitFor(() => expect(new URL(location.href).searchParams.get('triage'))
      .toBe('new,reviewed,confirmed,dismissed'))
  })

  it('stores the unchanged saved-view shape', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('Open review')
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    fireEvent.click(await screen.findByRole('button', { name: 'Save view' }))
    const stored = JSON.parse(localStorage.getItem('shellhound.saved-findings.case-1') || '[]')

    expect(stored).toEqual([{
      name: 'Open review', hiddenSeverity: ['3'], hiddenTriage: ['dismissed'],
      hiddenSource: [], search: '', showRetired: false,
    }])
  })
})

describe('save-and-next queue ordering', () => {
  const queue = [
    { artifact: 'first', triage: 'new' as const },
    { artifact: 'propagated', triage: 'reviewed' as const },
    { artifact: 'already-done', triage: 'confirmed' as const },
    { artifact: 'next', triage: 'new' as const },
  ]

  it('moves only forward and skips artifacts decided through propagation', () => {
    expect(nextReviewArtifact(queue, 'first', ['propagated'])?.artifact).toBe('next')
  })

  it('does not wrap when the filtered queue is complete', () => {
    expect(nextReviewArtifact(queue, 'next', [])).toBeNull()
  })

  it('opens untouched artifacts before returning to skipped ones', () => {
    expect(firstReviewArtifact(queue)?.artifact).toBe('first')
    expect(firstReviewArtifact(queue.slice(1))?.artifact).toBe('next')
    expect(firstReviewArtifact(queue.slice(1, 3))?.artifact).toBe('propagated')
    expect(firstReviewArtifact(queue.slice(2, 3))).toBeNull()
  })
})

describe('save-and-next Findings integration', () => {
  const artifacts: FindingsResponse['artifacts'] = ['client-one', 'client-two'].map(
    (artifact) => ({
      artifact, artifact_kind: 'client', worst: 1, source: 'logs', findings: 1,
      retired: 0, triage: 'new', triage_note: '', triaged_at: null, last_seen: '',
    }))
  const response: FindingsResponse = {
    ...RESPONSE,
    total: 2,
    artifacts,
    findings: artifacts.map((artifact, index) => ({
      id: index + 1, fingerprint: `finding-${index}`, artifact: artifact.artifact,
      artifact_kind: 'client', source: 'logs', rule: 'Suspicious request', severity: 1,
      evidence: 'synthetic request', line: null, created: '', last_seen: '', retired: 0,
      triage: 'new', triage_note: '',
    })),
  }
  const saved: TriageResult = {
    updated: 1, artifacts: 1, collected: [], linked: [], suggested: [], retained_iocs: [],
  }

  beforeEach(() => {
    vi.clearAllMocks()
    history.replaceState(null, '',
      '/?case=case-1&view=findings&search=client&artifact=client-one')
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path.includes('/findings?')) return response as never
      const requested = decodeURIComponent(path.split('artifact=')[1] ?? 'client-one')
      const context: ArtifactContext = {
        artifact: requested, kind: 'client', findings: response.findings.filter(
          (finding) => finding.artifact === requested),
        triage: 'new', triage_note: '', triaged_at: '', worst: 1, sources: ['logs'],
        related_ips: [], actor: null,
      }
      return context as never
    })
    vi.mocked(post).mockResolvedValue(saved)
  })

  it('updates the artifact URL only after a successful save', async () => {
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    await userEvent.click(await screen.findByRole('radio', { name: 'Skip for now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save & next' }))

    await waitFor(() => expect(new URL(location.href).searchParams.get('artifact'))
      .toBe('client-two'))
    expect(post).toHaveBeenCalledWith('/api/cases/case-1/triage', {
      artifacts: ['client-one'], state: 'reviewed', note: '', propagate: undefined,
    })
  })

  it('opens the next finding directly from the workbench action', async () => {
    history.replaceState(null, '', '/?case=case-1&view=findings&search=client')
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    await userEvent.click(await screen.findByRole('button', {
      name: 'Review next finding (2)',
    }))

    await waitFor(() => expect(new URL(location.href).searchParams.get('artifact'))
      .toBe('client-one'))
  })

  it('resolves the Dashboard handoff against the same displayed queue', async () => {
    history.replaceState(null, '',
      '/?case=case-1&view=findings&search=client&next=1')
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    await waitFor(() => expect(new URL(location.href).searchParams.get('artifact'))
      .toBe('client-one'))
    expect(new URL(location.href).searchParams.get('next')).toBeNull()
  })

  it('closes at the end without wrapping and reports the filtered queue complete', async () => {
    history.replaceState(null, '',
      '/?case=case-1&view=findings&search=client&artifact=client-two')
    renderWithProviders(<Findings slug="case-1" gotoView={vi.fn()} />)

    await userEvent.click(await screen.findByRole('radio', { name: 'Skip for now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save & next' }))

    await waitFor(() => expect(new URL(location.href).searchParams.get('artifact')).toBeNull())
    expect(screen.getByText('Filtered queue complete')).toBeVisible()
    expect(post).toHaveBeenCalledWith('/api/cases/case-1/triage', {
      artifacts: ['client-two'], state: 'reviewed', note: '', propagate: undefined,
    })
  })
})
