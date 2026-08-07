// CommandPalette.test.tsx -- what the palette is showing when it opens.
//
// THE DEFECT THIS FILE GUARDS. The palette clears its input on open but
// stays mounted, so the query it drives changes key without unmounting.
// Handing the previous key's data to the next one -- which is what a plain
// `placeholderData: prev => prev` does -- meant the box was empty while the
// last search's hits were still listed under it, with the first one
// highlighted. Enter then opened an artifact nobody had searched for.
//
// The tension worth stating: that same placeholder is what stops the list
// flickering between keystrokes, so the rule is not "no placeholder" but
// "no placeholder across a query the palette will not run".
import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api } from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { CommandPalette } from './CommandPalette'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

interface SearchShape {
  artifacts: { artifact: string; artifact_kind: string; worst: number
               triage: string; findings: number }[]
  iocs: { id: number; value: string; type: string; note: string }[]
  actors: { ip: string; requests: number; alerts: number }[]
  accounts: { id: number; login: string; email: string; admin: number; tbl: string }[]
}

const EMPTY: SearchShape = { artifacts: [], iocs: [], actors: [], accounts: [] }

function hits(paths: string[]): SearchShape {
  return {
    ...EMPTY,
    artifacts: paths.map((p) => ({
      artifact: p, artifact_kind: 'file', worst: 0,
      triage: 'new', findings: 1,
    })),
  }
}

/** Answer as the server would: whatever the query string asks for. Anything
 *  the palette lists that this did not answer came from somewhere it should
 *  not have. */
function answering(byQuery: Record<string, SearchShape>) {
  vi.mocked(api).mockImplementation(async (path: string) => {
    const q = decodeURIComponent(new URL(path, 'http://x').searchParams.get('q') ?? '')
    return byQuery[q] ?? EMPTY
  })
}

function mount(open = true) {
  const onOpenArtifact = vi.fn()
  const gotoView = vi.fn()
  const onClose = vi.fn()
  const view = renderWithProviders(
    <CommandPalette slug="case" open={open} onClose={onClose}
      gotoView={gotoView} onOpenArtifact={onOpenArtifact} />, testQueryClient())
  const palette = (isOpen: boolean) => (
    <CommandPalette slug="case" open={isOpen} onClose={onClose}
      gotoView={gotoView} onOpenArtifact={onOpenArtifact} />
  )
  return { onOpenArtifact, gotoView, onClose, palette, ...view }
}

const box = () => screen.getByPlaceholderText(/at least 2 characters/i)

describe('reopening the palette', () => {
  it('lists nothing under an empty input', async () => {
    // The bug in one assertion.
    answering({ shell: hits(['/var/www/Images/shell.php']) })
    const { rerender, palette } = mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() =>
      expect(screen.getByText('/var/www/Images/shell.php')).toBeInTheDocument())

    rerender(palette(false))
    rerender(palette(true))

    await waitFor(() => expect(box()).toHaveValue(''))
    expect(screen.queryByText('/var/www/Images/shell.php')).toBeNull()
  })

  it('offers nothing for Enter to open under an empty input', async () => {
    // The consequence: a highlighted first row plus a keyboard-driven
    // control means Enter opens something. Under an empty box it must open
    // nothing at all.
    answering({ shell: hits(['/var/www/Images/shell.php']) })
    const { rerender, palette, onOpenArtifact } = mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() =>
      expect(screen.getByText('/var/www/Images/shell.php')).toBeInTheDocument())

    rerender(palette(false))
    rerender(palette(true))
    await waitFor(() => expect(box()).toHaveValue(''))

    await userEvent.type(box(), '{Enter}')
    expect(onOpenArtifact).not.toHaveBeenCalled()
  })

  it('says what it searches instead of showing a stale list', async () => {
    answering({ shell: hits(['/var/www/Images/shell.php']) })
    const { rerender, palette } = mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() =>
      expect(screen.getByText('/var/www/Images/shell.php')).toBeInTheDocument())

    rerender(palette(false))
    rerender(palette(true))

    await waitFor(() =>
      expect(screen.getByText(/Searches artifacts, indicators/i)).toBeInTheDocument())
  })
})

describe('while typing', () => {
  it('asks nothing of the server below two characters', async () => {
    // A palette that searched on every keystroke from the first character
    // would run one full-case query per letter for answers nobody can use.
    answering({})
    mount()
    await userEvent.type(box(), 's')
    expect(api).not.toHaveBeenCalled()
  })

  it('replaces the previous search rather than adding to it', async () => {
    // Two searches' hits in one list is the same class of mistake as a
    // stale list on reopen: the rows no longer answer the question in the
    // box.
    answering({
      shell: hits(['/var/www/Images/shell.php']),
      avatar: hits(['/var/www/uploads/avatar.php']),
    })
    mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() =>
      expect(screen.getByText('/var/www/Images/shell.php')).toBeInTheDocument())

    await userEvent.clear(box())
    await userEvent.type(box(), 'avatar')
    await waitFor(() =>
      expect(screen.getByText('/var/www/uploads/avatar.php')).toBeInTheDocument())
    expect(screen.queryByText('/var/www/Images/shell.php')).toBeNull()
  })

  it('opens the artifact window on the row Enter is standing on', async () => {
    // A palette hit is a springboard, and for an artifact it opens the same
    // window as everywhere else -- with the note left empty, because the
    // search result does not carry one and the window fetches it.
    answering({ shell: hits(['/a/shell.php', '/b/shell.php']) })
    const { onOpenArtifact } = mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() => expect(screen.getByText('/b/shell.php')).toBeInTheDocument())

    await userEvent.type(box(), '{ArrowDown}{Enter}')
    expect(onOpenArtifact).toHaveBeenCalledWith(expect.objectContaining({
      artifact: '/b/shell.php', artifact_kind: 'file',
    }))
  })

  it('states plainly that a search found nothing', async () => {
    // An empty list and an empty answer look identical, and the difference
    // decides whether the analyst searches again or moves on.
    answering({ nothinghere: EMPTY })
    mount()

    await userEvent.type(box(), 'nothinghere')
    await waitFor(() =>
      expect(screen.getByText(/Nothing found/i)).toBeInTheDocument())
  })

  it('puts the cursor back on the first row when the results change', async () => {
    // The cursor is an index into a list that has just been replaced.
    // Leaving it where it was points it at a row that is now something else.
    answering({
      shell: hits(['/a/shell.php', '/b/shell.php', '/c/shell.php']),
      avatar: hits(['/x/avatar.php', '/y/avatar.php', '/z/avatar.php']),
    })
    const { onOpenArtifact } = mount()

    await userEvent.type(box(), 'shell')
    await waitFor(() => expect(screen.getByText('/c/shell.php')).toBeInTheDocument())
    await userEvent.type(box(), '{ArrowDown}{ArrowDown}')

    await userEvent.clear(box())
    await userEvent.type(box(), 'avatar')
    await waitFor(() => expect(screen.getByText('/z/avatar.php')).toBeInTheDocument())

    await userEvent.type(box(), '{Enter}')
    expect(onOpenArtifact).toHaveBeenCalledWith(expect.objectContaining({
      artifact: '/x/avatar.php',
    }))
  })
})

describe('when closed', () => {
  it('renders nothing and asks nothing', () => {
    answering({})
    const { container } = mount(false)
    expect(container).toBeEmptyDOMElement()
    expect(api).not.toHaveBeenCalled()
  })
})
