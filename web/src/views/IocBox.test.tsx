import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, type CrossCaseIocResponse, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocBox } from './IocBox'
import { defang } from '../defang'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
}))

const IOC: Ioc = {
  id: 7,
  value: 'bad.example',
  type: 'domain',
  note: 'analyst supplied',
  tags: ['confirmed'],
  origin: 'ioc box',
  added: '2026-08-09T00:00:00Z',
  first_seen: null,
  last_seen: null,
  links: [],
}

const CROSS_CASE: CrossCaseIocResponse = {
  entries: [{
    id: IOC.id,
    value: IOC.value,
    type: IOC.type,
    matches: [{
      slug: 'previous-case',
      name: 'Previous Case',
      reference: 'IR-41',
      id: 2,
      value: IOC.value,
      type: IOC.type,
      note: 'same campaign',
      tags: ['analyst'],
      origin: 'ioc box',
      added: '2026-08-01T00:00:00Z',
    }],
  }],
  matched_iocs: 1,
  matches: 1,
  matched_cases: 1,
  cases_scanned: 3,
  cases_skipped: 0,
}

const NO_CROSS: CrossCaseIocResponse = {
  entries: [], matched_iocs: 0, matches: 0, matched_cases: 0,
  cases_scanned: 0, cases_skipped: 0,
}

// The pair a confirmation collects: the file, and its digest linked via
// `hash-of`. The hash must dock UNDER the file card instead of standing
// somewhere in the list as a card of its own.
const FILE_IOC: Ioc = {
  id: 11,
  value: 'images/shell.php',
  type: 'path',
  note: '',
  tags: ['confirmed', 'finding', 'webshell'],
  origin: 'confirmed finding',
  added: '2026-08-09T00:00:01Z',
  first_seen: null,
  last_seen: null,
  links: [{ kind: 'hash-of', label: 'has the SHA-256', note: '',
            value: 'a'.repeat(64), type: 'hash', id: 12 }],
}
const HASH_IOC: Ioc = {
  id: 12,
  value: 'a'.repeat(64),
  type: 'hash',
  note: '',
  tags: ['confirmed', 'derived'],
  origin: 'sha-256 of images/shell.php',
  added: '2026-08-09T00:00:02Z',
  first_seen: null,
  last_seen: null,
  links: [{ kind: 'hash-of', label: 'is the SHA-256 of', note: '',
            value: 'images/shell.php', type: 'path', id: 11 }],
}

describe('cross-case IOC matches', () => {
  it('folds to a bar that still states the numbers, and links on demand', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/iocs/cross-case')) return CROSS_CASE
      if (path.endsWith('/iocs')) return [IOC]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<IocBox slug="current-case" gotoView={() => {}} />)

    // Folded by default: the bar names the fact, the details wait. The
    // current IOC's own card is not hidden by any of this.
    await screen.findByText(IOC.value, { selector: '.mono span' })
    expect(screen.getByText('Also seen in other cases')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Previous Case/ }))
      .not.toBeInTheDocument()

    fireEvent.click(screen.getByText('Also seen in other cases'))
    const link = await screen.findByRole('link', { name: /Previous Case/ })
    expect(link).toHaveAttribute('href', expect.stringContaining('case=previous-case'))
  })

  it('marks the matching entry itself with a badge that unfolds the section', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/iocs/cross-case')) return CROSS_CASE
      if (path.endsWith('/iocs')) return [IOC]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<IocBox slug="current-case" gotoView={() => {}} />)

    await screen.findByText(IOC.value, { selector: '.mono span' })
    // The badge sits on the entry the analyst is looking at -- not only in
    // a summary block they would have to cross-reference by value.
    const badge = screen.getByRole('button', { name: 'Also seen in other cases' })
    fireEvent.click(badge)
    expect(await screen.findByRole('link', { name: /Previous Case/ }))
      .toBeInTheDocument()
  })
})

describe('a derived hash folds into its file card', () => {
  it('is hidden by default and unfolds inside the file, not by insertion order', async () => {
    // Insertion order (added DESC) would put the hash FIRST as a card of
    // its own. Folded linking has to override that twice over: no hash on
    // screen until the link bar is opened, and after opening it sits
    // BELOW the file it belongs to.
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/iocs/cross-case')) return NO_CROSS
      if (path.endsWith('/iocs')) return [HASH_IOC, FILE_IOC]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<IocBox slug="current-case" gotoView={() => {}} />)

    const file = await screen.findByText(FILE_IOC.value, { selector: '.mono span' })
    expect(screen.queryByText(HASH_IOC.value, { selector: '.mono span' }))
      .not.toBeInTheDocument()

    const bar = screen.getByRole('button', { name: /1 linked indicator/ })
    expect(bar).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(bar)

    const hash = await screen.findByText(HASH_IOC.value, { selector: '.mono span' })
    expect(
      file.compareDocumentPosition(hash) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })
})

describe('the reputation panel is a lookup, not wallpaper', () => {
  it('stays closed until its toggle is clicked', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/iocs/cross-case')) return NO_CROSS
      if (path.endsWith('/iocs')) return [HASH_IOC]
      // The panel checks whether the service is configured before it offers
      // the button -- an unconfigured one would render the quiet not-ready
      // note and this test would pass without testing the toggle.
      if (path === '/api/settings') return {
        services: {
          virustotal: { configured: true, hint: '', sends: 'hash', url: '' },
          abuseipdb: { configured: true, hint: '', sends: 'ip', url: '' },
        },
        enrichment_ack: true,
        path: '',
      }
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<IocBox slug="current-case" gotoView={() => {}} />)

    await screen.findByText(HASH_IOC.value, { selector: '.mono span' })
    expect(screen.queryByText(/Ask VirusTotal/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Look up reputation' }))
    expect(await screen.findByText(/Ask VirusTotal/)).toBeInTheDocument()
  })
})

describe('defang', () => {
  it('leaves nothing clickable and nothing else changed', () => {
    expect(defang('203.0.113.9', 'ip')).toBe('203[.]0[.]113[.]9')
    expect(defang('https://evil.test/x.php', 'url')).toBe('hxxps://evil[.]test/x[.]php')
    expect(defang('evil.test', 'domain')).toBe('evil[.]test')
    expect(defang('a@evil.test', 'email')).toBe('a[at]evil[.]test')
    // Hashes and paths are inert already -- defanging must not touch them.
    expect(defang('a'.repeat(64), 'hash')).toBe('a'.repeat(64))
    expect(defang('images/shell.php', 'path')).toBe('images/shell.php')
  })
})
