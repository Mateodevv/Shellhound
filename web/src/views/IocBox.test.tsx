import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, type CrossCaseIocResponse, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocBox } from './IocBox'

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

describe('cross-case IOC matches', () => {
  it('names and links the other case without hiding the current IOC', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/iocs/cross-case')) return CROSS_CASE
      if (path.endsWith('/iocs')) return [IOC]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<IocBox slug="current-case" gotoView={() => {}} />)

    expect((await screen.findAllByText(IOC.value)).length).toBeGreaterThanOrEqual(2)
    const link = await screen.findByRole('link', { name: /Previous Case/ })
    expect(link).toHaveAttribute('href', expect.stringContaining('case=previous-case'))
    expect(screen.getByText('Also seen in other cases')).toBeInTheDocument()
  })
})
