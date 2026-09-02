import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type FindingsResponse } from '../api'
import { renderWithProviders } from '../test/setup'
import { Findings } from './Findings'

vi.mock('../api', async (original) => ({
  ...(await original<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
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

describe('findings filter workbench', () => {
  beforeEach(() => {
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
