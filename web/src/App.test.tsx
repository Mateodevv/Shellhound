import { fireEvent, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { renderWithProviders } from './test/setup'
import App, { CaseNavigation } from './App'
import { api } from './api'
import { queryClient } from './queryClient'

vi.mock('./api', async (original) => ({ ...(await original<typeof import('./api')>()), api: vi.fn() }))
vi.mock('./ws', () => ({ useLiveEvents: vi.fn() }))
vi.mock('./components/GeoBanner', () => ({ GeoBanner: () => null }))
vi.mock('./components/SetupBanners', () => ({ EnrichmentBanners: () => null }))
vi.mock('./views/Hunt', () => ({ Hunt: () => {
  const [page] = useState(() => new URLSearchParams(location.search).get('section') ?? 'overview')
  return <div>Saved Hunt page: {page}</div>
} }))

describe('CaseNavigation', () => {
  it('restores a Hunt results page on Back after revisiting Hunt in the sidebar', async () => {
    queryClient.clear()
    const resultUrl = '/?case=history-case&view=hunt&section=runs&batch=saved-check'
    history.replaceState(null, '', resultUrl)
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/jobs')) return []
      if (path.endsWith('/dashboard')) return { triage: {} }
      if (path.endsWith('/history-case')) return { name: 'History check', evidence_items: [] }
      return {}
    })
    renderWithProviders(<App />)
    expect(await screen.findByText('Saved Hunt page: runs')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Pattern hunt' }))
    expect(await screen.findByText('Saved Hunt page: overview')).toBeVisible()
    history.replaceState(null, '', resultUrl)
    fireEvent.popState(window)
    expect(await screen.findByText('Saved Hunt page: runs')).toBeVisible()
  })

  it('shows every investigation destination without a disclosure control', () => {
    renderWithProviders(<CaseNavigation view="dashboard" openArtifacts={0}
      onNavigate={vi.fn()} onSearch={vi.fn()} />)

    expect(screen.getByText('Investigation tools')).toBeInTheDocument()
    for (const label of [
      'Actors', 'Files', 'Timeline', 'Database', 'CMS inventory', 'Pattern hunt', 'Access logs',
    ]) {
      expect(screen.getByRole('button', { name: new RegExp(label, 'i') })).toBeInTheDocument()
    }
    expect(screen.queryByRole('button', { name: /^Investigation tools$/i })).not.toBeInTheDocument()
  })
})
