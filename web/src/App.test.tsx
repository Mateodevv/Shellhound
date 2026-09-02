import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { renderWithProviders } from './test/setup'
import { CaseNavigation } from './App'

describe('CaseNavigation', () => {
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
