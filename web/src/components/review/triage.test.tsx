import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { TriageResult } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { useTriage } from './useTriage'
import { TriageFollowUp } from './triage'

function Receipt({ content }: { content: TriageResult['content_assessment'] }) {
  const triage = useTriage('synthetic-case')
  return <>
    <button onClick={() => triage.recordResult({ updated: 1, artifacts: 1, collected: [], linked: [], suggested: [], retained_iocs: [], content_assessment: content })}>Show receipt</button>
    <TriageFollowUp t={triage} roots={[]} />
  </>
}

describe('indexed copy decision feedback', () => {
  it('gives an honest recovery path when the selected file has no prepared identity', () => {
    renderWithProviders(<Receipt content={{ applied: [], conflicts: [], needs_index: true }} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show receipt' }))
    expect(screen.getByText(/Decision saved for this file/)).toHaveTextContent('then save the decision again')
    expect(screen.queryByText(/No other indexed copies/)).not.toBeInTheDocument()
  })

  it('shows partial application and changed copies together without claiming all copies updated', () => {
    renderWithProviders(<Receipt content={{ applied: ['/copy/example.txt'], conflicts: [], skipped_count: 2, incomplete: true }} />)
    fireEvent.click(screen.getByRole('button', { name: 'Show receipt' }))
    expect(screen.getByText('Applied to 1 verified identical copy.')).toBeInTheDocument()
    expect(screen.getByText(/2 indexed copies changed or are unavailable/)).toHaveTextContent('This assessment was not applied to them')
    expect(screen.queryByText(/No other indexed copies/)).not.toBeInTheDocument()
  })
})
