import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Job } from '../api'
import { JobPopup } from './JobPopup'

const job: Job = {
  id: 1, run_id: 'run', kind: 'webshell', state: 'running', progress: 0.35,
  message: 'Scanning example.php', error: '', created: '', stats: {},
}

describe('JobPopup', () => {
  it('opens with current jobs and keeps a user collapse across progress updates', () => {
    const onShowRuns = vi.fn()
    const { rerender } = render(<JobPopup jobs={[job]} onShowRuns={onShowRuns} />)
    const toggle = screen.getByRole('button', { name: '1 job(s) running…' })
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('35%')).toBeInTheDocument()
    fireEvent.click(toggle)
    rerender(<JobPopup jobs={[{ ...job, progress: 0.75 }]} onShowRuns={onShowRuns} />)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('75%')).not.toBeInTheDocument()
    fireEvent.click(toggle)
    expect(screen.getByText('75%')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'View analysis runs' }))
    expect(onShowRuns).toHaveBeenCalledOnce()
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })

  it('shows queued jobs and allows keyboard users to collapse the popup', () => {
    render(<JobPopup jobs={[job, { ...job, id: 2, state: 'queued' }]} onShowRuns={vi.fn()} />)
    expect(screen.getByText('Queued')).toBeInTheDocument()
    const link = screen.getByRole('button', { name: 'View analysis runs' })
    link.focus()
    fireEvent.keyDown(link, { key: 'Escape' })
    const toggle = screen.getByRole('button', { name: '2 job(s) running…' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
  })
})
