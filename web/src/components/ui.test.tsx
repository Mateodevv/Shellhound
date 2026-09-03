import { useState } from 'react'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { renderWithProviders } from '../test/setup'
import { Modal } from './ui'

function DialogHarness() {
  const [open, setOpen] = useState(false)
  return <>
    <button onClick={() => setOpen(true)}>Open review</button>
    <Modal open={open} onClose={() => setOpen(false)} title="Review artifact">
      <input aria-label="Reasoning" />
      <button>Last action</button>
    </Modal>
  </>
}

describe('accessible modal behavior', () => {
  it('traps focus, closes with Escape, and restores the opener', async () => {
    const user = userEvent.setup()
    renderWithProviders(<DialogHarness />)
    const opener = screen.getByRole('button', { name: 'Open review' })

    await user.click(opener)
    const close = screen.getByRole('button', { name: /Close/ })
    await waitFor(() => expect(close).toHaveFocus())

    await user.tab({ shift: true })
    expect(screen.getByRole('button', { name: 'Last action' })).toHaveFocus()
    await user.tab()
    expect(close).toHaveFocus()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })
})
