import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { RevealFileButton } from './RevealFileButton'

vi.mock('../../api', async original => ({
  ...(await original<typeof import('../../api')>()), post: vi.fn(),
}))

beforeEach(() => { vi.mocked(post).mockReset() })

it('reveals only on explicit click and prevents duplicate clicks while pending', async () => {
  let finish!: (value: { ok: boolean }) => void
  vi.mocked(post).mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const path = 'C:\\Evidence folder\\sample notes.txt'
  renderWithProviders(<RevealFileButton slug="sample" path={path} />)
  const button = screen.getByRole('button', { name: 'Show in file manager' })
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(button)
  await waitFor(() => expect(button).toBeDisabled())
  fireEvent.click(button)
  expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/sample/reveal-file', { path })
  await act(async () => finish({ ok: true }))
  await waitFor(() => expect(button).toBeEnabled())
})

it('reports launch errors and allows retrying', async () => {
  vi.mocked(post).mockRejectedValueOnce(new Error('The local file manager is unavailable'))
    .mockResolvedValueOnce({ ok: true })
  renderWithProviders(<RevealFileButton slug="sample" path="/evidence/notes.txt" />)
  const button = screen.getByRole('button', { name: 'Show in file manager' })
  fireEvent.click(button)
  expect(await screen.findByRole('alert')).toHaveTextContent('The local file manager is unavailable')
  fireEvent.click(button)
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  expect(post).toHaveBeenCalledTimes(2)
})

it('does not reveal unavailable evidence', () => {
  renderWithProviders(<RevealFileButton slug="sample" path="/evidence/missing.txt" disabled />)
  const button = screen.getByRole('button', { name: 'Show in file manager' })
  expect(button).toBeDisabled()
  fireEvent.click(button)
  expect(post).not.toHaveBeenCalled()
})
