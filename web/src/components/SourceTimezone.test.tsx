import { fireEvent, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { api } from '../api'
import { renderWithProviders } from '../test/setup'
import { SourceTimezone } from './SourceTimezone'

vi.mock('../api', async original => ({
  ...(await original<typeof import('../api')>()), api: vi.fn(),
}))

it('shows a different source zone correctly and preserves custom editing', async () => {
  vi.mocked(api).mockResolvedValue({ zones: ['UTC', 'Pacific/Chatham', 'America/St_Johns'] })
  const onChange = vi.fn()
  const { rerender } = renderWithProviders(<SourceTimezone value="auto" onChange={onChange} />)
  const selector = screen.getByLabelText('Source timezone (when not recorded)')
  expect(selector).toHaveValue('auto')
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone
  const source = local === 'Pacific/Chatham' ? 'America/St_Johns' : 'Pacific/Chatham'
  rerender(<SourceTimezone value={source} onChange={onChange} />)
  expect(selector).toHaveValue('custom')
  expect(screen.getByRole('combobox', { name: 'Choose time zone…' })).toHaveValue(source)
  rerender(<SourceTimezone value="UTC" onChange={onChange} />)
  expect(selector).toHaveValue('UTC')
  expect(screen.queryByRole('combobox', { name: 'Choose time zone…' })).not.toBeInTheDocument()
  fireEvent.change(selector, { target: { value: 'custom' } })
  fireEvent.change(screen.getByRole('combobox', { name: 'Choose time zone…' }), { target: { value: '' } })
  expect(onChange).toHaveBeenCalledWith('')
  rerender(<SourceTimezone value="" onChange={onChange} />)
  expect(selector).toHaveValue('custom')
  expect(screen.getByRole('combobox', { name: 'Choose time zone…' })).toHaveValue('')
})
