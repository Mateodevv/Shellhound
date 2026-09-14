import { useState } from 'react'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { newCaseProfile } from '../opencti'
import { renderWithProviders } from '../test/setup'
import { SectorPicker } from './SectorPicker'

const sectors = [
  { id: '1', name: 'Technology', parents: [], subsector: false },
  { id: '2', name: 'Manufacturing', parents: [], subsector: false },
  { id: '3', name: 'Software', parents: ['Technology'], subsector: true },
]
function setup(empty = false) {
  const onCreate = vi.fn()
  const onSubmit = vi.fn()
  function Harness() {
    const [profile, setProfile] = useState(newCaseProfile())
    return <form onSubmit={event => { event.preventDefault(); onSubmit() }}>
      <SectorPicker sectors={empty ? [] : sectors} profile={profile} onChange={setProfile} required loading={false} onCreate={onCreate} />
      <button type="button">Outside</button>
    </form>
  }
  renderWithProviders(<Harness />)
  return { user: userEvent.setup(), input: screen.getByRole('combobox'), onCreate, onSubmit }
}

it('finds subsectors directly and includes their parent, without closing after selection', async () => {
  const { user, input } = setup()
  await user.type(input, 'soft')
  expect(screen.queryByRole('option', { name: 'Manufacturing' })).not.toBeInTheDocument()
  await user.click(screen.getByRole('option', { name: 'Technology → Software' }))
  expect(screen.getByRole('listbox')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Remove tag Technology' })).toBeVisible()
  expect(screen.getByRole('option', { name: 'Technology → Software' })).toHaveAttribute('aria-selected', 'true')
  await user.clear(input)
  await user.click(screen.getByRole('option', { name: 'Manufacturing' }))
  expect(screen.getByRole('option', { name: 'Technology' })).toHaveAttribute('aria-selected', 'true')
  await user.click(screen.getByRole('button', { name: 'Remove tag Technology' }))
  expect(screen.queryByRole('button', { name: 'Remove tag Technology → Software' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Remove tag Manufacturing' })).toBeVisible()
})

it('keeps the sector selected when only its subsector is removed', async () => {
  const { user, input } = setup()
  await user.click(input)
  await user.click(screen.getByRole('option', { name: 'Technology → Software' }))
  await user.click(screen.getByRole('button', { name: 'Remove tag Technology → Software' }))
  expect(screen.getByRole('button', { name: 'Remove tag Technology' })).toBeVisible()
})

it('supports keyboard selection and escape without submitting the wizard', async () => {
  const { user, input, onSubmit } = setup()
  await user.type(input, 'soft')
  await user.keyboard('{ArrowUp}{Enter}')
  expect(screen.getByRole('option', { name: 'Technology → Software' })).toHaveAttribute('aria-selected', 'true')
  expect(input).toHaveAttribute('aria-activedescendant', screen.getByRole('option').id)
  await user.keyboard('{Escape}')
  expect(input).toHaveAttribute('aria-expanded', 'false')
  expect(input).toHaveFocus()
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  expect(onSubmit).not.toHaveBeenCalled()
  await user.keyboard('{ArrowDown}{Enter}')
  expect(screen.getByRole('option')).toHaveAttribute('aria-selected', 'false')
})

it('prefills a new entry from an unmatched search even when the taxonomy is empty', async () => {
  const { user, input, onCreate } = setup(true)
  await user.type(input, 'Custom industry')
  expect(screen.getByRole('status')).toHaveTextContent('No matching')
  expect(screen.getByRole('button', { name: 'New subsector' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: 'New sector' }))
  expect(onCreate).toHaveBeenCalledWith('sector', 'Custom industry')
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
})

it('closes on outside focus and shows matching children when searching by parent', async () => {
  const { user, input } = setup()
  await user.type(input, 'technology')
  expect(within(screen.getByRole('listbox')).getAllByRole('option')).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Outside' }))
  expect(input).toHaveAttribute('aria-expanded', 'false')
})
