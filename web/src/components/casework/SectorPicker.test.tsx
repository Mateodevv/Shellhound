import { useState } from 'react'
import { fireEvent, screen } from '@testing-library/react'
import { expect, it } from 'vitest'
import { newCaseProfile, type CaseProfile } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { SectorPicker } from './SectorPicker'

it('uses fixed main sectors and retains legacy choices without a create action', () => {
  function Form() {
    const [profile, setProfile] = useState<CaseProfile>({ ...newCaseProfile(), sectors: ['Legacy sector'], subsectors: [{ name: 'Manual activity', sector: 'Legacy sector' }] })
    return <><SectorPicker sectors={['Technology', 'Healthcare']} profile={profile} onChange={setProfile} required /><output>{JSON.stringify(profile)}</output></>
  }
  renderWithProviders(<Form />)
  expect(screen.getByRole('checkbox', { name: 'Legacy sector' })).toBeChecked()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Technology' }))
  expect(screen.getByRole('checkbox', { name: 'Technology' })).toBeChecked()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Legacy sector' }))
  expect(screen.getByRole('status')).not.toHaveTextContent('Manual activity')
  expect(screen.queryByRole('button', { name: 'New sector' })).not.toBeInTheDocument()
})
