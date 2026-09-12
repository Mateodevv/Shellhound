import { describe, expect, it } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWithProviders } from '../test/setup'
import { ConnectorCapabilities, connectorTargets } from './ConnectorCapabilities'

describe('Shellhound connector capabilities', () => {
  it('maps file scopes to files and hashes and excludes sample-only targets', () => {
    expect(connectorTargets(['StixFile', 'Artifact']).map(target => target.type)).toEqual(['file', 'hash'])
    expect(connectorTargets(['Artifact', 'External-Reference'])).toEqual([])
    expect(connectorTargets(['vulnerability']).map(target => target.type)).toEqual(['vulnerability'])
    expect(connectorTargets(['Stix-Cyber-Observable']).map(target => target.type)).not.toContain('vulnerability')
  })

  it('reuses file badges and explains the lookup on keyboard focus', async () => {
    const { container } = renderWithProviders(<ConnectorCapabilities connector={{ id: 'vt', name: 'VirusTotal', active: true, auto: false, scope: ['StixFile', 'Artifact'] }} />)
    expect(screen.getByText('File')).toHaveClass('ioc-type-badge')
    expect(screen.getByText('Hash')).toHaveClass('ioc-type-badge')
    expect(screen.queryByText('Artifact')).not.toBeInTheDocument()
    fireEvent.focus(container.querySelector('[tabindex="0"]')!)
    const tooltip = await screen.findByRole('tooltip')
    expect(tooltip).toHaveTextContent('Queries VirusTotal using file hashes')
    expect(tooltip).toHaveTextContent('antivirus detections')
    expect(tooltip).toHaveTextContent('without attached file content')
  })

  it('preserves IPv4 and IPv6 distinctions', () => {
    renderWithProviders(<ConnectorCapabilities connector={{ id: 'abuse', name: 'AbuseIPDB', active: true, auto: false, scope: ['IPv4-Addr', 'IPv6-Addr'] }} />)
    expect(screen.getByText('IPv4')).toHaveClass('ioc-type-badge')
    expect(screen.getByText('IPv6')).toHaveClass('ioc-type-badge')
  })
})
