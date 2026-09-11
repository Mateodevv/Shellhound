import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocAttributes, type AttributeObservation } from './IocAttributes'
import { valueAttributes } from './iocAttributeValues'

vi.mock('../geo', () => ({ useGeo: () => ({ name: 'Germany', iso: 'de', special: false }) }))
const base: Ioc = { id: 1, type: 'other', value: 'test', tags: [], note: '', origin: '', added: '', first_seen: null, last_seen: null, links: [] }
const location: AttributeObservation = { id: 'a', kind: 'file-location', path: 'uploads/sample.txt', evidence_id: 1, active: true, first_seen: '', last_seen: '' }

describe('Type-specific IOC attributes', () => {
  it.each([
    ['ip', '198.51.100.1', 'Country / network range'],
    ['domain', 'example.test', 'DNS name'],
    ['url', 'https://example.test/example', 'Scheme'],
    ['email', 'user@example.test', 'Email domain'],
    ['path', '/example', 'Path type'],
    ['hash', 'a'.repeat(64), 'Hash algorithm'],
    ['file', 'a'.repeat(64), 'Content verified'],
    ['vulnerability', 'CVE-2026-12345', 'Evidence-backed associations'],
    ['user', 'test-user', 'Account context'],
    ['other', 'test-context', 'Case context'],
  ])('renders %s attributes', (type, value, label) => {
    renderWithProviders(<IocAttributes object={{ ...base, type, value }} observations={[]} relationships={[]} iocs={[]} />)
    expect(screen.getByText(label)).toBeVisible()
  })

  it('preserves URL path spelling and explicit default ports while omitting credentials and query contents', () => {
    const object = { ...base, type: 'url', value: 'https://analyst:synthetic-password@example.test:443/a/../b%2fc?token=synthetic-token#fragment' }
    const attrs = Object.fromEntries(valueAttributes(object))
    expect(attrs).toEqual({ scheme: 'https', host: 'example.test', port: '443', requestPath: '/a/../b%2fc' })
    expect(object.value).toContain('/a/../b%2fc')
    expect(JSON.stringify(attrs)).not.toMatch(/synthetic-password|synthetic-token|fragment/)
    expect(Object.fromEntries(valueAttributes({ ...base, type: 'url', value: 'https://[2001:db8::1]:8443/a' }))).toMatchObject({ host: '[2001:db8::1]', port: '8443' })
  })

  it('handles malformed values and hash-only records without inventing metadata', () => {
    expect(valueAttributes({ ...base, type: 'url', value: '/relative/path' })).toEqual([['urlParts', '']])
    expect(valueAttributes({ ...base, type: 'domain', value: 'example.test/path' })).toEqual([['dnsName', '']])
    expect(valueAttributes({ ...base, type: 'domain', value: 'bücher.example' })).toEqual([['dnsName', 'xn--bcher-kva.example']])
    expect(valueAttributes({ ...base, type: 'hash', value: 'z'.repeat(64) })).toEqual([['algorithm', '']])
    expect(valueAttributes({ ...base, type: 'hash', value: 'A'.repeat(40) })).toEqual([['algorithm', 'SHA-1']])
    expect(valueAttributes({ ...base, type: 'hash', value: 'a'.repeat(32) })).toEqual([['algorithm', 'MD5']])
    renderWithProviders(<IocAttributes object={{ ...base, type: 'hash', value: 'a'.repeat(64) }} observations={[]} relationships={[]} iocs={[]} />)
    expect(screen.getByText('Standalone hash')).toBeVisible()
    expect(screen.queryByText('Size')).not.toBeInTheDocument()
  })

  it('keeps file sources distinct, excludes withdrawn locations and preserves zero-byte size', () => {
    renderWithProviders(<IocAttributes object={{ ...base, type: 'file', file: { hashes: {}, names: ['sample.txt', 'renamed.txt'], size: 0, classification: '', verified_at: '2026-09-09T08:00:00' } }}
      observations={[location, { ...location, id: 'duplicate' }, { ...location, id: 'b', evidence_id: 2 }, { ...location, id: 'c', path: 'withdrawn.txt', active: false }]}
      relationships={[]} iocs={[]} />)
    expect(screen.getByText('0 bytes')).toBeVisible()
    expect(screen.getByText('sample.txt · renamed.txt')).toBeVisible()
    expect(screen.getAllByText('uploads/sample.txt')).toHaveLength(2)
    expect(screen.getByText('Evidence #1')).toBeVisible()
    expect(screen.getByText('Evidence #2')).toBeVisible()
    expect(screen.queryByText('withdrawn.txt')).not.toBeInTheDocument()
    expect(screen.getByText('2026-09-09 08:00:00')).toBeVisible()
  })

  it('shows explicit path context even when no free-text scope is saved', () => {
    renderWithProviders(<IocAttributes object={{ ...base, type: 'path', path_context: 'http-request', context: '' }} observations={[]} relationships={[]} iocs={[]} />)
    expect(screen.getByText('HTTP request path')).toBeVisible()
    expect(screen.getByText('Not recorded')).toBeVisible()
  })

  it('preserves separate locations when their evidence roots are not assigned', () => {
    renderWithProviders(<IocAttributes object={{ ...base, type: 'file' }} observations={[
      { ...location, evidence_id: null }, { ...location, id: 'other-source', evidence_id: null },
    ]} relationships={[]} iocs={[]} />)
    expect(screen.getAllByText('uploads/sample.txt')).toHaveLength(2)
  })

  it('navigates only to a file with a stored identity association', () => {
    const navigate = vi.fn()
    renderWithProviders(<IocAttributes object={{ ...base, type: 'hash', file_ids: [2] }} observations={[]} relationships={[]}
      iocs={[{ ...base, id: 2, type: 'file', value: 'associated-file' }, { ...base, id: 3, type: 'file', value: 'other-file' }]} onNavigate={navigate} />)
    fireEvent.click(screen.getByRole('button', { name: 'associated-file' }))
    expect(navigate).toHaveBeenCalledWith(2)
    expect(screen.queryByText('other-file')).not.toBeInTheDocument()
  })

  it('keeps CVE context and exploitation claims separate and filters withdrawn claims', () => {
    renderWithProviders(<IocAttributes object={{ ...base, type: 'vulnerability', value: 'CVE-2026-12345' }} observations={[]} iocs={[]} relationships={[
      { id: 1, src: 2, dst: 1, kind: 'cve-context', active: true },
      { id: 2, src: 3, dst: 1, kind: 'exploit-attempt', active: true },
      { id: 3, src: 4, dst: 1, kind: 'exploitation-confirmed', active: false },
    ]} />)
    expect(screen.getByText('Specific CVE context · 1')).toBeVisible()
    expect(screen.getByText('Exploitation attempt · 1')).toBeVisible()
    expect(screen.queryByText(/Confirmed exploitation/)).not.toBeInTheDocument()
    expect(screen.getByRole('link')).toHaveAttribute('href', 'https://www.cve.org/CVERecord?id=CVE-2026-12345')
  })
})
