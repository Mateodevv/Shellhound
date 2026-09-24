import { expect, it } from 'vitest'
import { iocCategories, inIocCategory } from './ctiSelectionModel'
import { iocGroups } from '../iocs/iocGroups'
it('shares all IOC Box groups and keeps software, email, user and path out of Other', () => {
 expect(iocCategories).toEqual(iocGroups.map(group=>group.id))
 for (const type of ['software','email','user','path']) {
  expect(inIocCategory(type,type)).toBe(true)
  expect(inIocCategory(type,'other')).toBe(false)
 }
 expect(inIocCategory('other','other')).toBe(true)
})
