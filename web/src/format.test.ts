// format.test.ts -- the time maths, exercised at offsets other than zero.
//
// WHY THIS FILE EXISTS AT ALL. Every fixture this project had rendered times
// at UTC+00:00, and at offset zero a shift applied twice is indistinguishable
// from a shift applied once, or from no shift at all. A whole class of defect
// -- double-shifting, shifting the wrong way, shifting in UTC mode -- is
// invisible there and appears the moment a log carries `+0200`.
//
// The law every test below is a statement of: the CLOCK READING on screen is
// the stored instant moved by the line's own offset EXACTLY ONCE in log mode,
// and not at all in UTC mode. Nothing here asserts a formatting nicety; each
// assertion is about which instant the analyst is being shown.
import { afterEach, describe, expect, it } from 'vitest'
import {
  formatDay, formatLogTime, formatOffset, formatSpan, setActiveTimeMode,
  storedTimeMode, TIME_KEY, zoneLabel,
} from './format'

/** Read a rendered stamp back as an instant. The renderer prints
 *  `YYYY-MM-DD HH:MM:SS` with no zone, so the test supplies the one the mode
 *  claims -- which is the whole point: if the stamp does not survive the
 *  round trip, the analyst is reading a different moment than the one
 *  stored. */
function readBack(stamp: string): number {
  const t = Date.parse(`${stamp.slice(0, 19).replace(' ', 'T')}Z`)
  expect(Number.isNaN(t), `unparseable stamp ${stamp}`).toBe(false)
  return t / 1000
}

// The offsets the case shapes actually produce: whole hours either way, a
// half-hour zone, and zero -- which must keep behaving like the others.
const OFFSETS = [0, 7200, -18000, 19800, -12600, 3600 * 14]

// 2024-03-17T22:45:10Z. Late enough in the day that a positive offset rolls
// the date forward and a negative one does not, so a day boundary is inside
// the reach of these numbers rather than a separate special case.
const EPOCH = Date.UTC(2024, 2, 17, 22, 45, 10) / 1000

afterEach(() => {
  setActiveTimeMode('log')
})

describe('formatLogTime', () => {
  it('renders the stored instant unchanged in UTC mode, at every offset', () => {
    // UTC mode exists so that two sources with different offsets can be laid
    // on one timeline. If the line's own offset leaked into that reading,
    // the timeline would be wrong by exactly the thing it was built to
    // remove -- and would still look plausible.
    for (const tz of OFFSETS) {
      expect(readBack(formatLogTime(EPOCH, tz, { mode: 'utc' })),
             `offset ${tz} leaked into UTC mode`).toBe(EPOCH)
    }
  })

  it('applies the offset exactly once in log mode', () => {
    // The defect this catches is the double shift. At +0000 a doubled shift
    // is zero and the test passes on broken code; at +0200 the reading is
    // two hours out and the analyst reports the wrong hour.
    for (const tz of OFFSETS) {
      const log = readBack(formatLogTime(EPOCH, tz, { mode: 'log' }))
      const utc = readBack(formatLogTime(EPOCH, tz, { mode: 'utc' }))
      expect(log - utc, `offset ${tz} was not applied exactly once`).toBe(tz)
    }
  })

  it('shifts a positive offset forward and a negative one back', () => {
    // Sign errors are the other half of the family, and they too vanish at
    // zero. Stated as literal readings so the direction is on the page.
    expect(formatLogTime(EPOCH, 7200, { mode: 'log' })).toBe('2024-03-18 00:45:10')
    expect(formatLogTime(EPOCH, -18000, { mode: 'log' })).toBe('2024-03-17 17:45:10')
    expect(formatLogTime(EPOCH, 19800, { mode: 'log' })).toBe('2024-03-18 04:15:10')
    expect(formatLogTime(EPOCH, -12600, { mode: 'log' })).toBe('2024-03-17 19:15:10')
  })

  it('follows the active mode when the call site names none', () => {
    // Most call sites pass no mode and rely on the module-level choice. A
    // helper that ignored it would render half the interface in one reading
    // and half in the other, with nothing on screen saying so.
    setActiveTimeMode('utc')
    expect(formatLogTime(EPOCH, 7200)).toBe(formatLogTime(EPOCH, 7200, { mode: 'utc' }))
    setActiveTimeMode('log')
    expect(formatLogTime(EPOCH, 7200)).toBe(formatLogTime(EPOCH, 7200, { mode: 'log' }))
  })

  it('states the zone of the reading it just produced, not of the line', () => {
    // A stamp that carries a zone is the one that gets pasted into a report.
    // If it named the log's offset while showing the UTC reading, the report
    // would carry a time and a contradicting zone.
    expect(formatLogTime(EPOCH, 7200, { withZone: true, mode: 'log' }))
      .toBe('2024-03-18 00:45:10 UTC+02:00')
    expect(formatLogTime(EPOCH, 7200, { withZone: true, mode: 'utc' }))
      .toBe('2024-03-17 22:45:10 UTC')
  })

  it('renders a dash rather than an epoch for a missing time', () => {
    expect(formatLogTime(null, 7200)).toBe('—')
    expect(formatLogTime(undefined, 7200)).toBe('—')
  })
})

describe('formatOffset', () => {
  it('names whole-hour offsets in both directions', () => {
    expect(formatOffset(7200)).toBe('UTC+02:00')
    expect(formatOffset(-18000)).toBe('UTC-05:00')
    expect(formatOffset(3600 * 14)).toBe('UTC+14:00')
  })

  it('names half-hour and three-quarter-hour offsets', () => {
    // A zone that is not a whole number of hours is where an
    // hours-only implementation quietly rounds the minutes away, and the
    // stated zone stops matching the stamp printed next to it.
    expect(formatOffset(19800)).toBe('UTC+05:30')
    expect(formatOffset(-12600)).toBe('UTC-03:30')
    expect(formatOffset(20700)).toBe('UTC+05:45')
  })

  it('calls zero UTC, which is the one name that is not a guess', () => {
    expect(formatOffset(0)).toBe('UTC')
    expect(formatOffset()).toBe('UTC')
  })

  it('never invents a zone abbreviation', () => {
    // `+0200` is CEST and equally EET and SAST. Printing a name would be a
    // guess wearing the clothes of a measurement, and this is the assertion
    // that keeps somebody from adding one later.
    for (const tz of OFFSETS) {
      expect(formatOffset(tz)).toMatch(/^UTC([+-]\d{2}:\d{2})?$/)
    }
  })
})

describe('zoneLabel', () => {
  it('reports UTC in UTC mode however the line was written', () => {
    for (const tz of OFFSETS) {
      expect(zoneLabel(tz, 'utc'), `offset ${tz} survived into the UTC label`)
        .toBe('UTC')
    }
  })

  it("reports the line's own offset in log mode", () => {
    expect(zoneLabel(7200, 'log')).toBe('UTC+02:00')
    expect(zoneLabel(-12600, 'log')).toBe('UTC-03:30')
    expect(zoneLabel(0, 'log')).toBe('UTC')
  })
})

describe('formatDay', () => {
  it('agrees with the stamp it stands next to', () => {
    // The day heading and the timestamps under it are rendered by different
    // functions. When they disagree, a request appears under the wrong date
    // and the sequence of the intrusion is misread.
    for (const mode of ['log', 'utc'] as const) {
      setActiveTimeMode(mode)
      for (const tz of OFFSETS) {
        expect(formatDay(EPOCH, tz), `day and stamp disagree at ${tz} in ${mode}`)
          .toBe(formatLogTime(EPOCH, tz, { mode }).slice(0, 10))
      }
    }
  })

  it('rolls the date forward when a positive offset crosses midnight', () => {
    setActiveTimeMode('log')
    expect(formatDay(EPOCH, 7200)).toBe('2024-03-18')
    setActiveTimeMode('utc')
    expect(formatDay(EPOCH, 7200)).toBe('2024-03-17')
  })

  it('rolls the date back when a negative offset crosses midnight', () => {
    const early = Date.UTC(2024, 2, 17, 1, 30, 0) / 1000
    setActiveTimeMode('log')
    expect(formatDay(early, -18000)).toBe('2024-03-16')
    setActiveTimeMode('utc')
    expect(formatDay(early, -18000)).toBe('2024-03-17')
  })

  it('renders a dash rather than 1970 for a missing time', () => {
    expect(formatDay(null, 7200)).toBe('—')
  })
})

describe('formatSpan', () => {
  it('does not depend on any offset, because a duration has none', () => {
    // A span is a difference between two instants. Both readings shift by
    // the same amount, so the answer must be identical in either mode --
    // anything else means an offset is being applied to only one end.
    const from = EPOCH
    const to = EPOCH + 3 * 3600
    setActiveTimeMode('log')
    const inLog = formatSpan(from, to)
    setActiveTimeMode('utc')
    expect(formatSpan(from, to)).toBe(inLog)
    expect(inLog).toBe('3 hours')
  })

  it('picks the unit the number belongs to', () => {
    expect(formatSpan(EPOCH, EPOCH + 45)).toBe('45 seconds')
    expect(formatSpan(EPOCH, EPOCH + 60)).toBe('1 minute')
    expect(formatSpan(EPOCH, EPOCH + 3600)).toBe('1 hour')
    expect(formatSpan(EPOCH, EPOCH + 86400)).toBe('1 day')
    expect(formatSpan(EPOCH, EPOCH + 86400 * 120)).toBe('120 days')
  })

  it('singularises exactly at one', () => {
    expect(formatSpan(EPOCH, EPOCH + 1)).toBe('1 second')
    expect(formatSpan(EPOCH, EPOCH + 2)).toBe('2 seconds')
  })

  it('never reports a negative span for reversed ends', () => {
    // First and last hit arrive from the server in whatever order the query
    // produced. "-3 hours of activity" in a report is worse than useless.
    expect(formatSpan(EPOCH + 3600, EPOCH)).toBe('0 seconds')
  })

  it('renders a dash when either end is missing', () => {
    expect(formatSpan(null, EPOCH)).toBe('—')
    expect(formatSpan(EPOCH, null)).toBe('—')
  })

  it('carries a rounded-up value into the next unit', () => {
    expect(formatSpan(EPOCH, EPOCH + 3599)).toBe('1 hour')
    expect(formatSpan(EPOCH, EPOCH + 86399)).toBe('1 day')
  })
})

describe('storedTimeMode', () => {
  it('defaults to the log reading when nothing is remembered', () => {
    expect(storedTimeMode()).toBe('log')
  })

  it('returns a remembered choice', () => {
    localStorage.setItem(TIME_KEY, 'utc')
    expect(storedTimeMode()).toBe('utc')
  })

  it('ignores a stored value that is not a mode', () => {
    // The key is in a storage the analyst can edit, and an unknown value
    // must not become a third rendering mode by accident.
    localStorage.setItem(TIME_KEY, 'local')
    expect(storedTimeMode()).toBe('log')
  })
})
