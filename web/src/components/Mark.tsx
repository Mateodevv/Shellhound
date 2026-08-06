// Mark.tsx -- the SHELLHOUND mark, in one place.
//
// The same geometry as web/public/favicon.svg. It is duplicated in exactly
// two files and nowhere else: the favicon has to be a standalone .svg the
// browser can fetch before any script runs, and this is the component the
// interface draws. If one changes, change the other -- there is a test that
// says so.
//
// WHAT IT MEANS: a trace that runs flat, steps up once and stays up, with
// the knee marked in severity red. The finding this tool exists to produce
// is almost never a spike but a level change that does not come back down --
// a shell dropped, an admin row planted, a backdoor that keeps answering.
// Everything measured is accent blue; exactly one point is red.
//
// `currentColor` is deliberately NOT used. The two colours carry the
// separation between measurement and verdict, and a mark that takes the
// colour of whatever surrounds it would lose it.

export function Mark({ size = 32, tile = true, className }: {
  size?: number
  /** The rounded near-black backing. On for a standalone badge, off when the
   *  mark sits on a panel that already provides one. */
  tile?: boolean
  className?: string
}) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} className={className}
      role="img" aria-label="SHELLHOUND">
      {tile && <rect width="32" height="32" rx="7" fill="#0b0e14" />}
      <path d="M5 24H16V10h11" fill="none" stroke="#3987e5" strokeWidth="4"
        strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="16" cy="10" r="3.6" fill="#d03b3b" />
    </svg>
  )
}
