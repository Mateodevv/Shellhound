// literals.test.ts -- the guard against prose that never went through tr().
//
// "Import fehlgeschlagen:" stood hardcoded and German in Start.tsx, the
// "Aufnehmen" button before it, "Gesichtet" in the findings list -- always
// the same class of defect: a JSX text literal written in whichever language
// the author was thinking in, invisible until someone switches the
// interface. A catalogue key forgotten in ONE language falls back to
// English; a literal falls back to nothing.
//
// The scan is textual, not an AST walk -- deliberately cheap. It extracts
// JSX text nodes (the stretches between > and < that contain no braces) and
// flags two shapes: anything carrying German-specific characters, and any
// multi-word prose that is not on the short allowlist of terms the
// interface uses untranslated in both languages.
/// <reference types="node" />
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative } from 'node:path'

// Under jsdom, import.meta.url is no file: URL -- but vitest runs with the
// web/ directory as its working directory, and that is stable.
const SRC = join(process.cwd(), 'src')

/** Terms that stand in the interface as-is, in both languages. */
const ALLOWED = new Set([
  'True Positive', 'False Positive', 'IOC Box',
  // Proper names: the view heading (nav.cms says the same in both
  // catalogues) and the country database's product name.
  'CMS Inventory', 'DB-IP Country Lite',
])

function tsxFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...tsxFiles(full))
    else if (entry.name.endsWith('.tsx') && !entry.name.endsWith('.test.tsx'))
      out.push(full)
  }
  return out
}

/** Strip comments -- prose lives there legitimately. Line comments are only
 *  taken when they START the line, so `https://` in a string survives. */
function stripComments(code: string): string {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
}

function findings(file: string): string[] {
  const code = stripComments(readFileSync(file, 'utf-8'))
  const out: string[] = []
  // A JSX text node: from a closing > (or the } of an interpolation) to
  // the next opening < (or the { of one). The interpolation ends matter:
  // the defect that motivated this guard read
  // `Import fehlgeschlagen: {String(error)}` -- prose ending at a brace,
  // which a plain >…< scan walks straight past.
  for (const match of code.matchAll(/[>}]([^<>{}]+)[<{]/g)) {
    const text = match[1].replace(/\s+/g, ' ').trim()
    // The allowlist is compared without the glue a text node carries
    // around an interpolation ("True Positive," with its comma).
    const bare = text.replace(/^[\s.,:;·–—-]+|[\s.,:;·–—-]+$/g, '')
    if (!text || ALLOWED.has(bare)) continue
    // Code that happens to sit between the delimiters (import lines,
    // comparisons, arrow bodies, declarations) is not a text node --
    // quotes, =, (), ; and leading keywords give it away.
    if (/[='"();`$_[\]]/.test(text)) continue
    if (/^(import|export|interface|const|type|function|class|return|else|extends)\b/.test(text)) continue
    const german = /[äöüÄÖÜß„“”]/.test(text)
    const prose = /\p{L}{2,}[ ]\p{L}{2,}/u.test(text)
    if (german || prose) {
      const line = code.slice(0, match.index).split('\n').length
      out.push(`${relative(SRC, file)}:${line}  »${text}«`)
    }
  }
  return out
}

describe('JSX text literals', () => {
  it('every piece of prose goes through tr()', () => {
    const hits = tsxFiles(SRC).flatMap(findings)
    expect(hits, 'hardcoded prose outside tr():\n' + hits.join('\n')).toEqual([])
  })
})
