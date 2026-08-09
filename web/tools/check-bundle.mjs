import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const DIST = new URL('../dist/', import.meta.url)
const ENTRY_LIMIT = 700 * 1024
const JS_LIMIT = 1_350 * 1024
const DIST_LIMIT = 3_500 * 1024

function filesBelow(path) {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name)
    return entry.isDirectory() ? filesBelow(child) : [child]
  })
}

function kib(bytes) {
  return `${(bytes / 1024).toFixed(1)} KiB`
}

const index = readFileSync(new URL('index.html', DIST), 'utf8')
const entryName = index.match(/<script[^>]+src="\/?(assets\/[^"]+\.js)"/)?.[1]
if (!entryName) throw new Error('Could not find the entry script in dist/index.html')

const files = filesBelow(fileURLToPath(DIST))
const entryBytes = statSync(new URL(entryName, DIST)).size
const jsBytes = files.filter((path) => path.endsWith('.js'))
  .reduce((sum, path) => sum + statSync(path).size, 0)
const distBytes = files.reduce((sum, path) => sum + statSync(path).size, 0)

console.log(`Entry: ${kib(entryBytes)} / ${kib(ENTRY_LIMIT)}`)
console.log(`JavaScript: ${kib(jsBytes)} / ${kib(JS_LIMIT)}`)
console.log(`Distribution: ${kib(distBytes)} / ${kib(DIST_LIMIT)}`)

const failures = [
  entryBytes > ENTRY_LIMIT && 'entry chunk',
  jsBytes > JS_LIMIT && 'total JavaScript',
  distBytes > DIST_LIMIT && 'complete distribution',
].filter(Boolean)

if (failures.length) {
  throw new Error(`Bundle budget exceeded: ${failures.join(', ')}`)
}
