import { afterEach, expect, it, vi } from 'vitest'
import { act, render, renderHook } from '@testing-library/react'
import { syntaxLanguage } from './syntax'
import { highlightLines } from './syntaxHighlight'
import { SyntaxText } from './components/ui/SyntaxCode'
import { useSyntaxLines } from './useSyntaxLines'

it.each([
  ['sample.xml.php','php'], ['sample.PHTML','php'], ['export.sql.gz','sql'],
  ['script.js','javascript'], ['document.html','xml'], ['settings.json','json'],
  ['.htaccess','apache'], ['sample.txt',null], ['image.bin',null],
])('selects a known grammar for %s', (path, expected) => {
  expect(syntaxLanguage(path)).toBe(expected)
})
it('recognizes PHP embedded in HTML even with a misleading filename', () => {
  expect(syntaxLanguage('sample.jpg', '<p>Example</p><?php echo "hello"; ?>')).toBe('php-template')
})
it.each([
  ['php', ['<?php', '/* first comment', 'second comment */', '$value = "hello";', 'echo strlen($value);', '']],
  ['php-template', ['<p>Example</p>', '<?php echo "hello"; ?>']],
  ['javascript', ['const message = "hello";', '// second line', '']],
  ['sql', ["SELECT name FROM items WHERE id = 1;", '']],
  ['json', ['{ "name": "example", "count": 42 }']],
])('preserves exact source lines and adds tokens for %s', (language, lines) => {
  const highlighted = highlightLines(language, lines)
  expect(highlighted?.map(line => line.map(token => token.text).join(''))).toEqual(lines)
  expect(highlighted?.flat().some(token => token.className.includes('hljs-'))).toBe(true)
})
it('renders markup evidence as inert text without creating elements or altering copied source', () => {
  const text = '<b title="example">Example & text</b>'
  const tokens = highlightLines('xml', [text])![0]
  const { container } = render(<SyntaxText text={text} tokens={tokens} />)
  expect(container.textContent).toBe(text)
  expect(container.querySelector('b')).toBeNull()
  expect(container.querySelector('[title]')).toBeNull()
})
it('leaves oversized and minified windows as plain text', () => {
  expect(highlightLines('javascript', ['a'.repeat(33000)])).toBeNull()
  expect(highlightLines('sql', Array(21000).fill('-- note'))).toBeNull()
})

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })
it('discards late worker results when a new file is opened and terminates slow parsing', () => {
  vi.useFakeTimers()
  const workers: FakeWorker[] = []
  class FakeWorker {
    onmessage?: (event: {data: unknown}) => void
    onerror?: () => void
    terminate = vi.fn()
    postMessage = vi.fn()
    constructor() { workers.push(this) }
  }
  vi.stubGlobal('Worker', FakeWorker)
  const first=['const one = 1;'], second=['const two = 2;']
  const { result, rerender, unmount } = renderHook(({path,lines}) => useSyntaxLines(path,lines), {initialProps:{path:'one.js',lines:first}})
  expect(result.current.tokens).toBeNull()
  rerender({path:'two.js',lines:second})
  expect(workers[0].terminate).toHaveBeenCalled()
  act(() => workers[0].onmessage?.({data:[[{text:'old',className:'hljs-keyword'}]]}))
  expect(result.current.tokens).toBeNull()
  act(() => vi.advanceTimersByTime(2001))
  expect(workers[1].terminate).toHaveBeenCalled()
  act(() => workers[1].onmessage?.({data:[[{text:'late',className:'hljs-keyword'}]]}))
  expect(result.current.tokens).toBeNull()
  unmount()
})

it.each([
  ['<?php', '', '$value = "cut off'],
  ['<?php', '/* unfinished comment'],
  ['<p>Example</p><?php echo "done"; ?>', '<?php', '$next = "cut off'],
])('highlights a truncated PHP preview without changing or completing its source', (...lines) => {
  const tokens = highlightLines('php-template', lines)!
  expect(tokens.map(line => line.map(token => token.text).join(''))).toEqual(lines)
  const last = tokens.at(-1)!
  expect(last.some(token => /hljs-(string|comment)/.test(token.className))).toBe(true)
})
