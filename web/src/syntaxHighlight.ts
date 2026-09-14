import { createLowlight } from 'lowlight'
import php from 'highlight.js/lib/languages/php'
import phpTemplate from 'highlight.js/lib/languages/php-template'
import xml from 'highlight.js/lib/languages/xml'
import javascript from 'highlight.js/lib/languages/javascript'
import typescript from 'highlight.js/lib/languages/typescript'
import css from 'highlight.js/lib/languages/css'
import json from 'highlight.js/lib/languages/json'
import sql from 'highlight.js/lib/languages/sql'
import python from 'highlight.js/lib/languages/python'
import bash from 'highlight.js/lib/languages/bash'
import yaml from 'highlight.js/lib/languages/yaml'
import ini from 'highlight.js/lib/languages/ini'
import apache from 'highlight.js/lib/languages/apache'
import nginx from 'highlight.js/lib/languages/nginx'
import type { SyntaxLines } from './syntax'

const highlighter = createLowlight({ php, 'php-template': phpTemplate, xml, javascript, typescript, css, json, sql, python, bash, yaml, ini, apache, nginx })
/** Convert only AST text and class names. Evidence never becomes HTML. */
export function highlightLines(language: string, lines: string[]): SyntaxLines | null {
  const text = lines.join('\n')
  if (text.length > 270_000 || lines.length > 20_000 || lines.some(line => line.length > 32_000)) return null
  // The template grammar defers unfinished PHP strings/comments until the
  // closing delimiter. Bounded evidence previews often end before that point.
  // Parse the final open PHP block directly, without inventing closing text.
  const openings = language === 'php-template' ? [...text.matchAll(/<\?(?:php\b|=)/gi)] : []
  const lastOpening = openings.at(-1)?.index
  const openPhp = lastOpening != null && text.indexOf('?>', lastOpening) < 0
  const tree = openPhp
    ? highlighter.highlight('php-template', text.slice(0, lastOpening))
    : highlighter.highlight(language, text)
  if (openPhp) tree.children.push(...highlighter.highlight('php', text.slice(lastOpening)).children)
  const output: SyntaxLines = [[]]
  let tokens = 0
  function walk(node: { type: string; value?: string; properties?: { className?: unknown }; children?: unknown[] }, inherited = '') {
    if (++tokens > 16_000) throw new Error('Token budget exceeded')
    const classes = Array.isArray(node.properties?.className) ? node.properties.className.filter(value => typeof value === 'string' && /^[a-zA-Z0-9_-]+$/.test(value)).join(' ') : ''
    const className = [inherited, classes].filter(Boolean).join(' ')
    if (node.type === 'text') {
      const parts = (node.value ?? '').split('\n')
      parts.forEach((part, index) => {
        if (index) output.push([])
        if (part) output[output.length - 1].push({ text: part, className })
      })
    } else if (node.children) {
      for (const child of node.children) walk(child as typeof node, className)
    }
  }
  walk(tree)
  if (output.length !== lines.length || output.some((line, i) => line.map(token => token.text).join('') !== lines[i])) return null
  return output
}
