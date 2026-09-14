/** Explicit language choice: no expensive, ambiguous automatic guessing. */
export type SyntaxToken = { text: string; className: string }
export type SyntaxLines = SyntaxToken[][]
export function syntaxLanguage(path: string, sample = ''): string | null {
  if (/<\?(?:php\b|=)/i.test(sample.slice(0, 8192))) return 'php-template'
  const name = path.replace(/\\/g, '/').split('/').pop()?.toLowerCase() ?? ''
  if (name === '.htaccess' || name === 'httpd.conf' || name === 'apache2.conf') return 'apache'
  if (name === 'nginx.conf') return 'nginx'
  const ext = name.replace(/\.(?:gz|bz2|xz)$/i, '').split('.').pop() ?? ''
  const languages: Record<string, string> = {
    php: 'php', php3: 'php', php4: 'php', php5: 'php', php7: 'php', php8: 'php', phtml: 'php', pht: 'php', inc: 'php',
    html: 'xml', htm: 'xml', xhtml: 'xml', xml: 'xml', svg: 'xml',
    js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
    css: 'css', json: 'json', sql: 'sql', py: 'python', sh: 'bash', bash: 'bash',
    yaml: 'yaml', yml: 'yaml', ini: 'ini',
  }
  return languages[ext] ?? null
}
export function syntaxLabel(language: string | null): string {
  return ({ 'php-template': 'PHP / HTML', php: 'PHP', xml: 'HTML / XML', javascript: 'JavaScript', typescript: 'TypeScript', css: 'CSS', json: 'JSON', sql: 'SQL', python: 'Python', bash: 'Shell', yaml: 'YAML', ini: 'INI', apache: 'Apache', nginx: 'Nginx' } as Record<string, string>)[language ?? ''] ?? ''
}
