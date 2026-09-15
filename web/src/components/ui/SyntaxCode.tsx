import type { SyntaxToken } from '../../syntax'

export function SyntaxText({ text, tokens }: { text: string; tokens?: SyntaxToken[] }) {
  return <span className="syntax-code whitespace-pre-wrap break-all">{tokens ? tokens.map((token, index) => <span key={index} className={token.className || undefined}>{token.text}</span>) : text || ' '}</span>
}
