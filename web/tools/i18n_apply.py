#!/usr/bin/env python3
"""Replace German literals in one view with catalogue lookups.

    python tools/i18n_apply.py <file.tsx> <mapping.json>

The mapping is {"german text": ["key", "english text"], ...}. The script
handles the three places a literal can sit and gets the syntax right for
each, which is exactly where hand-editing goes wrong:

    attribute:  title="Text"      ->  title={tr('key')}
    expression: hint={'Text'}     ->  hint={tr('key')}
    child:      >Text<            ->  >{tr('key')}<

It also appends any new keys to both catalogues, so a translated string
cannot silently end up without an entry.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'src'


def literal(text: str) -> str:
    """A TS string literal for `text`, quoted so it needs no escaping."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def apply_to_source(src: str, mapping: dict) -> tuple[str, int]:
    hits = 0
    for german, (key, _english) in mapping.items():
        call = f"tr('{key}')"
        for quote in ('"', "'"):
            # als Attributwert -> geschweifte Klammern
            attr = f'={quote}{german}{quote}'
            if attr in src:
                hits += src.count(attr)
                src = src.replace(attr, '={' + call + '}')
            # innerhalb eines Ausdrucks -> nackter Aufruf
            plain = f'{quote}{german}{quote}'
            if plain in src:
                hits += src.count(plain)
                src = src.replace(plain, call)
        # als Kindknoten
        for a, b in ((f'>{german}<', '>{' + call + '}<'),
                     (f'>\n          {german}\n', '>\n          {' + call + '}\n')):
            if a in src:
                hits += src.count(a)
                src = src.replace(a, b)
    return src, hits


def ensure_hook(src: str, rel_i18n: str) -> str:
    if 'const tr = useT()' in src:
        pass
    if 'useT' not in src:
        first = src.index('import ')
        src = src[:first] + f"import {{ useT }} from '{rel_i18n}'\n" + src[first:]
    return src


def append_keys(mapping: dict) -> int:
    added = 0
    for cat, which in (('en.ts', 1), ('de.ts', 0)):
        path = ROOT / 'i18n' / cat
        text = path.read_text(encoding='utf-8')
        new = ''
        for german, pair in mapping.items():
            key = pair[0]
            value = pair[1] if which else german
            if f"'{key}':" in text:
                continue
            new += f"  '{key}': {literal(value)},\n"
            added += 1
        if new:
            text = text.rstrip().rstrip('}').rstrip() + '\n\n' + new + '}\n'
            path.write_text(text, encoding='utf-8')
    return added


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target = ROOT / sys.argv[1]
    mapping = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
    src = target.read_text(encoding='utf-8')
    src, hits = apply_to_source(src, mapping)
    rel = '../i18n' if target.parent.name in ('views', 'components') else './i18n'
    src = ensure_hook(src, rel)
    target.write_text(src, encoding='utf-8')
    added = append_keys(mapping)
    print(f'{target.name}: {hits} literal(s) replaced, {added} catalogue entries added')
    return 0


if __name__ == '__main__':
    sys.exit(main())
