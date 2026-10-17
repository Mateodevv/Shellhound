"""Bounded, straight-line evidence for indirect PHP execution.

This is an original conservative pattern analyser, not a PHP interpreter. It
folds literal function names and follows simple copies/decoders in one block.
Unknown expressions, calls and scope boundaries discard state. No sample code
is executed and decoded values are never reparsed as source.
"""
import base64
import binascii
import codecs
import re
from dataclasses import dataclass, replace

MAX_LITERAL = 4096
MAX_TOKENS = 128
MAX_STATEMENT = 8192
MAX_VARIABLES = 64
MAX_DEPTH = 8

INDIRECT = 'webshell.indirect_input'
OBFUSCATED = 'webshell.obfuscated_call'
DECODED = 'webshell.decoded_execution'
RULE_IDS = frozenset((INDIRECT, OBFUSCATED, DECODED))
SINKS = frozenset((b'eval', b'assert', b'system', b'exec', b'shell_exec',
                   b'passthru', b'popen', b'proc_open', b'pcntl_exec'))
# PHP language constructs cannot be invoked as variable functions.
CALLABLE_SINKS = SINKS - {b'eval'}
DECODERS = frozenset((b'base64_decode', b'str_rot13', b'strrev', b'hex2bin'))
SOURCES = frozenset((b'$_GET', b'$_POST', b'$_REQUEST', b'$_COOKIE', b'$_FILES',
                    b'$_SERVER', b'$_ENV', b'$HTTP_GET_VARS', b'$HTTP_POST_VARS',
                    b'$HTTP_COOKIE_VARS', b'$HTTP_SERVER_VARS'))
_OPEN = re.compile(rb'<\?(?:php\b|=|(?!xml\b))', re.I)
_TOKEN = re.compile(
    rb'''(?s)\s+|/\*.*?(?:\*/|$)|//(?:(?!\?>)[^\r\n])*|\#(?!\[)(?:(?!\?>)[^\r\n])*|'''
    rb'''<<<[ \t]*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Za-z_]\w*))[ \t]*\r?\n|'''
    rb'''\?>|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|'''
    rb'''\$[A-Za-z_]\w*|[A-Za-z_]\w*|[0-9]+|\?->|->|::|=>|\.=|===|==|!=|<=|>=|\+\+|--|&&|\|\||.''')
_DIRECT_HINT = re.compile(rb'\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func)\s*\(', re.I)
_VARIABLE_CALL = re.compile(rb'(\$[A-Za-z_]\w*)\s*\(')
_ASSIGN_HINT = re.compile(
    rb'''(\$[A-Za-z_]\w*)\s*=\s*(?:['"]|\$[A-Za-z_]|(?:base64_decode|str_rot13|strrev|hex2bin)\s*\()''', re.I)


@dataclass(frozen=True, slots=True)
class Token:
    text: bytes
    offset: int
    end: int
    literal: bool = False


@dataclass(frozen=True, slots=True)
class Value:
    constant: bytes | None = None
    source: int | None = None
    decoded: bool = False
    obfuscated: bool = False
    hops: int = 0
    decoded_at: int | None = None


UNKNOWN = Value()


@dataclass(frozen=True, slots=True)
class Evidence:
    rule_id: str
    offset: int
    source: int | None
    function: bytes
    decoded_at: int | None = None


def _literal(text):
    if len(text) > MAX_LITERAL or text[:1] == b'`':
        return UNKNOWN
    body = text[1:-1]
    if text[:1] == b"'":
        result = body.replace(b"\\'", b"'").replace(b'\\\\', b'\\')
    else:
        # Interpolated strings are not constants. Recognising them safely needs
        # PHP's full string grammar; refusing them avoids inventing a callee.
        if b'$' in body:
            return UNKNOWN
        def escape(match):
            value = match[0][1:]
            if value[:1].lower() == b'x':
                return bytes((int(value[1:], 16),))
            if value[:1] in b'01234567':
                return bytes((int(value, 8) % 256,))
            return {b'n': b'\n', b'r': b'\r', b't': b'\t', b'\\': b'\\',
                    b'"': b'"', b'$': b'$'}.get(value, match[0])
        result = re.sub(rb'\\(?:x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)', escape, body)
    return Value(constant=result, obfuscated=result != body)


def _tokens(raw):
    cursor, active = 0, False
    while cursor < len(raw):
        if not active:
            opening = _OPEN.search(raw, cursor)
            if opening is None:
                return
            yield Token(b';boundary', opening.start(), opening.end())
            cursor, active = opening.end(), True
        match = _TOKEN.match(raw, cursor)
        text = match[0]
        cursor = match.end()
        if text.isspace() or text.startswith((b'/*', b'//')) or (text.startswith(b'#') and not text.startswith(b'#[')):
            continue
        if text == b'?>':
            active = False
            yield Token(b';boundary', match.start(), match.end())
        elif text.startswith(b'<<<'):
            label = next(value for value in match.groups() if value is not None)
            closing = re.compile(rb'(?m)^[ \t]*' + re.escape(label) + rb'\b').search(raw, cursor)
            cursor = closing.end() if closing else len(raw)
            yield Token(b';boundary', match.start(), cursor)
        else:
            quoted = text[:1] in (b"'", b'"', b'`')
            if quoted and len(text) == 1:
                # The quoted-token alternative failed: this is an unterminated
                # literal, not PHP statements embedded in its remaining text.
                return
            # Bound retained token data even when the source literal is huge.
            if len(text) > MAX_LITERAL:
                text = b';oversized'
            yield Token(text, match.start(), match.end(), quoted)


def _concat(left, right):
    constant = None
    if left.constant is not None and right.constant is not None:
        combined = left.constant + right.constant
        if len(combined) <= MAX_LITERAL:
            constant = combined
    return Value(constant, left.source if left.source is not None else right.source,
                 left.decoded or right.decoded, True, max(left.hops, right.hops),
                 left.decoded_at if left.decoded_at is not None else right.decoded_at)


def _decode(name, value, offset):
    result = None
    if value.constant is not None:
        try:
            if name == b'base64_decode':
                encoded = re.sub(rb'\s+', b'', value.constant)
                result = base64.b64decode(encoded, validate=True)
            elif name == b'str_rot13':
                result = codecs.encode(value.constant.decode('latin1'), 'rot13').encode('latin1')
            elif name == b'strrev':
                result = value.constant[::-1]
            elif name == b'hex2bin':
                if len(value.constant) % 2 or re.fullmatch(rb'[0-9a-fA-F]*', value.constant) is None:
                    return UNKNOWN
                result = bytes.fromhex(value.constant.decode('ascii'))
        except (ValueError, UnicodeError, binascii.Error):
            return UNKNOWN
    return Value(result, value.source, True, True, value.hops, offset)


class _Expression:
    def __init__(self, tokens, variables):
        self.tokens, self.variables = tokens, variables.copy()
        self.cursor = 0
        self.evidence = []

    def peek(self, value=None):
        token = self.tokens[self.cursor] if self.cursor < len(self.tokens) else None
        return token if value is None else token is not None and token.text == value

    def take(self, value):
        if not self.peek(value):
            raise ValueError('Unsupported expression')
        self.cursor += 1

    def expression(self, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('Expression depth limit')
        token = self.peek()
        if token is None:
            raise ValueError('Missing value')
        if token.text.startswith(b'$') and self.cursor + 1 < len(self.tokens) and self.tokens[self.cursor + 1].text == b'=':
            self.cursor += 2
            value = replace(self.expression(depth + 1), hops=1)
            self.variables[token.text] = value
            return value
        value = self.atom(depth)
        while self.peek(b'.'):
            self.cursor += 1
            value = _concat(value, self.atom(depth + 1))
        return value

    def atom(self, depth):
        if depth > MAX_DEPTH or self.peek() is None:
            raise ValueError('Invalid atom')
        token = self.peek()
        self.cursor += 1
        if token.text == b'@':
            return self.atom(depth + 1)
        if token.text == b'\\':
            if self.peek() is None or re.fullmatch(rb'[A-Za-z_]\w*', self.peek().text) is None:
                raise ValueError('Unsupported qualified expression')
            return self.atom(depth + 1)
        direct = None
        if token.literal:
            value = _literal(token.text)
        elif token.text.startswith(b'$'):
            value = UNKNOWN if token.text in SOURCES else self.variables.get(token.text, UNKNOWN)
        elif token.text == b'(':
            value = self.expression(depth + 1)
            self.take(b')')
        elif re.fullmatch(rb'[A-Za-z_]\w*', token.text):
            direct, value = token.text.lower(), UNKNOWN
        elif token.text.isdigit():
            value = UNKNOWN
        else:
            raise ValueError('Unsupported atom')
        while self.peek(b'['):
            # Only direct superglobal indexing is understood; arbitrary arrays
            # or object properties must not inherit a scalar variable's value.
            self.cursor += 1
            index = self.expression(depth + 1)
            self.take(b']')
            value = Value(source=token.offset) if token.text in SOURCES else UNKNOWN
            if token.text in (b'$_SERVER', b'$_ENV', b'$HTTP_SERVER_VARS'):
                if index.constant is None or not (index.constant.startswith(b'HTTP_') or index.constant in
                        (b'QUERY_STRING', b'REQUEST_URI', b'PATH_INFO', b'PHP_AUTH_USER', b'PHP_AUTH_PW')):
                    value = UNKNOWN
        if self.peek(b'('):
            name = direct if direct is not None else (value.constant.lower() if value.constant is not None else None)
            self.cursor += 1
            arguments = []
            while not self.peek(b')'):
                arguments.append(self.expression(depth + 1))
                if self.peek(b','):
                    self.cursor += 1
                else:
                    break
            self.take(b')')
            first = arguments[0] if arguments else UNKNOWN
            if name == b'getenv' and len(arguments) == 1 and first.constant is not None and (first.constant.startswith(b'HTTP_') or first.constant == b'QUERY_STRING'):
                return Value(source=token.offset)
            if name == b'file_get_contents' and first.constant == b'php://input':
                return Value(source=token.offset)
            if name == b'stripslashes' and len(arguments) == 1:
                return replace(first, constant=None)
            callable_value = value
            callable_direct = direct is not None
            if name == b'call_user_func' and arguments:
                callable_value = first
                callable_direct = False
                name = first.constant.lower() if first.constant is not None else None
                first = arguments[1] if len(arguments) > 1 else UNKNOWN
            if not callable_direct and callable_value.source is not None and callable_value.hops:
                self.evidence.append(Evidence(INDIRECT, token.offset, callable_value.source, b'request-selected callable'))
            valid_sink = name in (SINKS if callable_direct else CALLABLE_SINKS)
            if valid_sink:
                if first.source is not None and first.hops:
                    self.evidence.append(Evidence(INDIRECT, token.offset, first.source, name))
                if not callable_direct and callable_value.obfuscated:
                    self.evidence.append(Evidence(OBFUSCATED, token.offset, None, name, callable_value.decoded_at))
                if name in (b'eval', b'assert') and first.decoded and first.hops:
                    self.evidence.append(Evidence(DECODED, token.offset, first.source, name, first.decoded_at))
            if name in DECODERS and len(arguments) == 1:
                return _decode(name, first, token.offset)
            # Unknown calls can change arguments by reference. Discarding the
            # environment prevents a later call from using stale taint/names.
            self.variables.clear()
            return UNKNOWN
        return value


def analyse(raw):
    """Return proven local candidates; unsupported statements discard state.

    Work is linear in file size with bounded tokens, values and parser depth.
    The recognised pattern is deliberately confined to a straight-line block.
    """
    # A cheap over-approximation avoids lexing ordinary callback-heavy CMS
    # files. It only selects work: the analyser still verifies every finding.
    if not _DIRECT_HINT.search(raw):
        calls = {match[1] for match in _VARIABLE_CALL.finditer(raw)}
        if not calls or not any(match[1] in calls for match in _ASSIGN_HINT.finditer(raw)):
            return []
    variables, statement, results = {}, [], []
    oversized = False
    for token in _tokens(raw):
        if token.text in (b'{', b'}', b';boundary'):
            variables.clear()
            statement.clear()
            oversized = False
            continue
        if token.text == b';':
            if statement and not oversized:
                expression = _Expression(statement, variables)
                try:
                    expression.expression()
                    if expression.cursor != len(statement) or len(expression.variables) > MAX_VARIABLES:
                        raise ValueError('Unsupported statement')
                    variables = expression.variables
                    results.extend(expression.evidence)
                except ValueError:
                    variables.clear()
            else:
                variables.clear()
            statement.clear()
            oversized = False
            continue
        if oversized:
            continue
        statement.append(token)
        if len(statement) > MAX_TOKENS or token.end - statement[0].offset > MAX_STATEMENT or token.text == b';oversized':
            oversized = True
            statement.clear()
            variables.clear()
    return results
