# SPDX-License-Identifier: BSD-2-Clause
"""Compare the strict-OFF C tokens with the immutable official base.

Only MH_SAFE_FREEZE conditionals are evaluated. Architecture, debug and SDK
directives stay in the token stream, so both architecture branches are checked.
No Windows headers or compiler installation is required for this source check.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

BASE = '8af6b4acae5a9388fd742b56fa79ece89d96f823'
MEMBERS = ('src/hook.c', 'src/buffer.c', 'src/buffer.h')
TOKENS = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*|'
    r'[A-Za-z_]\w*|(?:0[xX][0-9a-fA-F]+|\d+)[A-Za-z0-9_.]*|'
    r'>>=|<<=|\.\.\.|->|\+\+|--|&&|\|\||<<|>>|<=|>=|==|!=|'
    r'[+*/%&|^=-]=|##|[^\s]', re.DOTALL)


def default_source(text):
    stack = []
    output = []
    for line in text.splitlines(keepends=True):
        match = re.match(r'\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)', line)
        active = all(value is not False for value in stack)
        if match:
            directive, expression = match.groups()
            if directive in ('if', 'ifdef', 'ifndef'):
                known = re.fullmatch(r'\s*defined\(MH_SAFE_FREEZE\)\s*', expression) if directive == 'if' else expression.strip() == 'MH_SAFE_FREEZE'
                stack.append(directive == 'ifndef' if known else None)
                if known:
                    continue
            elif directive == 'else':
                if stack[-1] is not None:
                    stack[-1] = not stack[-1]
                    continue
            elif directive == 'elif':
                if stack[-1] is not None or 'MH_SAFE_FREEZE' in expression:
                    raise ValueError('Unsupported strict conditional: ' + line)
            elif directive == 'endif':
                known = stack.pop() is not None
                if known:
                    continue
        if active:
            output.append(line)
    if stack:
        raise ValueError('Unbalanced preprocessor conditionals')
    return ''.join(output)


def tokens(text):
    return [token for token in TOKENS.findall(text)
            if not token.startswith(('/*', '//')) and token != '\ufeff']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--official-root', type=Path)
    args = parser.parse_args()
    for name in MEMBERS:
        original = ((args.official_root / name).read_bytes() if args.official_root else
                    subprocess.check_output(['git', '-C', str(args.root), 'show', BASE + ':' + name]))
        expected = tokens(original.decode('utf-8-sig'))
        actual = tokens(default_source((args.root / name).read_text(encoding='utf-8-sig')))
        if actual != expected:
            index = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]), min(len(actual), len(expected)))
            raise SystemExit(f'FAIL: strict-OFF tokens differ: {name}, token {index}, actual={actual[index:index+8]}, expected={expected[index:index+8]}')
        digest = hashlib.sha256('\n'.join(actual).encode()).hexdigest()
        print(f'PASS: strict-OFF tokens match official base: {name}; tokens={len(actual)} SHA256={digest}')


if __name__ == '__main__':
    main()
