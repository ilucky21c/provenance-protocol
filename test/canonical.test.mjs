import { canonicalJson } from '../src/canonical.js';

// Checks the canonical form against the JSON Canonicalization Scheme (RFC 8785),
// including the edge cases where a naive implementation differs from it.
let pass = 0, fail = 0;
const t = (name, got, want) => {
  const ok = got === want;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n  got  ${got}\n  want ${want}`}`);
  ok ? pass++ : fail++;
};

t('nested keys sorted, no whitespace', canonicalJson({ b: 1, a: { d: [3, { f: 1, e: 2 }], c: null } }), '{"a":{"c":null,"d":[3,{"e":2,"f":1}]},"b":1}');

// RFC 8785 sorts by UTF-16 code units, not code points: U+1F600 is encoded as
// the surrogate pair D83D DE00, which sorts BEFORE U+FFFF. Sorting by code
// point would put it after.
t('keys sorted by UTF-16 code units (RFC 8785 §3.2.3)', canonicalJson({ '￿': 1, '\u{1F600}': 2 }), '{"\u{1F600}":2,"￿":1}');

// RFC 8785 §3.2.2.3 number serialisation examples.
t('number: 1e21', canonicalJson(1e21), '1e+21');
t('number: 1e-7', canonicalJson(1e-7), '1e-7');
t('number: 333333333.33333329', canonicalJson(333333333.33333329), '333333333.3333333');
t('number: -0 serialises as 0', canonicalJson(-0), '0');

// String escaping per RFC 8785 §3.2.2.2: only the mandatory escapes, and
// non-ASCII left as-is.
const cp = (...codes) => String.fromCodePoint(...codes);
// Input: € $ U+000F LF A ' B " \ " /  — the RFC 8785 §3.2.2.2 example characters.
const input = cp(0x20ac, 0x24, 0x0f, 0x0a, 0x41, 0x27, 0x42, 0x22, 0x5c, 0x22, 0x2f);
// Expected: quote, €, $, \u000f, \n, A, ', B, \", \\, \", /, quote.
const expected = cp(0x22, 0x20ac, 0x24) + cp(0x5c) + 'u000f' + cp(0x5c) + 'n' + cp(0x41, 0x27, 0x42)
  + cp(0x5c, 0x22) + cp(0x5c, 0x5c) + cp(0x5c, 0x22) + cp(0x2f, 0x22);
t('string escaping (RFC 8785 §3.2.2.2)', canonicalJson(input), expected);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
