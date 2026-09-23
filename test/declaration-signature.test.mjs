import { readFileSync } from 'node:fs';
import { verifyDeclaration } from '../src/verify.js';

const V = JSON.parse(readFileSync(new URL('../test-vectors/declarations-0.2.json', import.meta.url), 'utf8'));
let pass = 0, fail = 0;

for (const v of V.vectors) {
  const r = await verifyDeclaration(v.declaration);
  const got = r.valid ? 'valid' : 'invalid';
  const ok = got === v.expect;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${v.id}  (${got})${ok ? '' : `  expected ${v.expect}; reason: ${r.reason}`}`);
  ok ? pass++ : fail++;
}

// The point of the whole change: 0.1 does NOT protect content, 0.2 does.
const v01 = JSON.parse(readFileSync(new URL('../test-vectors/signatures-0.1.json', import.meta.url), 'utf8'));
const k = v01.keypair;
const sig01 = v01.vectors.find((x) => x.id === 'identity-signature-valid').signature;
const decl01 = {
  provenance: '0.1', name: 'A', description: 'B', provenance_id: k.provenance_id,
  constraints: ['no:pii'],
  identity: { public_key: k.public_key, signature: sig01, algorithm: 'ed25519' },
};
const r01 = await verifyDeclaration(decl01);
const r01Tampered = await verifyDeclaration({ ...decl01, constraints: [] });

const covers01 = r01.valid && r01.coverage === 'identity';
console.log(`${covers01 ? 'PASS' : 'FAIL'}  0.1 verifies and reports coverage 'identity'`);
covers01 ? pass++ : fail++;

const gap = r01Tampered.valid === true;
console.log(`${gap ? 'PASS' : 'FAIL'}  0.1 still verifies after a constraint is deleted (the documented gap)`);
gap ? pass++ : fail++;

const r02 = await verifyDeclaration(V.vectors[0].declaration);
const covers02 = r02.valid && r02.coverage === 'declaration';
console.log(`${covers02 ? 'PASS' : 'FAIL'}  0.2 verifies and reports coverage 'declaration'`);
covers02 ? pass++ : fail++;

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
