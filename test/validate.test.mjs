import { readFileSync } from 'node:fs';
import { validateDeclaration, validateAttestation } from '../src/validate.js';

const D = JSON.parse(readFileSync(new URL('../test-vectors/declarations-0.2.json', import.meta.url), 'utf8'));
const A = JSON.parse(readFileSync(new URL('../test-vectors/attestations-0.1.json', import.meta.url), 'utf8'));
let pass = 0, fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};

const decl = D.vectors.find((x) => x.id === 'declaration-signature-valid').declaration;
let r = validateDeclaration(decl);
check(r.valid, '0.2 vector declaration is valid', r.errors);

r = validateDeclaration({ provenance: '0.2', name: 'A', description: 'B', provenance_id: 'provenance:domain:agent.example.com' });
check(r.valid, 'domain identifier is accepted', r.errors);

r = validateDeclaration({ provenance: '0.2', name: 'A', description: 'B', some_future_field: 1 });
check(r.valid, 'unknown top-level field is ignored, as conformance requires', r.errors);

r = validateDeclaration({ provenance: '0.2', name: 'A' });
check(!r.valid && r.errors.some((e) => e.includes('description')), 'missing description is an error', r.errors);

r = validateDeclaration({ provenance: '0.2', name: 'A', description: 'B', constraints: ['financial:transact'] });
check(!r.valid, 'a constraint without no: is an error', r.errors);

r = validateDeclaration({ provenance: '7', name: 'A', description: 'B' });
check(!r.valid && /not known/.test(r.errors[0]), 'unknown version is refused, not guessed', r.errors);

r = validateDeclaration({ provenance: '0.1', name: 'A', description: 'B', provenance_id: 'provenance:github:a/b', identity: { public_key: 'x', signature: 'y' } });
check(r.valid && r.warnings.length === 1, '0.1 signature warns about coverage', r);

for (const v of A.vectors.filter((x) => x.expect === 'valid')) {
  r = validateAttestation(v.attestation);
  check(r.valid, `attestation vector ${v.id} is schema-valid`, r.errors);
}

const att = A.vectors[0].attestation;
r = validateAttestation({ ...att, kind: 'made-up' });
check(!r.valid, 'unprefixed custom kind is refused', r.errors);
r = validateAttestation({ ...att, kind: 'example.com:pen-test' });
check(r.valid, 'domain-prefixed custom kind is accepted', r.errors);
r = validateAttestation({ ...att, subject: { declaration_digest: att.subject.declaration_digest } });
check(!r.valid, 'subject with neither id nor url is refused', r.errors);
r = validateAttestation({ ...att, claims: { ...att.claims, location: 'maybe' } });
check(!r.valid, 'declaration-check claims are checked against their kind', r.errors);
r = validateAttestation({ ...att, valid_until: '2026-09-24 09:00' });
check(!r.valid, 'timestamp without offset is refused', r.errors);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
