import { readFileSync } from 'node:fs';
import {
  verifyAttestation,
  verifyAttestationWithdrawal,
  declarationDigest,
  keyFingerprint,
} from '../src/verify.js';
import { generateProvenanceKeyPair, signAttestation } from '../src/keygen.js';

const V = JSON.parse(readFileSync(new URL('../test-vectors/attestations-0.1.json', import.meta.url), 'utf8'));
const D = JSON.parse(readFileSync(new URL('../test-vectors/declarations-0.2.json', import.meta.url), 'utf8'));
let pass = 0, fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  ${detail}`}`);
  ok ? pass++ : fail++;
};

for (const v of V.vectors) {
  const r = await verifyAttestation(v.attestation, { issuerPublicKey: V.issuer.public_key, now: Date.parse(v.now) });
  check(r.status === v.expect, `${v.id}  (${r.status})`, `expected ${v.expect}; reason: ${r.reason}`);
}

const w = V.withdrawal;
check(
  await verifyAttestationWithdrawal(V.issuer.public_key, w.issuer, w.attestation_id, w.signature),
  'withdrawal verifies'
);
check(
  !(await verifyAttestationWithdrawal(V.issuer.public_key, w.issuer, 'att-0002', w.signature)),
  'withdrawal does not transfer to another attestation'
);

const decl = D.vectors.find((x) => x.id === V.declaration_digest.declaration_id).declaration;
check((await declarationDigest(decl)) === V.declaration_digest.digest, 'declaration digest matches vector');
check(
  (await declarationDigest({ ...decl, identity: { ...decl.identity, signature: 'different' } })) === V.declaration_digest.digest,
  'digest ignores the signature'
);
check(
  (await declarationDigest({ ...decl, constraints: [] })) !== V.declaration_digest.digest,
  'digest changes when a constraint is removed'
);

// No key supplied must read as "could not check", never as invalid or valid.
const noKey = await verifyAttestation(V.vectors[0].attestation, {});
check(noKey.status === 'unchecked' && !noKey.valid, 'no issuer key → unchecked');

// Round trip with a fresh key.
const k = generateProvenanceKeyPair();
const a = { ...V.vectors[0].attestation, issuer: { ...V.vectors[0].attestation.issuer, key_fingerprint: await keyFingerprint(k.publicKey) } };
a.signature = signAttestation(k.privateKey, a);
const rt = await verifyAttestation(a, { issuerPublicKey: k.publicKey, now: Date.parse('2026-09-22T00:00:00Z') });
check(rt.status === 'valid', 'sign → verify round trip', rt.reason);

// A missing scope is malformed, not merely unsigned.
const { scope: _s, ...noScope } = V.vectors[0].attestation;
const ns = await verifyAttestation(noScope, { issuerPublicKey: V.issuer.public_key, now: Date.parse('2026-09-22T00:00:00Z') });
check(ns.status === 'invalid' && /scope/.test(ns.reason), 'missing scope → invalid');

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
