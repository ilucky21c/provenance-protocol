import { readFileSync } from 'node:fs';
import { verifyDeclaration, verifyChallenge, verifyRevocation, checkLocation, keyFingerprint }
  from '../src/verify.js';

const V = JSON.parse(readFileSync(new URL('../test-vectors/signatures-0.1.json', import.meta.url),'utf8'));
const { provenance_id: PID, public_key: PUB } = V.keypair;
const vec = id => V.vectors.find(v => v.id === id);
let pass = 0, fail = 0;
const t = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`}`);
  ok ? pass++ : fail++;
};

// --- signed declaration, correct location ---
const signed = { provenance: '0.1', name: 'A', description: 'B', provenance_id: PID,
  identity: { public_key: PUB, signature: vec('identity-signature-valid').signature, algorithm: 'ed25519' } };
let r = await verifyDeclaration(signed, { retrievedFrom: 'https://github.com/example/research-agent' });
t('signed + location match -> valid & trustworthy', [r.valid, r.trustworthy, r.location], [true, true, 'match']);

r = await verifyDeclaration(signed, { retrievedFrom: 'https://github.com/attacker/fork' });
t('signed + wrong location -> valid but not trustworthy', [r.valid, r.trustworthy, r.location], [true, false, 'mismatch']);

r = await verifyDeclaration(signed);
t('signed, no location given -> valid, unchecked', [r.valid, r.trustworthy, r.location], [true, false, 'unchecked']);

// --- wrong key / tampering ---
r = await verifyDeclaration({ ...signed, identity: { ...signed.identity, signature: vec('identity-signature-wrong-key').signature } });
t('wrong-key signature -> invalid', [r.signed, r.valid], [true, false]);

r = await verifyDeclaration({ ...signed, provenance_id: 'provenance:github:attacker/fork' });
t('tampered provenance_id -> invalid', [r.signed, r.valid], [true, false]);

r = await verifyDeclaration({ ...signed, identity: { ...signed.identity, signature: 'not-a-signature' } });
t('malformed signature -> invalid, no throw', [r.signed, r.valid], [true, false]);

// --- unsigned / absent identity ---
r = await verifyDeclaration({ ...signed, identity: { public_key: PUB } });
t('key without signature -> not signed, fingerprint present', [r.signed, r.valid, typeof r.fingerprint], [false, false, 'string']);

r = await verifyDeclaration({ provenance: '0.1', name: 'A', description: 'B' });
t('no identity block -> not signed', [r.signed, r.valid, r.reason], [false, false, 'No identity block']);

r = await verifyDeclaration('not an object');
t('non-object input -> handled', [r.valid, r.reason], [false, 'Declaration must be a parsed object']);

r = await verifyDeclaration({ ...signed, identity: { ...signed.identity, algorithm: 'rsa' } });
t('unsupported algorithm rejected', [r.valid, r.reason], [false, 'Unsupported algorithm: rsa']);

// --- location parsing ---
t('raw githubusercontent url matches', checkLocation(PID, 'https://raw.githubusercontent.com/example/research-agent/main/PROVENANCE.yml'), 'match');
t('unknown host -> unchecked', checkLocation(PID, 'https://example.com/whatever'), 'unchecked');
t('platform mismatch -> mismatch', checkLocation(PID, 'https://huggingface.co/example/research-agent'), 'mismatch');
t('garbage url -> unchecked', checkLocation(PID, 'not a url'), 'unchecked');

// --- challenge + revocation ---
t('challenge verifies', await verifyChallenge(PUB, PID, vec('challenge-signature-valid').nonce, vec('challenge-signature-valid').signature), true);
t('challenge with wrong nonce fails', await verifyChallenge(PUB, PID, 'wrong', vec('challenge-signature-valid').signature), false);
t('revocation verifies', await verifyRevocation(PUB, PID, vec('revocation-signature-valid').signature), true);

// --- fingerprint is stable and key-specific ---
const f1 = await keyFingerprint(PUB), f2 = await keyFingerprint(PUB);
t('fingerprint stable, 64 hex chars', [f1 === f2, /^[0-9a-f]{64}$/.test(f1)], [true, true]);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
