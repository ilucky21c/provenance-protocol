/**
 * A public challenge endpoint is a signing oracle: anyone can ask the agent to
 * sign a string of their choosing. These tests pin down that the domain-
 * separated payloads cannot be turned into each other, and record the legacy
 * flaw they exist to fix.
 */
import { generateProvenanceKeyPair, signChallenge, signRevocation, signForProvenance,
         signAgentChallenge, signAgentRevocation, signDeclaration } from '../src/keygen.js';
import { verifyAgentChallenge, verifyAgentRevocation, verifyRevocation, verifyDeclaration } from '../src/verify.js';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const ID = 'provenance:github:alice/agent';
const { publicKey, privateKey } = generateProvenanceKeyPair();

// --- the flaw being fixed, recorded so it cannot quietly return ---
t('LEGACY: a challenge signed over nonce "REVOKE" IS a valid revocation',
  await verifyRevocation(publicKey, ID, signChallenge(privateKey, ID, 'REVOKE')) === true);
t('LEGACY: that signature is byte-identical to signRevocation',
  signChallenge(privateKey, ID, 'REVOKE') === signRevocation(privateKey, ID));

// --- the separated forms ---
t('challenge round-trips',
  await verifyAgentChallenge(publicKey, ID, 'n1', signAgentChallenge(privateKey, ID, 'n1')) === true);
t('challenge is bound to its nonce',
  await verifyAgentChallenge(publicKey, ID, 'n2', signAgentChallenge(privateKey, ID, 'n1')) === false);
t('challenge is bound to its provenance id',
  await verifyAgentChallenge(publicKey, 'provenance:github:bob/agent', 'n1', signAgentChallenge(privateKey, ID, 'n1')) === false);
t('revocation round-trips',
  await verifyAgentRevocation(publicKey, ID, signAgentRevocation(privateKey, ID)) === true);

// --- the attacks a signing oracle enables, all now refused ---
t('oracle output for nonce "REVOKE" is NOT a revocation',
  await verifyAgentRevocation(publicKey, ID, signAgentChallenge(privateKey, ID, 'REVOKE')) === false);

let worstCase = false;
for (const nonce of ['REVOKE', publicKey, `${ID}:${publicKey}`, '', 'revoke', 'provenance-revocation-v1']) {
  if (!nonce) continue;
  if (await verifyAgentRevocation(publicKey, ID, signAgentChallenge(privateKey, ID, nonce))) worstCase = true;
}
t('no chosen nonce yields a revocation', worstCase === false);

// A 0.2 declaration signature must not be obtainable from the oracle either.
const decl = { provenance: '0.2', name: 'A', description: 'B', provenance_id: ID,
  constraints: ['no:pii'], identity: { public_key: publicKey, algorithm: 'ed25519' } };
const realDeclSig = signDeclaration(privateKey, decl);
let forged = false;
for (const nonce of [publicKey, JSON.stringify(decl), 'provenance-declaration-v1']) {
  if (signAgentChallenge(privateKey, ID, nonce) === realDeclSig) forged = true;
}
t('no chosen nonce yields a declaration signature', forged === false);

// And the legacy declaration payload is reachable from the legacy oracle.
t('LEGACY: oracle with nonce=<public_key> reproduces the 0.1 declaration signature',
  signChallenge(privateKey, ID, publicKey) === signForProvenance(privateKey, ID, publicKey));

const r = await verifyDeclaration({ ...decl, identity: { ...decl.identity, signature: realDeclSig } });
t('the real declaration still verifies', r.valid === true && r.coverage === 'declaration');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
