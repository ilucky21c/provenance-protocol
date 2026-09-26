import { checkDeclaration, openDeliveredDeclaration, keyFingerprint, declarationDigest, verifyAttestation } from '../src/index.js';
import { generateProvenanceKeyPair, signDeclaration, signNotice, signAttestation } from '../src/keygen.js';
import { validateAttestation, validateNotice } from '../src/validate.js';

let pass = 0, fail = 0;
const t = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};

// An organisation, publicly known by its own domain, and an internal agent
// nobody outside can reach.
const ORG = 'provenance:domain:corp.example';
const AGENT = 'provenance:domain:hr-assistant.corp.internal';
const org = generateProvenanceKeyPair();
const agent = generateProvenanceKeyPair();
const NOW = Date.parse('2026-09-26T12:00:00Z');

const decl = { provenance: '0.2', name: 'HR Assistant', description: 'Answers staff HR questions.', provenance_id: AGENT,
  constraints: ['no:financial:transact'], identity: { public_key: agent.publicKey, algorithm: 'ed25519' } };
decl.identity.signature = signDeclaration(agent.privateKey, decl);

const noticeBody = { notice: '0.1', id: 'n1', event: 'declaration-published', provenance_id: AGENT,
  key_fingerprint: await keyFingerprint(agent.publicKey), issued_at: '2026-09-26T11:00:00Z',
  claims: { declaration_url: 'https://hr-assistant.corp.internal/.well-known/provenance.json', declaration_digest: await declarationDigest(decl), declaration: decl } };
const notice = { ...noticeBody, signature: signNotice(agent.privateKey, noticeBody) };

function affiliation(overrides = {}, key = org.privateKey) {
  const a = { attestation: '0.1', id: 'aff-1', kind: 'affiliation',
    issuer: { provenance_id: ORG, key_fingerprint: null },
    subject: { provenance_id: AGENT },
    issued_at: '2026-09-01T00:00:00Z', valid_until: '2027-09-01T00:00:00Z',
    scope: 'Corp operates this agent, with this key. Not an assessment of its behaviour.',
    claims: { relationship: 'operated_by', unit: 'Human Resources', subject_key_fingerprint: null }, ...overrides };
  return a;
}
async function signed(a, key = org.privateKey, issuerPub = org.publicKey) {
  a.issuer = { ...a.issuer, key_fingerprint: await keyFingerprint(issuerPub) };
  if (a.claims.subject_key_fingerprint === null) a.claims = { ...a.claims, subject_key_fingerprint: await keyFingerprint(agent.publicKey) };
  return { ...a, signature: signAttestation(key, a) };
}
const aff = await signed(affiliation());

t('delivery notice is schema-valid', validateNotice(notice).valid, validateNotice(notice).errors);
t('affiliation is schema-valid', validateAttestation(aff).valid, validateAttestation(aff).errors);

let o = await openDeliveredDeclaration(notice);
t('delivered declaration opens', o.valid, o.reason);

let r = await checkDeclaration(o.declaration, { requireConstraints: ['no:financial:transact'] });
t('without an affiliation, an internal agent cannot be tied to anyone', !r.allowed, r.reason);

r = await checkDeclaration(o.declaration, { affiliation: { attestation: aff, issuerPublicKey: org.publicKey, now: NOW }, requireConstraints: ['no:financial:transact'] });
t('with the organisation\'s affiliation it is accepted, anchored by affiliation', r.allowed && r.anchor === 'affiliation', r.reason);

// Attacks and mistakes.
const stranger = generateProvenanceKeyPair();
r = await checkDeclaration(decl, { affiliation: { attestation: await signed(affiliation(), stranger.privateKey, stranger.publicKey), issuerPublicKey: org.publicKey, now: NOW } });
t('affiliation signed by someone else is refused', !r.allowed, r.reason);

r = await checkDeclaration(decl, { affiliation: { attestation: await signed(affiliation({ subject: { provenance_id: 'provenance:domain:payroll.corp.internal' } })), issuerPublicKey: org.publicKey, now: NOW } });
t('affiliation for another agent is refused', !r.allowed && /different agent/.test(r.reason), r.reason);

const otherKey = generateProvenanceKeyPair();
r = await checkDeclaration(decl, { affiliation: { attestation: await signed(affiliation({ claims: { relationship: 'operated_by', subject_key_fingerprint: await keyFingerprint(otherKey.publicKey) } })), issuerPublicKey: org.publicKey, now: NOW } });
t('affiliation for another key is refused — a new key needs a new affiliation', !r.allowed && /different key/.test(r.reason), r.reason);

r = await checkDeclaration(decl, { affiliation: { attestation: aff, issuerPublicKey: org.publicKey, now: Date.parse('2028-01-01T00:00:00Z') } });
t('expired affiliation is refused and says expired', !r.allowed && /expired/.test(r.reason), r.reason);

r = await checkDeclaration(decl, { affiliation: { attestation: await signed(affiliation({ kind: 'decision' })), issuerPublicKey: org.publicKey, now: NOW } });
t('another kind of attestation does not count as affiliation', !r.allowed, r.reason);

// Delivery tampering.
const tampered = { ...notice, claims: { ...notice.claims, declaration: { ...decl, constraints: [] } } };
o = await openDeliveredDeclaration(tampered);
t('declaration altered in transit is refused', !o.valid, o.reason);

const swapped = { ...noticeBody, key_fingerprint: await keyFingerprint(stranger.publicKey) };
o = await openDeliveredDeclaration({ ...swapped, signature: signNotice(stranger.privateKey, swapped) });
t('notice signed by a key other than the declaration\'s is refused', !o.valid, o.reason);

const wrongDigest = { ...noticeBody, claims: { ...noticeBody.claims, declaration_digest: 'sha256:' + '0'.repeat(64) } };
o = await openDeliveredDeclaration({ ...wrongDigest, signature: signNotice(agent.privateKey, wrongDigest) });
t('digest mismatch is refused', !o.valid && /digest/.test(o.reason), o.reason);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
