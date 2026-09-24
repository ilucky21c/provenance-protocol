import { readFileSync } from 'node:fs';
import { verifyNotice } from '../src/verify.js';
import { validateNotice, validateDeclaration } from '../src/validate.js';

const V = JSON.parse(readFileSync(new URL('../test-vectors/notices-0.1.json', import.meta.url), 'utf8'));
let pass = 0, fail = 0;
const t = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};

for (const v of V.vectors) {
  const r = await verifyNotice(v.notice, { publicKey: V.old_key.public_key });
  t(`${v.id}  (${r.status})`, r.status === v.expect, r.reason);
  if (v.new_key_fingerprint) t(`${v.id} yields the new key's fingerprint`, r.newKeyFingerprint === v.new_key_fingerprint);
  if (v.expect === 'valid') {
    const s = validateNotice(v.notice);
    t(`${v.id} is schema-valid`, s.valid, s.errors);
  }
}

const noKey = await verifyNotice(V.vectors[0].notice, {});
t('no key → unchecked, not invalid', noKey.status === 'unchecked');

const bad = validateNotice({ ...V.vectors[3].notice, claims: { ...V.vectors[3].notice.claims, severity: 'catastrophic' } });
t('incident severity outside the vocabulary is refused', !bad.valid, bad.errors);

// The new declaration sections validate, and malformed ones do not.
const full = {
  provenance: '0.2', name: 'A', description: 'B',
  operator: { legal_name: 'Acme Ltd', jurisdiction: 'GB', registration: 'GB-COH:12345678', security_contact: 'https://acme.example/.well-known/security.txt' },
  data: { categories: ['customer_content', 'personal'], retention: 'P30D', training_use: 'none', regions: ['EU', 'GB'] },
  subprocessors: [{ name: 'ModelCo', role: 'model_provider', regions: ['US'], data_categories: ['customer_content'] }],
  oversight: { approval_required: ['financial:transact'], pausable_by_customer: true },
  limits: [{ applies_to: 'financial:transact', max: 500, unit: 'USD', per: 'P1D' }],
  dependencies: [{ provenance_id: 'provenance:domain:tool.example', kind: 'mcp_server', purpose: 'search' }, { url: 'https://api.pay.example', kind: 'api' }],
  certifications: [{ standard: 'ISO/IEC 42001', attestation_url: 'https://cert.example/a.json' }],
  changes: { notice_period: 'P30D', pending: [{ field: 'constraints', change: 'removed', value: 'no:write:external', effective: '2026-11-01', reason: 'CRM sync' }] },
  interop: { a2a_agent_card: 'https://agent.example.com/.well-known/agent-card.json', mcp_registry: 'com.example/research' },
};
let r = validateDeclaration(full);
t('declaration with every new section is valid', r.valid, r.errors);
for (const [label, patch] of [
  ['retention not a duration', { data: { retention: '30 days' } }],
  ['unknown data category', { data: { categories: ['everything'] } }],
  ['jurisdiction not a country code', { operator: { legal_name: 'A', jurisdiction: 'Britain' } }],
  ['negative limit', { limits: [{ applies_to: 'financial:transact', max: -1, unit: 'USD' }] }],
  ['dependency with neither id nor url', { dependencies: [{ kind: 'api' }] }],
  ['pending change without a date', { changes: { pending: [{ field: 'constraints', change: 'removed' }] } }],
]) {
  r = validateDeclaration({ ...full, ...patch });
  t(`refused: ${label}`, !r.valid, r.errors);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
