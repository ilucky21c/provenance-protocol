import { readFileSync } from 'node:fs';
import { checkDeclaration, locateDeclaration, checkLocation } from '../src/index.js';

const D = JSON.parse(readFileSync(new URL('../test-vectors/declarations-0.2.json', import.meta.url), 'utf8'));
const decl = D.vectors.find((x) => x.id === 'declaration-signature-valid').declaration;
const home = 'https://raw.githubusercontent.com/example/research-agent/HEAD/PROVENANCE.yml';
let pass = 0, fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `  ${detail}`}`);
  ok ? pass++ : fail++;
};

let r = await checkDeclaration(decl, { retrievedFrom: home, requireConstraints: ['no:pii'] });
check(r.allowed, 'signed, at home, has constraint → allowed', r.reason);

r = await checkDeclaration(decl, {});
check(!r.allowed && /location not given/i.test(r.reason), 'no retrieval location → refused, saying why', r.reason);

r = await checkDeclaration(decl, { retrievedFrom: 'https://raw.githubusercontent.com/mallory/copy/HEAD/PROVENANCE.yml' });
check(!r.allowed && /not served from/.test(r.reason), 're-hosted copy → refused', r.reason);

r = await checkDeclaration(decl, { retrievedFrom: home, requireConstraints: ['no:write:external'] });
check(!r.allowed && /no:write:external/.test(r.reason), 'missing constraint → refused', r.reason);

r = await checkDeclaration({ ...decl, constraints: [] }, { retrievedFrom: home });
check(!r.allowed, 'constraint deleted after signing → refused', r.reason);

r = await checkDeclaration(decl, { retrievedFrom: home, expectedFingerprint: '0'.repeat(64) });
check(!r.allowed && /rotation/.test(r.reason), 'different key than pinned → refused as rotation', r.reason);

check(
  locateDeclaration('provenance:domain:agent.example.com') === 'https://agent.example.com/.well-known/provenance.json',
  'locate: domain'
);
check(
  locateDeclaration('provenance:domain:example.com/agents/research') ===
    'https://example.com/agents/research/.well-known/provenance.json',
  'locate: domain with path'
);
check(locateDeclaration('provenance:github:alice/agent') === 'https://raw.githubusercontent.com/alice/agent/HEAD/PROVENANCE.yml', 'locate: github');
check(locateDeclaration('provenance:npm:thing') === null, 'locate: npm has no single location → null');
check(locateDeclaration('provenance:domain:evil.com@good.com') === null, 'locate: refuses a host with userinfo');

// Every located URL must pass the location check for its own id.
for (const id of ['provenance:domain:agent.example.com', 'provenance:domain:example.com/agents/research', 'provenance:github:alice/agent']) {
  check(checkLocation(id, locateDeclaration(id)) === 'match', `located URL matches its id: ${id}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
