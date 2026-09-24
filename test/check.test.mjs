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

import { checkInteropLinks } from '../src/index.js';
const L = (id, interop) => checkInteropLinks({ provenance_id: id, interop });
let l = L('provenance:domain:agent.example.com', { a2a_agent_card: 'https://agent.example.com/.well-known/agent-card.json' });
check(l.a2a === 'confirmed', 'A2A card on the same host → confirmed');
l = L('provenance:domain:agent.example.com', { a2a_agent_card: 'https://famous-agent.example.org/.well-known/agent-card.json' });
check(l.a2a === 'claimed', 'A2A card on another host → only claimed');
l = L('provenance:domain:example.com', { mcp_registry: 'com.example/research' });
check(l.mcp === 'confirmed', 'MCP namespace matching the domain → confirmed');
l = L('provenance:domain:someone.vercel.app', { mcp_registry: 'app.vercel/anything' });
check(l.mcp === 'claimed', 'subdomain claiming the parent namespace → only claimed');
l = L('provenance:github:alice/agent', { mcp_registry: 'io.github.alice/agent' });
check(l.mcp === 'confirmed', 'io.github.<owner> for a github id → confirmed');
l = L('provenance:github:mallory/agent', { mcp_registry: 'io.github.alice/agent' });
check(l.mcp === 'claimed', 'someone else\'s GitHub namespace → only claimed');
check(L('provenance:domain:a.example', {}).a2a === 'none', 'no link → none');

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
