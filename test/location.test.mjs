import { checkLocation } from '../src/verify.js';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const cases = [
  ['hosted service at its own domain', 'provenance:domain:agent.example.com',
    'https://agent.example.com/.well-known/provenance.json', 'match'],
  ['served from someone else\'s domain', 'provenance:domain:agent.example.com',
    'https://evil.example.com/.well-known/provenance.json', 'mismatch'],
  ['a subdomain is NOT the parent domain', 'provenance:domain:example.com',
    'https://agent.example.com/provenance.json', 'mismatch'],
  ['and the parent is not the subdomain', 'provenance:domain:agent.example.com',
    'https://example.com/provenance.json', 'mismatch'],
  ['hostname comparison is case-insensitive', 'provenance:domain:AGENT.Example.COM',
    'https://agent.example.com/provenance.json', 'match'],
  ['several agents under one domain', 'provenance:domain:example.com/agents/research',
    'https://example.com/agents/research/provenance.json', 'match'],
  ['the wrong agent under the right domain', 'provenance:domain:example.com/agents/research',
    'https://example.com/agents/billing/provenance.json', 'mismatch'],
  ['repo identifiers still work', 'provenance:github:alice/agent',
    'https://github.com/alice/agent', 'match'],
  ['raw file URLs under a repo still work', 'provenance:github:alice/agent',
    'https://raw.githubusercontent.com/alice/agent/main/PROVENANCE.yml', 'match'],
  ['a repo id served from a bare domain is unchecked, not a match', 'provenance:github:alice/agent',
    'https://agent.example.com/.well-known/provenance.json', 'unchecked'],
  ['malformed identifier', 'not-a-provenance-id', 'https://example.com/x', 'unchecked'],
  ['malformed url', 'provenance:domain:example.com', 'not a url', 'unchecked'],
  ['empty host in identifier', 'provenance:domain:/', 'https://example.com/x', 'unchecked'],
];

for (const [name, id, url, want] of cases) {
  const got = checkLocation(id, url);
  t(name, got === want, `got '${got}', want '${want}'`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
