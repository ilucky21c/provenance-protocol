#!/usr/bin/env node
/**
 * provenance-cli — Provenance Protocol identity CLI
 *
 * Usage:
 *   provenance keygen
 *   provenance register --id <id> --url <url> [options]
 *   provenance status <id>
 *   provenance validate [file]
 *   provenance revoke --id <id> [--private-key <key>]
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

const API     = process.env.PROVENANCE_API_URL || 'https://getprovenance.dev';
const VERSION = '0.1.1';

// ── Colours ───────────────────────────────────────────────────────────────────

const c = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', amber: '\x1b[33m', red: '\x1b[31m', white: '\x1b[97m',
};
const ok  = s => `${c.green}✓${c.reset} ${s}`;
const err = s => `${c.red}✗${c.reset} ${s}`;
const dim = s => `${c.dim}${s}${c.reset}`;
const hi  = s => `${c.white}${c.bold}${s}${c.reset}`;
const amb = s => `${c.amber}${s}${c.reset}`;

// ── Arg parsing ───────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { _: [] };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { args[key] = next; i += 2; }
      else { args[key] = true; i++; }
    } else { args._.push(a); i++; }
  }
  return args;
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey:  Buffer.from(publicKey).toString('base64'),
    privateKey: Buffer.from(privateKey).toString('base64'),
  };
}

function signMessage(privateKeyBase64, message) {
  const key = createPrivateKey({ key: Buffer.from(privateKeyBase64, 'base64'), format: 'der', type: 'pkcs8' });
  return nodeSign(null, Buffer.from(message, 'utf8'), key).toString('base64');
}

function derivePublicKey(privateKeyBase64) {
  const priv = createPrivateKey({ key: Buffer.from(privateKeyBase64, 'base64'), format: 'der', type: 'pkcs8' });
  return Buffer.from(createPublicKey(priv).export({ type: 'spki', format: 'der' })).toString('base64');
}

// ── Commands ──────────────────────────────────────────────────────────────────

async function cmdKeygen() {
  console.log(`\n${amb('Generating Ed25519 keypair...')}\n`);
  const { publicKey, privateKey } = generateKeyPair();

  console.log(`${hi('Public key')} ${dim('(add to PROVENANCE.yml identity.public_key)')}`);
  console.log(`${c.green}${publicKey}${c.reset}\n`);
  console.log(`${hi('Private key')} ${dim('(store as PROVENANCE_PRIVATE_KEY — never commit)')}`);
  console.log(`${c.amber}${privateKey}${c.reset}\n`);
  console.log(dim('─'.repeat(60)));
  console.log(dim('Add to your environment:'));
  console.log(`  PROVENANCE_PRIVATE_KEY=${privateKey}\n`);
  console.log(dim('Add to PROVENANCE.yml:'));
  console.log(`  identity:`);
  console.log(`    public_key: "${publicKey}"`);
  console.log(`    algorithm: ed25519\n`);
}

async function cmdRegister(args) {
  const id          = args.id;
  const url         = args.url;
  const name        = args.name;
  const description = args.description || args.desc;
  const caps        = args.capabilities ? args.capabilities.split(',').map(s => s.trim()) : [];
  const cons        = args.constraints  ? args.constraints.split(',').map(s => s.trim())  : [];
  const model       = args.model;
  const modelId     = args['model-id'];
  const ajpEndpoint = args['ajp-endpoint'];
  const privateKey  = args['private-key'] || process.env.PROVENANCE_PRIVATE_KEY;

  if (!id)  { console.error(err('--id required'));  process.exit(1); }
  if (!url) { console.error(err('--url required')); process.exit(1); }

  console.log(`\n${amb('Registering')} ${hi(id)}...\n`);

  let pubKey, signedChallenge;
  if (privateKey) {
    pubKey          = args['public-key'] || process.env.PROVENANCE_PUBLIC_KEY || derivePublicKey(privateKey);
    signedChallenge = signMessage(privateKey, `${id}:REGISTER`);
    console.log(ok('Signing with private key'));
  }

  const body = {
    provenance_id: id, url,
    ...(name        && { name }),
    ...(description && { description }),
    ...(caps.length && { capabilities: caps }),
    ...(cons.length && { constraints: cons }),
    ...(model       && { model_provider: model }),
    ...(modelId     && { model_id: modelId }),
    ...(ajpEndpoint && { ajp_endpoint: ajpEndpoint }),
    ...(pubKey      && { public_key: pubKey }),
    ...(signedChallenge && { signed_challenge: signedChallenge }),
  };

  const res  = await fetch(`${API}/api/agents/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const data = await res.json();

  if (!res.ok) { console.error(err(data.error || `HTTP ${res.status}`)); process.exit(1); }

  const agent = data.agent || data;
  console.log(ok(data.created ? 'Agent registered' : 'Agent updated'));
  console.log(`  ${dim('confidence:')}      ${c.green}${agent.confidence}${c.reset}`);
  console.log(`  ${dim('identity_verified:')} ${agent.identity_verified ? c.green + 'true' : c.amber + 'false'}${c.reset}`);
  if (ajpEndpoint) console.log(`  ${dim('ajp_endpoint:')}    ${ajpEndpoint}`);
  if (!agent.identity_verified)
    console.log(`\n${c.amber}Tip:${c.reset} Run with ${hi('--private-key')} to get identity_verified status`);
  console.log();
}

async function cmdStatus(args) {
  const id = args._[1];
  if (!id) { console.error(err('Usage: provenance status <provenance_id>')); process.exit(1); }

  console.log(`\n${amb('Checking')} ${hi(id)}...\n`);

  const res  = await fetch(`${API}/api/agent/${id.replace('provenance:', '').replace(':', '/')}`);
  const data = await res.json();

  if (!res.ok || data.error) { console.error(err(data.error || 'Not found')); process.exit(1); }

  const trust      = Math.round((data.confidence || 0) * 100);
  const trustColor = trust >= 80 ? c.green : trust >= 50 ? c.amber : c.red;

  console.log(`${hi(data.name || id)}`);
  console.log(`${dim(data.provenance_id)}\n`);
  console.log(`${dim('Trust score:')}       ${trustColor}${trust}/100${c.reset}`);
  console.log(`${dim('Declared:')}          ${data.declared ? c.green + 'yes' : c.amber + 'no'}${c.reset}`);
  console.log(`${dim('Identity verified:')} ${data.identity_verified ? c.green + 'yes' : c.amber + 'no'}${c.reset}`);
  console.log(`${dim('AJP endpoint:')}      ${data.ajp?.endpoint ? c.green + data.ajp.endpoint : c.dim + 'not set'}${c.reset}`);
  console.log(`${dim('Incidents:')}         ${(data.incident_count || 0) === 0 ? c.green + '0' : c.red + data.incident_count}${c.reset}`);
  if (data.capabilities?.length) console.log(`${dim('Capabilities:')}      ${data.capabilities.join(', ')}`);
  if (data.constraints?.length)  console.log(`${dim('Constraints:')}       ${data.constraints.join(', ')}`);

  console.log();
  for (const [pass, label] of [
    [data.declared,                'PROVENANCE.yml declared'],
    [data.identity_verified,       'Identity verified (Ed25519)'],
    [!!data.ajp?.endpoint,         'AJP endpoint configured'],
    [(data.incident_count||0)===0, 'No open incidents'],
  ]) console.log(`  ${pass ? ok(label) : dim('○ ' + label)}`);
  console.log();
}

async function cmdValidate(args) {
  const file = args._[1] || 'PROVENANCE.yml';
  const path = resolve(process.cwd(), file);
  if (!existsSync(path)) { console.error(err(`File not found: ${path}`)); process.exit(1); }

  console.log(`\n${amb('Validating')} ${hi(file)}...\n`);
  const content = readFileSync(path, 'utf8');
  const res  = await fetch(`${API}/api/mcp`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'validate_provenance_yml', arguments: { content } } }),
  });
  const rpc  = await res.json();
  const data = JSON.parse(rpc.result?.content?.[0]?.text || '{}');

  if (data.valid) console.log(ok('Valid PROVENANCE.yml'));
  else { console.log(err('Validation failed')); for (const e of data.errors || []) console.log(`  ${c.red}✗${c.reset} ${e}`); }
  for (const w of data.warnings || []) console.log(`  ${c.amber}⚠${c.reset} ${w}`);
  console.log();
}

async function cmdRevoke(args) {
  const id         = args.id;
  const privateKey = args['private-key'] || process.env.PROVENANCE_PRIVATE_KEY;
  if (!id)         { console.error(err('--id required')); process.exit(1); }
  if (!privateKey) { console.error(err('--private-key or PROVENANCE_PRIVATE_KEY required')); process.exit(1); }

  console.log(`\n${c.red}Revoking identity for${c.reset} ${hi(id)}...\n`);

  const res  = await fetch(`${API}/api/agents/revoke`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provenance_id: id, signed_challenge: signMessage(privateKey, `${id}:REVOKE`) }),
  });
  const data = await res.json();
  if (!res.ok || !data.success) { console.error(err(data.error || `HTTP ${res.status}`)); process.exit(1); }

  console.log(ok('Identity revoked'));
  console.log(dim('Run `provenance register` with a new keypair to re-establish.\n'));
}

function cmdHelp() {
  console.log(`
${hi('provenance')} ${dim(`v${VERSION}`)} — Provenance Protocol identity CLI

${amb('Commands:')}
  ${hi('keygen')}                              Generate an Ed25519 keypair
  ${hi('register')}  --id <id> --url <url>     Register or update your agent
               [--name <name>]
               [--description <text>]
               [--capabilities read:web,write:code]
               [--constraints no:pii,no:financial:transact]
               [--model anthropic] [--model-id claude-sonnet-4-6]
               [--ajp-endpoint <url>]
               [--private-key <key>]
  ${hi('status')}    <provenance_id>            Check trust score and checklist
  ${hi('validate')}  [file]                     Validate PROVENANCE.yml (default: ./PROVENANCE.yml)
  ${hi('revoke')}    --id <id>                  Revoke cryptographic identity
               [--private-key <key>]

${amb('Environment variables:')}
  PROVENANCE_ID           Your agent's Provenance ID
  PROVENANCE_PRIVATE_KEY  Your Ed25519 private key (base64 PKCS8 DER)
  PROVENANCE_API_URL      Override API base (default: https://getprovenance.dev)

${amb('For AJP job delegation:')}
  ${dim('npm install -g ajp-cli')}
  ${dim('npx ajp hire <id> --instruction "..."')}

${amb('Examples:')}
  npx provenance keygen
  npx provenance register --id provenance:github:alice/my-agent --url https://github.com/alice/my-agent
  npx provenance status provenance:github:alice/my-agent
  npx provenance validate
`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const args = parseArgs(argv);
const cmd  = args._[0];

try {
  if (!cmd || cmd === 'help' || args.help) cmdHelp();
  else if (cmd === 'keygen')   await cmdKeygen();
  else if (cmd === 'register') await cmdRegister(args);
  else if (cmd === 'status')   await cmdStatus(args);
  else if (cmd === 'validate') await cmdValidate(args);
  else if (cmd === 'revoke')   await cmdRevoke(args);
  else { console.error(err(`Unknown command: ${cmd}\nRun \`provenance help\` for usage.`)); process.exit(1); }
} catch (e) {
  console.error(err(e.message));
  process.exit(1);
}
