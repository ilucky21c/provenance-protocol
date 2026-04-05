#!/usr/bin/env node
/**
 * provenance CLI
 *
 * npx provenance keygen
 * npx provenance register --id provenance:github:org/agent --url https://...
 * npx provenance status provenance:github:org/agent
 * npx provenance revoke --id provenance:github:org/agent
 */

import { writeFileSync, readFileSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { generateProvenanceKeyPair, signChallenge, signForProvenance, signRevocation } from './keygen.js';

const API = 'https://getprovenance.dev/api/agents';
const KEY_FILE = '.provenance-key';

function readPrivateKey() {
  if (process.env.PROVENANCE_PRIVATE_KEY) return process.env.PROVENANCE_PRIVATE_KEY.trim();
  if (existsSync(KEY_FILE)) return readFileSync(KEY_FILE, 'utf8').trim();
  console.error(`No private key found. Set PROVENANCE_PRIVATE_KEY or run: npx provenance keygen`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    } else {
      args._ = args._ || [];
      args._.push(argv[i]);
    }
  }
  return args;
}

const [,, command, ...rest] = process.argv;
const args = parseArgs(rest);

// ── keygen ──────────────────────────────────────────────────────────────────

if (command === 'keygen') {
  const { publicKey, privateKey } = generateProvenanceKeyPair();

  writeFileSync(KEY_FILE, privateKey, { mode: 0o600 });
  try { execSync(`grep -qxF "${KEY_FILE}" .gitignore 2>/dev/null || echo "${KEY_FILE}" >> .gitignore`); } catch {}

  console.log(`\nKeypair generated.\n`);
  console.log(`Private key → ${KEY_FILE} (chmod 600, added to .gitignore)`);
  console.log(`\nPublic key (add to PROVENANCE.yml):\n`);
  console.log(`  identity:`);
  console.log(`    public_key: "${publicKey}"`);
  console.log(`    algorithm: ed25519`);
  console.log(`\nNext: npx provenance register --id provenance:<platform>:<org>/<name>\n`);
  process.exit(0);
}

// ── register ─────────────────────────────────────────────────────────────────

if (command === 'register') {
  const id = args.id || args._?.[0];
  if (!id) { console.error('Usage: npx provenance register --id provenance:<platform>:<org>/<name> [options]'); process.exit(1); }

  const privateKey = readPrivateKey();
  const { publicKey } = (() => {
    // derive public key from private key for display — we just use the stored one
    // We can't derive public from private easily here, so read from PROVENANCE.yml or require --public-key
    return { publicKey: args['public-key'] || null };
  })();

  // If no public key arg, re-generate won't work — need the stored public key
  // Best path: require keygen was run, read public key from PROVENANCE.yml if present
  let pubKey = args['public-key'];
  if (!pubKey) {
    if (existsSync('PROVENANCE.yml')) {
      const yml = readFileSync('PROVENANCE.yml', 'utf8');
      const match = yml.match(/public_key:\s*["']?([A-Za-z0-9+/=]+)["']?/);
      if (match) pubKey = match[1];
    }
  }
  if (!pubKey) {
    console.error('Public key required. Pass --public-key or add identity.public_key to PROVENANCE.yml first.');
    process.exit(1);
  }

  const signed_challenge = signChallenge(privateKey, id, 'REGISTER');

  const body = {
    provenance_id: id,
    public_key: pubKey,
    signed_challenge,
    ...(args.url ? { url: args.url } : {}),
    ...(args.name ? { name: args.name } : {}),
    ...(args.description ? { description: args.description } : {}),
    ...(args.capabilities ? { capabilities: args.capabilities.split(',').map(s => s.trim()) } : {}),
    ...(args.constraints ? { constraints: args.constraints.split(',').map(s => s.trim()) } : {}),
    ...(args.model ? { model_provider: args.model } : {}),
    ...(args['model-id'] ? { model_id: args['model-id'] } : {}),
  };

  try {
    const res = await fetch(`${API}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error(`\nRegistration failed: ${data.error}`);
      if (data.hint) console.error(`Hint: ${data.hint}`);
      process.exit(1);
    }
    console.log(`\n${data.created ? 'Registered' : 'Updated'}: ${id}`);
    console.log(`identity: ${data.agent?.identity}`);
    console.log(`profile:  https://getprovenance.dev/agent/${id.replace('provenance:', '').replace(':', '/')}\n`);
  } catch (e) {
    console.error('Network error:', e.message);
    process.exit(1);
  }
  process.exit(0);
}

// ── status ───────────────────────────────────────────────────────────────────

if (command === 'status') {
  const id = args._?.[0] || args.id;
  if (!id) { console.error('Usage: npx provenance status <provenance_id>'); process.exit(1); }

  try {
    const res = await fetch(`${API}/register?provenance_id=${encodeURIComponent(id)}`);
    const data = await res.json();
    if (!data.registered) { console.log(`\nNot registered: ${id}\n`); process.exit(0); }
    const a = data.agent;
    console.log(`\n${id}`);
    console.log(`name:     ${a.name || '—'}`);
    console.log(`identity: ${a.identity}`);
    console.log(`status:   ${a.status}`);
    console.log(`profile:  https://getprovenance.dev/agent/${id.replace('provenance:', '').replace(':', '/')}\n`);
  } catch (e) {
    console.error('Network error:', e.message);
    process.exit(1);
  }
  process.exit(0);
}

// ── revoke ───────────────────────────────────────────────────────────────────

if (command === 'revoke') {
  const id = args.id || args._?.[0];
  if (!id) { console.error('Usage: npx provenance revoke --id <provenance_id>'); process.exit(1); }

  const privateKey = readPrivateKey();
  const signed_challenge = signRevocation(privateKey, id);

  try {
    const res = await fetch(`${API}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provenance_id: id, signed_challenge }),
    });
    const data = await res.json();
    if (!res.ok) { console.error(`Revocation failed: ${data.error}`); process.exit(1); }
    console.log(`\nKey revoked for ${id}.`);
    console.log(`Run npx provenance keygen && npx provenance register --id ${id} to re-register with a new key.\n`);
  } catch (e) {
    console.error('Network error:', e.message);
    process.exit(1);
  }
  process.exit(0);
}

// ── help ─────────────────────────────────────────────────────────────────────

console.log(`
provenance <command>

  keygen                          Generate an Ed25519 keypair
  register --id <id> [options]    Register or update your agent
  status <id>                     Check registration status
  revoke --id <id>                Revoke your registered key

register options:
  --id           provenance:<platform>:<org>/<name>  (required)
  --url          URL to your PROVENANCE.yml (for independent verification)
  --name         Agent display name
  --description  One-sentence description
  --capabilities read:web,write:summaries
  --constraints  no:pii,no:financial:transact
  --model        anthropic / openai / etc.
  --model-id     claude-sonnet-4-6 / gpt-4o / etc.
  --public-key   Base64 public key (auto-read from PROVENANCE.yml if present)

Full docs: https://getprovenance.dev/docs
`);
process.exit(0);
