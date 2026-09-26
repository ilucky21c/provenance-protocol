/**
 * provenance-protocol — `provenance init`
 *
 * Writes and signs a first declaration in about five minutes, on the
 * developer's own machine. Nothing is sent anywhere.
 *
 *   1. Reads what the project already knows: name, version, repository,
 *      which AI provider it uses, which libraries imply which capabilities,
 *      which MCP servers it connects to.
 *   2. Suggests the promises (constraints) that fit — the developer decides.
 *   3. Asks the few policy questions that matter; everything else stays
 *      optional until a buyer asks.
 *   4. Generates a key if there is none, keeps it out of git, and signs.
 *
 * Promises are never made on the developer's behalf: with --yes, detected
 * facts are filled in, but constraints and policy answers are only listed as
 * suggestions, because a promise has to be a decision.
 *
 * Node-only.
 */

import { readFileSync, existsSync, writeFileSync, appendFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { execFileSync } from 'node:child_process';
import YAML from 'yaml';
import { generateProvenanceKeyPair, signDeclaration } from './keygen.js';
import { verifyDeclaration } from './verify.js';
import { validateDeclaration } from './validate.js';

// Library → what it implies. Deliberately short: a wrong suggestion costs the
// developer's trust in every other suggestion.
const PROVIDERS = [
  [/^@anthropic-ai\/sdk$|^anthropic$|^@ai-sdk\/anthropic$|^langchain-anthropic$/, 'anthropic'],
  [/^openai$|^@ai-sdk\/openai$|^langchain-openai$/, 'openai'],
  [/^@google\/generative-ai$|^@google\/genai$|^google-genai$|^google-generativeai$|^@ai-sdk\/google$/, 'google'],
  [/^@mistralai\/mistralai$|^mistralai$|^@ai-sdk\/mistral$/, 'mistral'],
  [/^ollama$/, 'local'],
];

const CAPABILITY_HINTS = [
  [/^(nodemailer|@sendgrid\/mail|resend|postmark|mailgun\.js|sendgrid|smtplib)$/, 'write:email', 'sends email'],
  [/^(stripe|@stripe\/stripe-js|braintree|adyen|@paypal\/.+|paypalrestsdk)$/, 'financial:transact', 'payment library'],
  [/^(puppeteer|playwright|@playwright\/test|selenium|browser-use)$/, 'execute:browser', 'browser automation'],
  [/^(pg|mysql2?|mongodb|mongoose|@prisma\/client|prisma|sequelize|typeorm|knex|drizzle-orm|psycopg2?|psycopg2-binary|sqlalchemy|pymongo)$/, 'read:database', 'database client'],
  [/^(pdf-parse|pdfjs-dist|pypdf|pdfplumber|pymupdf)$/, 'read:pdf', 'PDF parsing'],
  [/^(@e2b\/code-interpreter|e2b|e2b-code-interpreter)$/, 'execute:code', 'code sandbox'],
];

// Capabilities worth a promise when the code shows no sign of them.
const PROMISE_CANDIDATES = [
  ['financial:transact', 'never move money'],
  ['write:email', 'never send email'],
  ['write:external', 'never write to external systems'],
  ['delegate:agents', 'never hand work to other agents'],
  ['execute:code', 'never run code'],
];

const RETENTION = { '1': 'none', '2': 'P30D', '3': 'P90D', '4': 'P365D' };
const TRAINING = { '1': 'none', '2': 'opt_in', '3': 'opt_out', '4': 'yes' };

function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

function pythonDeps(dir) {
  const deps = new Set();
  const req = join(dir, 'requirements.txt');
  if (existsSync(req)) {
    for (const line of readFileSync(req, 'utf8').split('\n')) {
      const m = /^\s*([A-Za-z0-9_.-]+)/.exec(line);
      if (m && !line.trim().startsWith('#')) deps.add(m[1].toLowerCase());
    }
  }
  const pyproject = join(dir, 'pyproject.toml');
  if (existsSync(pyproject)) {
    const text = readFileSync(pyproject, 'utf8');
    for (const m of text.matchAll(/["']([A-Za-z0-9_.-]+)\s*(?:[<>=~!;[]|["'])/g)) deps.add(m[1].toLowerCase());
  }
  return deps;
}

function projectMeta(dir) {
  const pkg = readJson(join(dir, 'package.json'));
  if (pkg) {
    return {
      name: pkg.name?.replace(/^@[^/]+\//, ''),
      description: pkg.description,
      version: pkg.version,
      deps: new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]),
      source: 'package.json',
    };
  }
  const pyproject = join(dir, 'pyproject.toml');
  if (existsSync(pyproject)) {
    const text = readFileSync(pyproject, 'utf8');
    const get = (k) => new RegExp(`^${k}\\s*=\\s*["']([^"']+)["']`, 'm').exec(text)?.[1];
    return { name: get('name'), description: get('description'), version: get('version'), deps: pythonDeps(dir), source: 'pyproject.toml' };
  }
  return { name: basename(dir), description: undefined, version: undefined, deps: pythonDeps(dir), source: null };
}

function gitRemote(dir) {
  try {
    const url = execFileSync('git', ['-C', dir, 'remote', 'get-url', 'origin'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const m = /github\.com[:/]([^/]+)\/([^/.]+?)(?:\.git)?$/i.exec(url);
    return m ? { owner: m[1], repo: m[2] } : null;
  } catch {
    return null;
  }
}

// Model ids appearing as string literals, e.g. 'claude-sonnet-4-5'. Only a
// single unambiguous match is used; several are listed and none chosen.
function modelIds(dir) {
  const found = new Set();
  const pattern = /["'`]((?:claude|gpt|o[134]|gemini|mistral|llama)[-.][A-Za-z0-9.-]{2,40})["'`]/g;
  let files = 0;
  const walk = (d, depth) => {
    if (depth > 4 || files > 400) return;
    let entries;
    try { entries = readdirSync(d); } catch { return; }
    for (const e of entries) {
      if (e.startsWith('.') || e === 'node_modules' || e === 'dist' || e === 'build' || e === 'venv' || e === '__pycache__') continue;
      const p = join(d, e);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p, depth + 1);
      else if (/\.(m?[jt]sx?|py)$/.test(e) && st.size < 200_000) {
        files++;
        for (const m of readFileSync(p, 'utf8').matchAll(pattern)) found.add(m[1]);
      }
    }
  };
  walk(dir, 0);
  return [...found];
}

function mcpServers(dir) {
  const out = [];
  for (const f of ['.mcp.json', 'mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
    const cfg = readJson(join(dir, f));
    const servers = cfg?.mcpServers ?? cfg?.servers;
    if (!servers || typeof servers !== 'object') continue;
    for (const [name, s] of Object.entries(servers)) {
      if (typeof s?.url === 'string' && /^https:\/\//.test(s.url)) {
        out.push({ url: s.url, kind: 'mcp_server', purpose: name });
      } else if (typeof s?.command === 'string') {
        // A local server has no URL to name; record it by package where possible.
        const pkg = (s.args ?? []).find((a) => typeof a === 'string' && /^[@a-z0-9]/.test(a) && !a.startsWith('-'));
        if (pkg) out.push({ url: `https://www.npmjs.com/package/${pkg.replace(/@[^@/]+$/, '')}`, kind: 'package', purpose: `MCP server: ${name}` });
      }
    }
  }
  return out;
}

/**
 * What the project already says about itself. Pure detection — no prompts,
 * no writes — so it can be tested and shown before anything is decided.
 *
 * @param {string} dir  Project root
 * @param {object} [options]
 * @param {string} [options.domain]  Hostname the agent is served from, for a provenance:domain: id
 */
export function detectProject(dir, { domain } = {}) {
  const meta = projectMeta(dir);
  const deps = [...meta.deps].map((d) => d.toLowerCase());
  const remote = gitRemote(dir);

  const provider = PROVIDERS.find(([re]) => deps.some((d) => re.test(d)))?.[1] ?? null;
  const ids = modelIds(dir);

  const capabilities = new Map();
  for (const [re, cap, why] of CAPABILITY_HINTS) {
    const dep = deps.find((d) => re.test(d));
    if (dep) capabilities.set(cap, `${why} (${dep})`);
  }

  const dependencies = mcpServers(dir);
  const provenanceId = domain
    ? `provenance:domain:${domain.toLowerCase()}`
    : remote ? `provenance:github:${remote.owner}/${remote.repo}` : null;

  const promises = PROMISE_CANDIDATES
    .filter(([cap]) => !capabilities.has(cap) && !(cap === 'delegate:agents' && dependencies.length))
    .map(([cap, words]) => ({ constraint: `no:${cap}`, words }));

  return {
    name: meta.name,
    description: meta.description,
    version: meta.version,
    source: meta.source,
    provenanceId,
    model: provider ? { provider, ...(ids.length === 1 ? { model_id: ids[0] } : {}) } : null,
    modelIdsSeen: ids,
    capabilities: [...capabilities].map(([capability, reason]) => ({ capability, reason })),
    dependencies,
    promises,
  };
}

/**
 * Build the declaration from detected facts and the developer's answers.
 * Only answered policy questions become fields; nothing is guessed.
 */
export function buildDeclaration(found, answers = {}) {
  const d = {
    provenance: '0.2',
    name: answers.name ?? found.name,
    description: answers.description ?? found.description,
    ...(found.version ? { version: String(found.version) } : {}),
    ...(found.model ? { model: found.model } : {}),
    capabilities: found.capabilities.map((c) => c.capability),
    constraints: answers.constraints ?? [],
    ...(found.dependencies.length ? { dependencies: found.dependencies } : {}),
  };
  if (!d.capabilities.length) delete d.capabilities;
  if (!d.constraints.length) delete d.constraints;
  const data = {};
  if (answers.retention) data.retention = answers.retention;
  if (answers.training_use) data.training_use = answers.training_use;
  if (Object.keys(data).length) d.data = data;
  if (answers.operator) d.operator = answers.operator;
  if (answers.provenanceId ?? found.provenanceId) d.provenance_id = answers.provenanceId ?? found.provenanceId;
  return d;
}

const HEADER = `# PROVENANCE.yml — what this agent is, can do, and promises never to do.
# Generated by \`provenance init\`. Edit freely, then re-sign: npx provenance-protocol sign
# Spec: https://github.com/provenance-protocol/provenance-protocol/blob/main/SPEC.md
`;

function keepOutOfGit(dir, file) {
  const gi = join(dir, '.gitignore');
  const existing = existsSync(gi) ? readFileSync(gi, 'utf8') : '';
  if (!existing.split('\n').some((l) => l.trim() === file)) {
    appendFileSync(gi, `${existing && !existing.endsWith('\n') ? '\n' : ''}${file}\n`);
  }
}

/**
 * Run init. `ask(question, fallback)` returns the answer string; supply one
 * backed by a terminal, or none with `yes` for non-interactive use.
 *
 * @returns {Promise<{ path: string, declaration: object, keyCreated: boolean, suggestions: object, notStated: string[] }>}
 */
export async function runInit(dir, { ask, yes = false, domain, force = false, privateKey } = {}) {
  const path = join(dir, 'PROVENANCE.yml');
  if (existsSync(path) && !force) {
    throw new Error('PROVENANCE.yml already exists. Edit it and run `provenance sign`, or pass --force to start again.');
  }
  if (!yes && typeof ask !== 'function') throw new Error('init needs a terminal to ask questions, or --yes');

  const found = detectProject(dir, { domain });
  const answers = {};
  const notStated = [];
  const q = async (text, fallback) => (yes ? fallback : ((await ask(text, fallback)) || fallback));

  answers.name = await q(`Agent name [${found.name ?? ''}]: `, found.name);
  answers.description = await q(`One line on what it does [${found.description ?? ''}]: `, found.description);
  if (!answers.name || !answers.description) {
    throw new Error('A name and a one-line description are required. Pass them in package.json or answer the prompts.');
  }

  if (!found.provenanceId) {
    const host = await q('Where is it served from? Hostname, e.g. agent.example.com (blank to skip): ', '');
    if (host) answers.provenanceId = `provenance:domain:${host.toLowerCase()}`;
    else notStated.push('provenance_id — needed before anyone can tie this declaration to you');
  }

  // Promises: always a decision, never a default.
  answers.constraints = [];
  if (!yes) {
    for (const p of found.promises) {
      const a = (await ask(`Your code shows no sign of this. Promise it will ${p.words}? [y/N]: `, 'n')).trim().toLowerCase();
      if (a === 'y' || a === 'yes') answers.constraints.push(p.constraint);
    }
    const pii = (await ask('Promise it never collects personal data? [y/N]: ', 'n')).trim().toLowerCase();
    if (pii === 'y' || pii === 'yes') answers.constraints.push('no:pii');

    const r = await ask('How long is data you receive kept? 1) not kept  2) 30 days  3) 90 days  4) a year  (blank to skip): ', '');
    if (RETENTION[r.trim()]) answers.retention = RETENTION[r.trim()];
    else notStated.push('data.retention');
    const t = await ask('Is it used to train models? 1) never  2) only if the customer opts in  3) unless they opt out  4) yes  (blank to skip): ', '');
    if (TRAINING[t.trim()]) answers.training_use = TRAINING[t.trim()];
    else notStated.push('data.training_use');
  } else {
    notStated.push('constraints (promises are never made for you — see suggestions)', 'data.retention', 'data.training_use');
  }

  const declaration = buildDeclaration(found, answers);

  // Key: use the one in the environment, or create one kept out of git.
  let key = privateKey ?? process.env.PROVENANCE_PRIVATE_KEY;
  let keyCreated = false;
  if (!key) {
    const pair = generateProvenanceKeyPair();
    key = pair.privateKey;
    writeFileSync(join(dir, '.provenance-key'), `${key}\n`, { mode: 0o600 });
    keepOutOfGit(dir, '.provenance-key');
    keyCreated = true;
  }
  const { createPrivateKey, createPublicKey } = await import('node:crypto');
  const publicKey = Buffer.from(
    createPublicKey(createPrivateKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'pkcs8' }))
      .export({ type: 'spki', format: 'der' })
  ).toString('base64');
  declaration.identity = { public_key: publicKey, algorithm: 'ed25519' };

  const schema = validateDeclaration(declaration);
  if (!schema.valid) throw new Error(`The draft does not validate: ${schema.errors.join('; ')}`);

  declaration.identity.signature = signDeclaration(key, declaration);
  writeFileSync(path, HEADER + '\n' + YAML.stringify(declaration, { lineWidth: 0 }));

  // Read back what was written and verify it; a write that went wrong must
  // not be reported as a success.
  const back = YAML.parse(readFileSync(path, 'utf8'));
  const check = await verifyDeclaration(back);
  if (!check.valid) throw new Error(`Wrote PROVENANCE.yml but it does not verify: ${check.reason}`);

  return {
    path,
    declaration: back,
    keyCreated,
    suggestions: { promises: found.promises, modelIdsSeen: found.modelIdsSeen },
    notStated,
  };
}
