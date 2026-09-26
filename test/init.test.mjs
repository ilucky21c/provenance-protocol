import { mkdtempSync, writeFileSync, readFileSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import YAML from 'yaml';
import { detectProject, runInit } from '../src/init.js';
import { verifyDeclaration } from '../src/verify.js';
import { validateDeclaration } from '../src/validate.js';

let pass = 0, fail = 0;
const t = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${JSON.stringify(detail)}`}`);
  ok ? pass++ : fail++;
};
delete process.env.PROVENANCE_PRIVATE_KEY;

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'init-'));
  for (const [f, body] of Object.entries(files)) {
    mkdirSync(join(dir, f, '..'), { recursive: true });
    writeFileSync(join(dir, f), typeof body === 'string' ? body : JSON.stringify(body));
  }
  return dir;
}

const node = project({
  'package.json': { name: '@acme/support-agent', description: 'Answers customer support tickets.', version: '2.1.0',
    dependencies: { '@anthropic-ai/sdk': '^1', nodemailer: '^6', '@prisma/client': '^5' } },
  'src/agent.ts': "const model = 'claude-sonnet-4-5';\n",
  '.mcp.json': { mcpServers: { search: { url: 'https://mcp.search.example/sse' }, files: { command: 'npx', args: ['-y', '@acme/files-mcp@1.2.0'] } } },
});
execFileSync('git', ['-C', node, 'init', '-q']);
execFileSync('git', ['-C', node, 'remote', 'add', 'origin', 'git@github.com:acme/support-agent.git']);

const f = detectProject(node);
t('reads name, description, version from package.json', f.name === 'support-agent' && f.version === '2.1.0' && /support tickets/.test(f.description));
t('derives the id from the git remote', f.provenanceId === 'provenance:github:acme/support-agent', f.provenanceId);
t('detects the AI provider and the one model id used', f.model?.provider === 'anthropic' && f.model?.model_id === 'claude-sonnet-4-5', f.model);
t('suggests capabilities from libraries, with the reason', f.capabilities.some((c) => c.capability === 'write:email' && /nodemailer/.test(c.reason)) && f.capabilities.some((c) => c.capability === 'read:database'));
t('reads MCP servers as dependencies', f.dependencies.some((d) => d.url === 'https://mcp.search.example/sse' && d.kind === 'mcp_server') && f.dependencies.some((d) => d.url === 'https://www.npmjs.com/package/@acme/files-mcp'), f.dependencies);
t('never suggests promising against what the code does', !f.promises.some((p) => p.constraint === 'no:write:email') && f.promises.some((p) => p.constraint === 'no:financial:transact'));

// Interactive run: the developer accepts one promise and answers the policy questions.
const answers = {
  'Promise it will never move money': 'y',
  'Promise it never collects personal data': 'n',
  'How long is data you receive kept': '2',
  'Is it used to train models': '1',
};
const ask = async (question) => Object.entries(answers).find(([k]) => question.includes(k))?.[1] ?? '';
const r = await runInit(node, { ask });
const written = YAML.parse(readFileSync(join(node, 'PROVENANCE.yml'), 'utf8'));
t('writes a declaration that validates', validateDeclaration(written).valid, validateDeclaration(written).errors);
t('and verifies, signed over every field', (await verifyDeclaration(written)).coverage === 'declaration');
t('records only the promises the developer made', JSON.stringify(written.constraints) === JSON.stringify(['no:financial:transact']), written.constraints);
t('records the policy answers', written.data?.retention === 'P30D' && written.data?.training_use === 'none', written.data);
t('creates a key readable only by its owner, kept out of git', r.keyCreated && (statSync(join(node, '.provenance-key')).mode & 0o077) === 0 && readFileSync(join(node, '.gitignore'), 'utf8').includes('.provenance-key'));
t('the private key is not in the declaration', !readFileSync(join(node, 'PROVENANCE.yml'), 'utf8').includes(readFileSync(join(node, '.provenance-key'), 'utf8').trim()));

let refused = false;
try { await runInit(node, { ask }); } catch (e) { refused = /already exists/.test(e.message); }
t('never overwrites an existing declaration without --force', refused);

// Non-interactive: facts only, no promises made for anyone.
const py = project({
  'pyproject.toml': '[project]\nname = "invoice-bot"\ndescription = "Reads invoices."\nversion = "0.3.0"\ndependencies = ["openai>=1", "stripe>=7", "pdfplumber"]\n',
});
const y = await runInit(py, { yes: true, domain: 'invoices.example.com' });
t('--yes on a Python project fills in the facts', y.declaration.name === 'invoice-bot' && y.declaration.model?.provider === 'openai' && y.declaration.capabilities.includes('financial:transact') && y.declaration.provenance_id === 'provenance:domain:invoices.example.com', y.declaration);
t('--yes makes no promises and says so', !y.declaration.constraints && y.notStated.some((n) => n.startsWith('constraints')));

const bare = project({});
let needsInfo = false;
try { await runInit(bare, { yes: true }); } catch (e) { needsInfo = /name and a one-line description/.test(e.message); }
t('a project with no name or description is refused, saying what is missing', needsInfo);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
