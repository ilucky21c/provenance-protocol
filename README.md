# provenance-protocol

SDK for querying the [Provenance](https://getprovenance.dev) agent identity index.

Drop this into any receiving system — marketplace, API, agent orchestrator —
to verify an AI agent's identity and trust profile before allowing it in.

```bash
npm install provenance-protocol
```

---

## Quick start

```js
import { provenance } from 'provenance-protocol';

// Check a single agent
const trust = await provenance.check('provenance:github:alice/research-assistant');
console.log(trust);
// {
//   found: true,
//   identity: 'verified',       // 'inferred' | 'declared' | 'verified'
//   identity_verified: true,
//   declared: true,
//   age_days: 142,
//   capabilities: ['read:web', 'write:summaries'],
//   constraints: ['no:financial:transact', 'no:pii'],
//   incidents: 0,
//   status: 'active'
// }
```

---

## gate() — all checks in one call

The most useful method for receiving systems.

```js
const result = await provenance.gate('provenance:github:alice/agent', {
  requireDeclared: true,                                    // must have PROVENANCE.yml
  requireVerified: true,                                    // must have identity_verified: true
  requireConstraints: ['no:financial:transact', 'no:pii'], // must have committed to these
  requireClean: true,                                       // no open incidents
  requireMinAge: 30,                                        // must be at least 30 days old
});

if (!result.allowed) {
  return res.status(403).json({ error: result.reason });
  // e.g. "Agent has not committed to constraint: no:financial:transact"
}

// result.trust has the full profile if you need it
```

---

## Individual methods

```js
// Boolean checks
await provenance.hasConstraint(id, 'no:financial:transact'); // → true/false
await provenance.hasCapability(id, 'read:web');              // → true/false
await provenance.isClean(id);                                // → true/false
await provenance.isOldEnough(id, 90);                        // → true/false (90+ days)

// Search for agents
const results = await provenance.search({
  capabilities: ['read:web'],
  constraints: ['no:financial:transact'],
  declared: true,
  limit: 10,
});
```

---

## Configuration

```js
import { Provenance } from 'provenance-protocol';

const provenance = new Provenance({
  apiUrl: 'https://your-own-provenance-instance.com',
  cacheTTL: 300,        // Cache results for 5 minutes (default)
  onApiError: 'deny'    // 'throw' | 'allow' | 'deny' (default: 'throw')
});
```

### Caching

All `check()` calls are automatically cached with a configurable TTL (default 5 minutes). This dramatically reduces latency and load when used in middleware or hot paths.

### Fail-Safe Behavior

When the Provenance API is unreachable, you can configure how `gate()` responds:

- `'throw'` (default): Throws an error, letting your app handle it
- `'deny'`: Returns `{ allowed: false }` — fail closed
- `'allow'`: Returns `{ allowed: true }` — fail open

```js
// Fail closed if API is down
const result = await provenance.gate(id, {
  requireDeclared: true,
  onApiError: 'deny'
});

if (result.fallback) {
  console.warn('Verification skipped due to API unavailability');
}
```

---

## What the trust object contains

| Field | Type | Description |
|---|---|---|
| `found` | boolean | Agent exists in Provenance index |
| `identity` | string | `'inferred'` \| `'declared'` \| `'verified'` — see below |
| `identity_verified` | boolean | Cryptographic key ownership confirmed against a public URL |
| `declared` | boolean | Agent has a PROVENANCE.yml (or registered via API with full fields) |
| `age_days` | number | Days since first indexed |
| `capabilities` | string[] | What the agent declares it can do |
| `constraints` | string[] | What the agent has publicly committed never to do |
| `incidents` | number | Number of open incidents |
| `status` | string | `active` / `suspended` / `removed` |
| `model` | object | `{ provider, model_id }` if declared |
| `public_key` | string\|null | Base64 Ed25519 public key, if registered |
| `ajp_endpoint` | string\|null | AJP job endpoint URL, if the agent accepts delegated jobs |
| `first_seen` | string | ISO date of first public appearance |

### Identity states

| State | Meaning |
|---|---|
| `inferred` | Indexed by crawler from a public repo. No PROVENANCE.yml, no self-registration. |
| `declared` | Agent registered itself (or has PROVENANCE.yml) but without cryptographic key verification. |
| `verified` | Agent registered with a keypair and the public key was confirmed against a publicly fetchable PROVENANCE.yml. **Independently auditable** — anyone can re-verify without trusting the Provenance registry. |

---

## Registering your own agent

### Public repo (GitHub / HuggingFace / npm)

Push a `PROVENANCE.yml` containing your public key to the repo, then register. The server fetches the file and confirms the key — independently verifiable by anyone.

```js
import { generateProvenanceKeyPair, signForProvenance, signChallenge } from 'provenance-protocol/keygen';

const { publicKey, privateKey } = generateProvenanceKeyPair();
const provenanceId = 'provenance:github:your-org/your-agent';

// Add to PROVENANCE.yml → commit → push, then:
const signed_challenge = signChallenge(privateKey, provenanceId, 'REGISTER');

await provenance.register({
  id: provenanceId,
  url: 'https://github.com/your-org/your-agent',
  name: 'Your Agent',
  description: 'What it does',
  capabilities: ['read:web', 'write:summaries'],
  constraints: ['no:pii'],
  public_key: publicKey,
  signed_challenge,
});
// → { created: true, agent: { identity: 'verified', identity_verified: true } }
```

### Private agent (no public repo)

Use `provenance:custom:` platform. Host your `PROVENANCE.yml` at any public URL you control and pass it as `url` — this makes the identity independently verifiable. Without a `url`, verification is registry-dependent (key control only).

```js
const provenanceId = 'provenance:custom:your-org/your-agent';
const signed_challenge = signChallenge(privateKey, provenanceId, 'REGISTER');

await provenance.register({
  id: provenanceId,
  url: 'https://yourdomain.com/.well-known/provenance.yml', // optional but recommended
  name: 'Your Agent',
  description: 'What it does',
  capabilities: ['read:web'],
  constraints: ['no:pii'],
  public_key: publicKey,
  signed_challenge,
});
// → { created: true, agent: { identity: 'verified', identity_verified: true } }
```

See [getprovenance.dev/docs#ai-quickstart](https://getprovenance.dev/docs#ai-quickstart) for full automated scripts.

## Revoking a compromised key

```js
import { signRevocation } from 'provenance-protocol/keygen';

const signed_challenge = signRevocation(process.env.PROVENANCE_PRIVATE_KEY, provenanceId);

await fetch('https://getprovenance.dev/api/agents/revoke', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ provenance_id: provenanceId, signed_challenge }),
});
// Then generate a new keypair and re-register
```

---

## CLI

```bash
npx provenance keygen
npx provenance register --id provenance:github:your-org/your-agent --url https://github.com/...
npx provenance status provenance:github:alice/my-agent
npx provenance validate PROVENANCE.yml
npx provenance revoke --id provenance:github:your-org/your-agent
```

Full CLI reference: [getprovenance.dev/docs#cli](https://getprovenance.dev/docs#cli)

---

## Layers

`provenance-protocol` is the identity layer. Protocols that build on it:

| Package | Purpose |
|---|---|
| `provenance-protocol` | Agent identity, trust, and registration (this package) |
| [`ajp-protocol`](https://www.npmjs.com/package/ajp-protocol) | Agent Job Protocol — agent-to-agent job delegation |

---

## Full documentation

[getprovenance.dev/docs](https://getprovenance.dev/docs)

---

## MIT License — getprovenance.dev
