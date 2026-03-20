/**
 * provenance-protocol SDK
 *
 * Drop this into any receiving system — marketplace, API, agent orchestrator.
 * Query the Provenance index before trusting an agent.
 *
 * npm install provenance-protocol
 *
 * Usage:
 *   import { Provenance } from 'provenance-protocol';
 *   const trust = await Provenance.check('provenance:github:alice/research-assistant');
 */

// ── Cryptographic helpers ──────────────────────────────────────────────────
// Uses the Web Crypto API (crypto.subtle) which is available in:
//   - All modern browsers
//   - Node.js 18+ (globalThis.crypto.subtle)
// No external dependencies needed.

/**
 * Verify an Ed25519 signature against a public key stored in the index.
 *
 * @param {string} publicKeyBase64  Base64-encoded SPKI DER public key
 * @param {string} signatureBase64  Base64-encoded raw signature (64 bytes)
 * @param {string} message          The message that was signed (UTF-8 string)
 * @returns {Promise<boolean>}
 */
async function _verifyEd25519(publicKeyBase64, signatureBase64, message) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('Web Crypto API (crypto.subtle) not available');

  const keyBuffer = Uint8Array.from(Buffer.from(publicKeyBase64, 'base64'));
  const sigBuffer = Uint8Array.from(Buffer.from(signatureBase64, 'base64'));
  const msgBuffer = new TextEncoder().encode(message);

  const cryptoKey = await subtle.importKey(
    'spki',
    keyBuffer,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  return subtle.verify('Ed25519', cryptoKey, sigBuffer, msgBuffer);
}

const DEFAULT_API = 'https://provenance.dev';
const DEFAULT_CACHE_TTL = 300; // 5 minutes

// Simple LRU cache
class Cache {
  constructor(ttlSeconds = DEFAULT_CACHE_TTL) {
    this.cache = new Map();
    this.ttl = ttlSeconds * 1000;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }
    return item.value;
  }

  set(key, value) {
    this.cache.set(key, {
      value,
      expiry: Date.now() + this.ttl
    });
  }

  clear() {
    this.cache.clear();
  }
}

export class Provenance {

  constructor({ 
    apiUrl = DEFAULT_API,
    cacheTTL = DEFAULT_CACHE_TTL,
    onApiError = 'throw' // 'throw' | 'allow' | 'deny'
  } = {}) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.cache = new Cache(cacheTTL);
    this.onApiError = onApiError;
  }

  // ── Main method — the one most receiving systems need ────────────────────

  /**
   * Check an agent's trust profile.
   *
   * @param {string} provenanceId  e.g. "provenance:github:alice/research-assistant"
   * @returns {object} trust summary
   *
   * Example:
   *   const trust = await provenance.check('provenance:github:alice/research-assistant');
   *   // {
   *   //   found: true,
   *   //   declared: true,       — has PROVENANCE.yml
   *   //   age_days: 142,        — how long this agent has existed publicly
   *   //   confidence: 0.9,
   *   //   capabilities: ['read:web', 'write:summaries'],
   *   //   constraints: ['no:financial:transact', 'no:pii'],
   *   //   incidents: 0,
   *   //   model: { provider: 'anthropic', model_id: 'claude-sonnet-4-5' },
   *   //   status: 'active',
   *   // }
   */
  async check(provenanceId) {
    // Check cache first
    const cached = this.cache.get(provenanceId);
    if (cached) return cached;

    const path = this._idToPath(provenanceId);
    try {
      const res = await fetch(`${this.apiUrl}/api/agent/${path}`);
      if (res.status === 404) {
        const notFound = { found: false, provenance_id: provenanceId };
        this.cache.set(provenanceId, notFound);
        return notFound;
      }
      if (!res.ok) throw new Error(`Provenance API error: ${res.status}`);
      const data = await res.json();

      const result = {
        found: true,
        provenance_id: data.provenance_id,
        platform: data.platform,
        name: data.name,
        declared: data.declared,
        confidence: data.confidence,
        age_days: data.timestamps?.first_seen
          ? Math.floor((Date.now() - new Date(data.timestamps.first_seen)) / 86400000)
          : null,
        capabilities: data.capabilities || [],
        constraints: data.constraints || [],
        incidents: data.incident_count || 0,
        model: data.model || null,
        status: data.status || 'unknown',
        first_seen: data.timestamps?.first_seen || null,
        url: data.url,
        public_key: data.public_key || null,
      };

      // Cache the result
      this.cache.set(provenanceId, result);
      return result;
    } catch (e) {
      throw new Error(`Provenance.check failed: ${e.message}`);
    }
  }

  // ── Convenience guard methods — boolean checks ───────────────────────────

  /**
   * Returns true if the agent has publicly committed to a constraint.
   *
   * Example:
   *   if (!await provenance.hasConstraint(id, 'no:financial:transact')) {
   *     throw new Error('Agent not cleared for financial operations');
   *   }
   */
  async hasConstraint(provenanceId, constraint) {
    const trust = await this.check(provenanceId);
    return trust.found && trust.constraints.includes(constraint);
  }

  /**
   * Returns true if the agent has declared a capability.
   */
  async hasCapability(provenanceId, capability) {
    const trust = await this.check(provenanceId);
    return trust.found && trust.capabilities.includes(capability);
  }

  /**
   * Returns true if the agent has no open incidents.
   */
  async isClean(provenanceId) {
    const trust = await this.check(provenanceId);
    return trust.found && trust.incidents === 0 && trust.status === 'active';
  }

  /**
   * Returns true if the agent has existed for at least minDays.
   * Age is a proxy for reliability — a 6-month-old agent with no incidents
   * is more trustworthy than a brand-new one.
   */
  async isOldEnough(provenanceId, minDays) {
    const trust = await this.check(provenanceId);
    return trust.found && trust.age_days !== null && trust.age_days >= minDays;
  }

  // ── Cryptographic identity verification ──────────────────────────────────

  /**
   * Verify that a running agent cryptographically owns the identity it claims.
   *
   * This closes the gap between "a repo declares this identity" and "the agent
   * talking to you actually controls that repo's private key."
   *
   * Protocol (challenge-response):
   *   1. Receiving system generates a nonce:  const nonce = crypto.randomUUID()
   *   2. Receiving system sends nonce to agent
   *   3. Agent signs: signChallenge(privateKey, provenanceId, nonce) → signature
   *   4. Receiving system verifies: await provenance.verifySignature(id, nonce, signature)
   *
   * @param {string} provenanceId     e.g. "provenance:github:alice/research-assistant"
   * @param {string} nonce            The nonce you sent to the agent (UUID or random string)
   * @param {string} signatureBase64  Base64 signature returned by the agent
   * @returns {{ verified: boolean, reason: string | null }}
   *
   * Example:
   *   const nonce = crypto.randomUUID();
   *   // ... send nonce to agent, receive signature back ...
   *   const result = await provenance.verifySignature(
   *     'provenance:github:alice/research-assistant',
   *     nonce,
   *     agentSignature
   *   );
   *   if (!result.verified) throw new Error(`Identity check failed: ${result.reason}`);
   */
  async verifySignature(provenanceId, nonce, signatureBase64) {
    let trust;
    try {
      trust = await this.check(provenanceId);
    } catch (e) {
      return { verified: false, reason: `Could not fetch agent profile: ${e.message}` };
    }

    if (!trust.found) {
      return { verified: false, reason: 'Agent not found in Provenance index' };
    }
    if (!trust.public_key) {
      return { verified: false, reason: 'Agent has no public key registered in PROVENANCE.yml' };
    }

    // The signed message is always: "<provenanceId>:<nonce>"
    // This binds the signature to both the agent's identity and the specific challenge,
    // preventing replay attacks and cross-agent signature reuse.
    const message = `${provenanceId}:${nonce}`;

    try {
      const verified = await _verifyEd25519(trust.public_key, signatureBase64, message);
      return { verified, reason: verified ? null : 'Signature is invalid' };
    } catch (e) {
      return { verified: false, reason: `Signature verification error: ${e.message}` };
    }
  }

  // ── Gate method — combine all checks in one call ─────────────────────────

  /**
   * Run all your trust requirements in one call.
   * Returns { allowed, reason, trust }.
   *
   * Example:
   *   const result = await provenance.gate('provenance:github:alice/agent', {
   *     requireDeclared: true,
   *     requireConstraints: ['no:financial:transact', 'no:pii'],
   *     requireClean: true,
   *     requireMinAge: 30,
   *     requireMinConfidence: 0.7,
   *   });
   *
   *   if (!result.allowed) {
   *     return res.status(403).json({ error: result.reason });
   *   }
   */
  async gate(provenanceId, {
    requireDeclared = false,
    requireConstraints = [],
    requireCapabilities = [],
    requireClean = true,
    requireMinAge = 0,
    requireMinConfidence = 0,
    requireSignedProof = null,
    // { nonce: string, signature: string }
    // When provided, cryptographically verifies the agent controls its declared
    // private key. The agent must have signed `${provenanceId}:${nonce}`.
    onApiError, // Override instance default if provided
  } = {}) {
    const errorPolicy = onApiError || this.onApiError;
    let trust;
    try {
      trust = await this.check(provenanceId);
    } catch (e) {
      // Handle API failures based on policy
      if (errorPolicy === 'allow') {
        return { 
          allowed: true, 
          reason: 'Verification skipped (API unavailable)', 
          trust: null,
          fallback: true 
        };
      }
      if (errorPolicy === 'deny') {
        return { 
          allowed: false, 
          reason: `Verification failed (API unavailable): ${e.message}`, 
          trust: null,
          fallback: true 
        };
      }
      // errorPolicy === 'throw'
      throw e;
    }

    if (!trust.found) {
      return { allowed: false, reason: 'Agent not found in Provenance index', trust };
    }
    if (trust.status !== 'active') {
      return { allowed: false, reason: `Agent status is ${trust.status}`, trust };
    }
    if (requireDeclared && !trust.declared) {
      return { allowed: false, reason: 'Agent has not declared a PROVENANCE.yml file', trust };
    }
    if (requireClean && trust.incidents > 0) {
      return { allowed: false, reason: `Agent has ${trust.incidents} open incident(s)`, trust };
    }
    if (requireMinConfidence && trust.confidence < requireMinConfidence) {
      return { allowed: false, reason: `Agent confidence ${trust.confidence} below required ${requireMinConfidence}`, trust };
    }
    if (requireMinAge && (trust.age_days === null || trust.age_days < requireMinAge)) {
      return { allowed: false, reason: `Agent is ${trust.age_days ?? 0} days old, minimum is ${requireMinAge}`, trust };
    }
    for (const constraint of requireConstraints) {
      if (!trust.constraints.includes(constraint)) {
        return { allowed: false, reason: `Agent has not committed to constraint: ${constraint}`, trust };
      }
    }
    for (const capability of requireCapabilities) {
      if (!trust.capabilities.includes(capability)) {
        return { allowed: false, reason: `Agent does not declare capability: ${capability}`, trust };
      }
    }
    if (requireSignedProof) {
      const { nonce, signature } = requireSignedProof;
      const result = await this.verifySignature(provenanceId, nonce, signature);
      if (!result.verified) {
        return { allowed: false, reason: `Cryptographic identity verification failed: ${result.reason}`, trust };
      }
    }

    return { allowed: true, reason: null, trust };
  }

  // ── Search ────────────────────────────────────────────────────────────────

  /**
   * Search for agents by capabilities, constraints, platform etc.
   *
   * Example:
   *   const agents = await provenance.search({
   *     capabilities: ['read:web'],
   *     constraints: ['no:financial:transact'],
   *     declared: true,
   *   });
   */
  async search(params = {}) {
    const qs = new URLSearchParams();
    if (params.q) qs.set('q', params.q);
    if (params.platform) qs.set('platform', params.platform);
    if (params.capabilities?.length) qs.set('capabilities', params.capabilities.join(','));
    if (params.constraints?.length) qs.set('constraints', params.constraints.join(','));
    if (params.declared !== undefined) qs.set('declared', String(params.declared));
    if (params.minConfidence) qs.set('min_confidence', String(params.minConfidence));
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.offset) qs.set('offset', String(params.offset));

    try {
      const res = await fetch(`${this.apiUrl}/api/search?${qs}`);
      if (!res.ok) throw new Error(`Provenance API error: ${res.status}`);
      return res.json();
    } catch (e) {
      throw new Error(`Provenance.search failed: ${e.message}`);
    }
  }

  // ── Batch operations ────────────────────────────────────────────────────

  /**
   * Check multiple agents in a single request.
   * More efficient than calling check() multiple times.
   *
   * @param {string[]} provenanceIds - Array of provenance IDs (max 50)
   * @returns {object} Map of provenance_id → trust profile
   */
  async checkBatch(provenanceIds) {
    if (!Array.isArray(provenanceIds) || provenanceIds.length === 0) {
      throw new Error('provenanceIds must be a non-empty array');
    }
    if (provenanceIds.length > 50) {
      throw new Error('Maximum 50 IDs per batch request');
    }

    // Check cache first, collect uncached IDs
    const results = {};
    const uncached = [];

    for (const id of provenanceIds) {
      const cached = this.cache.get(id);
      if (cached) {
        results[id] = cached;
      } else {
        uncached.push(id);
      }
    }

    // If all cached, return immediately
    if (uncached.length === 0) {
      return results;
    }

    // Fetch uncached from API
    try {
      const res = await fetch(`${this.apiUrl}/api/agents/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: uncached }),
      });

      if (!res.ok) throw new Error(`Provenance API error: ${res.status}`);
      
      const data = await res.json();

      // Cache and merge results
      for (const id of uncached) {
        const profile = data.results?.[id] || { found: false, provenance_id: id };
        this.cache.set(id, profile);
        results[id] = profile;
      }

      return results;
    } catch (e) {
      throw new Error(`Provenance.checkBatch failed: ${e.message}`);
    }
  }

  /**
   * Gate multiple agents in a single request.
   *
   * @param {string[]} provenanceIds - Array of provenance IDs
   * @param {object} options - Same options as gate()
   * @returns {object} Map of provenance_id → gate result
   */
  async gateBatch(provenanceIds, options = {}) {
    const profiles = await this.checkBatch(provenanceIds);
    const results = {};

    for (const id of provenanceIds) {
      const trust = profiles[id];
      results[id] = this._evaluateGate(trust, options);
    }

    return results;
  }

  // Internal: evaluate gate rules against a trust profile
  _evaluateGate(trust, options) {
    const {
      requireDeclared = false,
      requireConstraints = [],
      requireCapabilities = [],
      requireClean = true,
      requireMinAge = 0,
      requireMinConfidence = 0,
    } = options;

    if (!trust || !trust.found) {
      return { allowed: false, reason: 'Agent not found in Provenance index', trust };
    }
    if (trust.status !== 'active') {
      return { allowed: false, reason: `Agent status is ${trust.status}`, trust };
    }
    if (requireDeclared && !trust.declared) {
      return { allowed: false, reason: 'Agent has not declared a PROVENANCE.yml file', trust };
    }
    for (const c of requireConstraints) {
      if (!trust.constraints?.includes(c)) {
        return { allowed: false, reason: `Agent has not committed to constraint: ${c}`, trust };
      }
    }
    for (const c of requireCapabilities) {
      if (!trust.capabilities?.includes(c)) {
        return { allowed: false, reason: `Agent does not have capability: ${c}`, trust };
      }
    }
    if (requireClean && trust.incidents > 0) {
      return { allowed: false, reason: `Agent has ${trust.incidents} open incident(s)`, trust };
    }
    if (requireMinAge > 0 && (trust.age_days || 0) < requireMinAge) {
      return { allowed: false, reason: `Agent is only ${trust.age_days || 0} days old (minimum: ${requireMinAge})`, trust };
    }
    if (requireMinConfidence > 0 && (trust.confidence || 0) < requireMinConfidence) {
      return { allowed: false, reason: `Agent confidence ${trust.confidence} below minimum ${requireMinConfidence}`, trust };
    }

    return { allowed: true, reason: null, trust };
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  _idToPath(provenanceId) {
    // provenance:github:alice/research-assistant
    // → github/alice/research-assistant
    return provenanceId.replace('provenance:', '').replace(':', '/');
  }
}

  // ── Self-registration ─────────────────────────────────────────────────────

  /**
   * Register or update this agent in the Provenance index.
   * Call once at agent startup — idempotent, safe to call on every boot.
   *
   * Example:
   *   import { provenance } from 'provenance-protocol';
   *
   *   await provenance.register({
   *     id: 'provenance:github:your-org/your-agent',
   *     url: 'https://github.com/your-org/your-agent',
   *     name: 'Your Agent',
   *     description: 'What it does',
   *     capabilities: ['read:web', 'write:summaries'],
   *     constraints: ['no:pii', 'no:financial:transact'],
   *   });
   *
   * @param {object} profile
   * @param {string} profile.id            provenance:<platform>:<owner>/<name>
   * @param {string} profile.url           Canonical URL (GitHub repo, package page, etc.)
   * @param {string} [profile.name]        Display name
   * @param {string} [profile.description] One-sentence description
   * @param {string[]} [profile.capabilities]
   * @param {string[]} [profile.constraints]
   * @param {string} [profile.model_provider]
   * @param {string} [profile.model_id]
   * @param {string} [profile.contact_url]
   * @param {string} [profile.ajp_endpoint]
   * @param {string} [profile.public_key]  Ed25519 public key: "ed25519:<base64>"
   * @param {string} [profile.version]
   * @returns {{ created: boolean, updated: boolean, agent: object }}
   */
  async register(profile = {}) {
    const { id, ...rest } = profile;
    if (!id) throw new Error('profile.id is required');

    try {
      const res = await fetch(`${this.apiUrl}/api/agents/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provenance_id: id, ...rest }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Registration failed: ${res.status}`);
      }
      return res.json();
    } catch (e) {
      throw new Error(`Provenance.register failed: ${e.message}`);
    }
  }
}

// Default instance pointing at provenance.dev
export const provenance = new Provenance();
