/**
 * provenance-protocol — offline verification
 *
 * Verifies a PROVENANCE.yml declaration without contacting any service.
 * No network, no account, no API key. See SPEC.md § Signing and Verification.
 *
 *   import { verifyDeclaration } from 'provenance-protocol/verify';
 *
 *   const result = await verifyDeclaration(parsedYaml, {
 *     retrievedFrom: 'https://github.com/alice/research-assistant',
 *   });
 *
 * Declarations are YAML. Parse them with whatever library you already use and
 * pass the resulting object — this module stays dependency-free on purpose.
 *
 * Uses the Web Crypto API (crypto.subtle): all modern browsers, Node 18+.
 */

import { declarationSigningPayload, challengePayload, revocationPayload } from './canonical.js';

/** Signature algorithm. Ed25519 in every spec version so far. */
const ALGORITHM = 'ed25519';

/**
 * Which spec versions this module knows how to verify a signature for, and what
 * the signature covers in each.
 *
 *   0.1 — signs "<provenance_id>:<public_key>". Proves key control under that
 *         identity. Does NOT cover the rest of the declaration: a constraint can
 *         be deleted and the signature still verifies.
 *   0.2 — signs the canonical form of the whole declaration. Any change to any
 *         field breaks it.
 */
const SIGNATURE_COVERAGE = { '0.1': 'identity', '0.2': 'declaration' };

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('Web Crypto API (crypto.subtle) not available');
  return s;
}

function fromBase64(value) {
  if (typeof value !== 'string' || value.length === 0) throw new Error('not base64');
  // atob is available in browsers and Node 18+; avoids depending on Buffer.
  const binary = atob(value.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyEd25519(publicKeyBase64, signatureBase64, message) {
  const key = await subtle().importKey(
    'spki',
    fromBase64(publicKeyBase64),
    { name: 'Ed25519' },
    false,
    ['verify']
  );
  return subtle().verify(
    'Ed25519',
    key,
    fromBase64(signatureBase64),
    new TextEncoder().encode(message)
  );
}

/**
 * SHA-256 of the raw public key bytes, hex encoded.
 *
 * Use it to detect key rotation: store the fingerprint you saw for a
 * provenance_id, and treat a different one later as a material change rather
 * than a silent update. See SPEC.md § Signing and Verification (Continuity).
 *
 * @param {string} publicKeyBase64  Base64 SPKI DER Ed25519 public key
 * @returns {Promise<string>}
 */
export async function keyFingerprint(publicKeyBase64) {
  const digest = await subtle().digest('SHA-256', fromBase64(publicKeyBase64));
  return toHex(new Uint8Array(digest));
}

/**
 * Where a declaration claims to live, parsed out of its provenance_id.
 *
 * @param {string} provenanceId  e.g. 'provenance:github:alice/agent'
 * @returns {{ platform: string, path: string } | null}
 */
export function parseProvenanceId(provenanceId) {
  if (typeof provenanceId !== 'string') return null;
  const match = /^provenance:([a-z0-9-]+):(.+)$/i.exec(provenanceId.trim());
  if (!match) return null;
  return { platform: match[1].toLowerCase(), path: match[2] };
}

const HOST_PLATFORMS = [
  [/(^|\.)github\.com$/i, 'github'],
  [/(^|\.)githubusercontent\.com$/i, 'github'],
  [/(^|\.)huggingface\.co$/i, 'huggingface'],
  [/(^|\.)npmjs\.com$/i, 'npm'],
  [/(^|\.)registry\.npmjs\.org$/i, 'npm'],
  [/(^|\.)pypi\.org$/i, 'pypi'],
];

/**
 * Does a retrieval location agree with the declaration's own provenance_id?
 *
 * A declaration served from somewhere other than the location it names was
 * placed there by someone who may have no control over the named project —
 * the re-hosting case. A conformant verifier treats that as unverified
 * however good the signature is.
 *
 * Returns 'unchecked' when the location cannot be interpreted, so an unknown
 * host is never reported as agreement.
 *
 * @param {string} provenanceId
 * @param {string} retrievedFrom  URL the declaration was fetched from
 * @returns {'match' | 'mismatch' | 'unchecked'}
 */
export function checkLocation(provenanceId, retrievedFrom) {
  const id = parseProvenanceId(provenanceId);
  if (!id || typeof retrievedFrom !== 'string') return 'unchecked';

  let url;
  try {
    url = new URL(retrievedFrom);
  } catch {
    return 'unchecked';
  }

  // provenance:domain:<hostname>[/<path>] — for an agent that runs as a service
  // and has no public repository. Control is proven the same way as with a
  // repo: whoever put the file there had write access to the location. Most
  // commercial agents are this shape, so without it they could never be
  // verified as their operator's.
  if (id.platform === 'domain') {
    const [declaredHost, ...declaredPath] = id.path.split('/').filter(Boolean);
    if (!declaredHost) return 'unchecked';
    // Exact host match. A subdomain is a different party as far as this is
    // concerned, and treating it as the same would be the whole attack.
    if (url.hostname.toLowerCase() !== declaredHost.toLowerCase()) return 'mismatch';
    if (declaredPath.length === 0) return 'match';
    const segs = url.pathname.split('/').filter(Boolean).map((x) => x.toLowerCase());
    const want = declaredPath.map((x) => x.toLowerCase());
    for (let i = 0; i + want.length <= segs.length; i++) {
      if (want.every((part, j) => segs[i + j] === part)) return 'match';
    }
    return 'mismatch';
  }

  const platform = HOST_PLATFORMS.find(([host]) => host.test(url.hostname))?.[1];
  if (!platform) return 'unchecked';
  if (platform !== id.platform) return 'mismatch';

  // github/huggingface ids are owner/repo; npm and pypi are package names.
  const segments = url.pathname.split('/').filter(Boolean);
  const expected = id.path.toLowerCase().split('/').filter(Boolean);
  if (expected.length === 0) return 'unchecked';

  // The declared path must appear as consecutive segments of the URL path.
  // Covers both https://github.com/owner/repo and raw/blob URLs beneath it.
  const haystack = segments.map((s) => s.toLowerCase());
  for (let i = 0; i + expected.length <= haystack.length; i++) {
    if (expected.every((part, j) => haystack[i + j] === part)) return 'match';
  }
  return 'mismatch';
}

/**
 * Verify a parsed PROVENANCE.yml declaration offline.
 *
 * Checks the identity signature against the public key inside the file, and —
 * when `retrievedFrom` is given — whether the file was served from the
 * location it claims.
 *
 * What a valid signature proves depends on the spec version, and `coverage`
 * reports which: 'declaration' (0.2) means every field is covered, so any edit
 * breaks it; 'identity' (0.1) means only the identity and key are covered, so
 * the declared capabilities and constraints are NOT protected by it.
 *
 * In neither case does a signature prove who the key holder is, that the
 * declared capabilities are accurate, or that the declaration is current.
 * Revocation and standing cannot be checked offline.
 *
 * @param {object} declaration  Parsed PROVENANCE.yml
 * @param {object} [options]
 * @param {string} [options.retrievedFrom]  URL the declaration was fetched from
 * @returns {Promise<{
 *   signed: boolean,
 *   valid: boolean,
 *   reason: string | null,
 *   provenanceId: string | null,
 *   publicKey: string | null,
 *   fingerprint: string | null,
 *   location: 'match' | 'mismatch' | 'unchecked',
 *   coverage: 'declaration' | 'identity' | null,
 *   trustworthy: boolean
 * }>}
 */
export async function verifyDeclaration(declaration, options = {}) {
  const base = {
    signed: false,
    valid: false,
    reason: null,
    provenanceId: null,
    publicKey: null,
    fingerprint: null,
    location: 'unchecked',
    coverage: null,
    trustworthy: false,
  };

  if (declaration === null || typeof declaration !== 'object') {
    return { ...base, reason: 'Declaration must be a parsed object' };
  }

  const provenanceId =
    typeof declaration.provenance_id === 'string' ? declaration.provenance_id : null;
  const identity =
    declaration.identity !== null && typeof declaration.identity === 'object'
      ? declaration.identity
      : null;
  const publicKey = typeof identity?.public_key === 'string' ? identity.public_key : null;
  const signature = typeof identity?.signature === 'string' ? identity.signature : null;

  const location = options.retrievedFrom
    ? checkLocation(provenanceId, options.retrievedFrom)
    : 'unchecked';

  const result = { ...base, provenanceId, publicKey, location };

  if (!identity) return { ...result, reason: 'No identity block' };
  if (!publicKey) return { ...result, reason: 'identity.public_key is missing' };

  const algorithm = identity.algorithm ?? ALGORITHM;
  if (String(algorithm).toLowerCase() !== ALGORITHM) {
    return { ...result, reason: `Unsupported algorithm: ${algorithm}` };
  }

  try {
    result.fingerprint = await keyFingerprint(publicKey);
  } catch {
    return { ...result, reason: 'identity.public_key is not a valid Ed25519 key' };
  }

  // A key with no signature advertises which key to challenge later. It says
  // nothing about whether this file has been altered.
  if (!signature) {
    return { ...result, reason: 'identity.signature is absent — key advertised, file not attested' };
  }
  result.signed = true;

  const declaredVersion = typeof declaration.provenance === 'string' ? declaration.provenance : '0.1';
  if (!provenanceId && declaredVersion === '0.1') {
    // The 0.1 payload is built from provenance_id, so without it there is
    // nothing to verify. A 0.2 signature covers the whole declaration and does
    // not need it (though the location check still does).
    return { ...result, reason: 'provenance_id is required to verify a 0.1 signature' };
  }

  // What the signature covers depends on the spec version the declaration
  // declares, so the payload is built differently for each.
  const specVersion = typeof declaration.provenance === 'string' ? declaration.provenance : '0.1';
  const coverage = SIGNATURE_COVERAGE[specVersion];
  if (!coverage) {
    return {
      ...result,
      reason: `Spec version ${specVersion} is not known to this verifier — cannot check its signature`,
    };
  }
  result.coverage = coverage;

  let payload;
  try {
    payload =
      coverage === 'declaration'
        ? declarationSigningPayload(declaration)
        : `${provenanceId}:${publicKey}`;
  } catch (e) {
    return { ...result, reason: `Declaration cannot be canonicalised: ${e.message}` };
  }

  let valid;
  try {
    valid = await verifyEd25519(publicKey, signature, payload);
  } catch {
    return { ...result, reason: 'identity.signature is malformed' };
  }

  if (!valid) return { ...result, reason: 'Signature does not verify' };

  return {
    ...result,
    valid: true,
    // Signature proves integrity; location binds it to a project someone
    // controls. Only both together justify treating the file as the owner's.
    trustworthy: location === 'match',
    reason: location === 'match' ? null : 'Signature valid, but retrieval location was not confirmed',
  };
}

/**
 * Verify a live challenge response — domain-separated form.
 *
 * Pair with `signAgentChallenge`. Prefer this over `verifyChallenge`: the legacy
 * payload is the same shape as a revocation, so any public endpoint signing it
 * is a way to revoke the agent's own key.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} nonce            Single-use, unpredictable
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyAgentChallenge(publicKeyBase64, provenanceId, nonce, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, challengePayload(provenanceId, nonce));
  } catch {
    return false;
  }
}

/**
 * Verify a revocation — domain-separated form.
 *
 * Confirms it came from the key holder. It does not tell you whether a
 * revocation exists; that requires asking an index.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyAgentRevocation(publicKeyBase64, provenanceId, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, revocationPayload(provenanceId));
  } catch {
    return false;
  }
}

/**
 * Verify a live challenge response offline, against a key you already hold.
 *
 * LEGACY (spec 0.1 payload). Accepts "<provenanceId>:<nonce>", which is the same
 * shape as a revocation with nonce "REVOKE" — so never verify against a peer
 * that exposes this form publicly. Use `verifyAgentChallenge`.
 *
 * The network equivalent in the main SDK looks the key up in the index; this
 * takes the key directly, so a system that already stores keys can verify
 * without contacting anyone.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} nonce            Single-use, unpredictable
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyChallenge(publicKeyBase64, provenanceId, nonce, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, `${provenanceId}:${nonce}`);
  } catch {
    return false;
  }
}

/**
 * Verify an owner-signed revocation offline.
 *
 * Confirms the revocation came from the key holder. It does not tell you
 * whether a revocation exists — that requires asking an index.
 *
 * @param {string} publicKeyBase64
 * @param {string} provenanceId
 * @param {string} signatureBase64
 * @returns {Promise<boolean>}
 */
export async function verifyRevocation(publicKeyBase64, provenanceId, signatureBase64) {
  try {
    return await verifyEd25519(publicKeyBase64, signatureBase64, `${provenanceId}:REVOKE`);
  } catch {
    return false;
  }
}
