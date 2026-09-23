/**
 * provenance-protocol — canonical form for signing declarations
 *
 * Spec 0.1 signed only "<provenance_id>:<public_key>", so a signature proved
 * key control but left the rest of the declaration unprotected: a constraint
 * could be deleted and the signature would still verify. Spec 0.2 signs the
 * whole declaration, which needs one canonical serialisation that every
 * implementation agrees on byte for byte.
 *
 * Canonicalisation applies to the PARSED value, not the file's bytes. Comments,
 * indentation, quoting style and key order therefore do not affect the
 * signature — a declaration can be reformatted without re-signing, which is
 * what anyone would expect.
 *
 * Rules:
 *   - object keys sorted by Unicode code point, recursively
 *   - no insignificant whitespace
 *   - `identity.signature` removed before signing (it cannot cover itself)
 *   - only JSON-representable values; anything else throws rather than being
 *     silently coerced into an ambiguous signature
 */

/** Thrown when a declaration contains something that cannot be canonicalised. */
export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanonicalError';
  }
}

const DOMAIN = 'provenance-declaration-v1';

/**
 * Every distinct thing an agent key signs gets its own prefix, so a signature
 * obtained for one purpose can never be presented as another.
 *
 * This is not theoretical. Spec 0.1 signed a challenge as "<id>:<nonce>" and a
 * revocation as "<id>:REVOKE" — the same payload with a chosen nonce. Any
 * publicly reachable endpoint that signs a caller-supplied nonce therefore
 * hands out valid revocation signatures for its own key, letting a stranger
 * revoke the agent. A key lifted into the nonce likewise reproduces the 0.1
 * declaration payload.
 *
 * The separated forms below cannot be confused with each other whatever the
 * caller supplies.
 */
export const CHALLENGE_DOMAIN = 'provenance-challenge-v1';
export const REVOCATION_DOMAIN = 'provenance-revocation-v1';

/** Payload for proving live control of a key. Nonce must be single-use. */
export function challengePayload(provenanceId, nonce) {
  if (typeof provenanceId !== 'string' || provenanceId.length === 0) {
    throw new CanonicalError('provenanceId is required');
  }
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new CanonicalError('nonce is required');
  }
  return `${CHALLENGE_DOMAIN}:${provenanceId}:${nonce}`;
}

/** Payload for revoking a provenance id. Carries no caller-supplied input. */
export function revocationPayload(provenanceId) {
  if (typeof provenanceId !== 'string' || provenanceId.length === 0) {
    throw new CanonicalError('provenanceId is required');
  }
  return `${REVOCATION_DOMAIN}:${provenanceId}`;
}

function canonicalValue(value, path = '$') {
  if (value === null) return 'null';

  const type = typeof value;

  if (type === 'string') return JSON.stringify(value);
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalError(`${path}: non-finite numbers cannot be signed`);
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item, i) => canonicalValue(item, `${path}[${i}]`)).join(',')}]`;
  }

  if (type === 'object') {
    // A YAML parser may produce Dates, Maps, Buffers and so on. Signing those
    // would depend on whichever serialisation happened to be used, so refuse.
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new CanonicalError(
        `${path}: only plain objects can be signed (got ${value.constructor?.name ?? 'unknown type'}) — quote the value as a string`
      );
    }
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    const parts = keys.map(
      (k) => `${JSON.stringify(k)}:${canonicalValue(value[k], `${path}.${k}`)}`
    );
    return `{${parts.join(',')}}`;
  }

  throw new CanonicalError(`${path}: values of type ${type} cannot be signed`);
}

/**
 * The exact string a spec-0.2 declaration signature is computed over.
 *
 * Domain-separated so a declaration signature can never be replayed as a
 * signature over some other kind of message.
 *
 * @param {object} declaration  Parsed declaration (its identity.signature is ignored)
 * @returns {string}
 */
export function declarationSigningPayload(declaration) {
  if (declaration === null || typeof declaration !== 'object' || Array.isArray(declaration)) {
    throw new CanonicalError('Declaration must be a parsed object');
  }

  const { identity, ...rest } = declaration;
  const covered = { ...rest };

  if (identity !== undefined) {
    if (identity === null || typeof identity !== 'object' || Array.isArray(identity)) {
      throw new CanonicalError('$.identity must be an object when present');
    }
    // public_key and algorithm ARE covered; only the signature is excluded.
    const { signature: _excluded, ...identityRest } = identity;
    covered.identity = identityRest;
  }

  return `${DOMAIN}:${canonicalValue(covered)}`;
}

export { DOMAIN as DECLARATION_SIGNING_DOMAIN };
