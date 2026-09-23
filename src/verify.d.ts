/**
 * provenance-protocol — offline verification (TypeScript definitions)
 *
 * Verifies a PROVENANCE.yml declaration without contacting any service.
 * Works anywhere the Web Crypto API exists: modern browsers, Node 18+.
 */

/** Whether a declaration was served from the location its provenance_id names. */
export type LocationCheck = 'match' | 'mismatch' | 'unchecked';

/** What a signature was found to cover, per the declaration's spec version. */
export type SignatureCoverage = 'declaration' | 'identity';

export interface VerificationResult {
  /** An identity.signature was present to check. */
  signed: boolean;
  /** The signature verified against identity.public_key. */
  valid: boolean;
  /** Why the result is not a clean pass, or null when it is. */
  reason: string | null;
  provenanceId: string | null;
  publicKey: string | null;
  /** SHA-256 of the public key, hex. Store it to detect key rotation. */
  fingerprint: string | null;
  location: LocationCheck;
  /**
   * 'declaration' (spec 0.2) — every field is covered; any edit breaks it.
   * 'identity' (spec 0.1) — only the identity and key are covered, so the
   * declared capabilities and constraints are NOT protected by the signature.
   * null when no signature was checked.
   */
  coverage: SignatureCoverage | null;
  /**
   * Signature valid AND retrieval location confirmed. Only both together
   * justify treating the declaration as the named project owner's.
   */
  trustworthy: boolean;
}

export interface VerifyOptions {
  /** URL the declaration was fetched from, for the location check. */
  retrievedFrom?: string;
}

/**
 * Verify a parsed PROVENANCE.yml declaration offline.
 *
 * Declarations are YAML — parse with your own library and pass the object;
 * this module is dependency-free by design.
 *
 * A valid signature proves the declaration came from the holder of that
 * private key and is unaltered. It does not prove who that holder is, that
 * the declared capabilities are accurate, or that the declaration is current.
 * Revocation and standing cannot be checked offline.
 */
export function verifyDeclaration(
  declaration: unknown,
  options?: VerifyOptions
): Promise<VerificationResult>;

/** SHA-256 of the raw public key bytes, hex encoded. Use it to detect key rotation. */
export function keyFingerprint(publicKeyBase64: string): Promise<string>;

/** Split a provenance id into its platform and path, or null if malformed. */
export function parseProvenanceId(
  provenanceId: string
): { platform: string; path: string } | null;

/**
 * Does a retrieval location agree with the declaration's own provenance_id?
 * Returns 'unchecked' when the location cannot be interpreted, so an unknown
 * host is never reported as agreement.
 */
export function checkLocation(provenanceId: string, retrievedFrom: string): LocationCheck;

/**
 * Verify a live challenge response against a key you already hold.
 * The nonce must be single-use and unpredictable.
 */
export function verifyChallenge(
  publicKeyBase64: string,
  provenanceId: string,
  nonce: string,
  signatureBase64: string
): Promise<boolean>;

/**
 * Verify an owner-signed revocation. Confirms it came from the key holder;
 * it does not tell you whether a revocation exists.
 */
export function verifyRevocation(
  publicKeyBase64: string,
  provenanceId: string,
  signatureBase64: string
): Promise<boolean>;

/**
 * Verify a live challenge response — domain-separated form. Prefer this over
 * `verifyChallenge`, whose payload is indistinguishable from a revocation.
 */
export function verifyAgentChallenge(
  publicKeyBase64: string, provenanceId: string, nonce: string, signatureBase64: string
): Promise<boolean>;

/** Verify a revocation — domain-separated form. */
export function verifyAgentRevocation(
  publicKeyBase64: string, provenanceId: string, signatureBase64: string
): Promise<boolean>;
