/**
 * provenance-protocol — Key generation and signing utilities (TypeScript definitions)
 * Node.js only. Not for browser use.
 */

export interface KeyPair {
  /** Base64-encoded SPKI DER public key. Put this in PROVENANCE.yml identity.public_key */
  publicKey: string;
  /** Base64-encoded PKCS8 DER private key. Store as PROVENANCE_PRIVATE_KEY env var. Never commit. */
  privateKey: string;
}

/**
 * Generate a new Ed25519 keypair for Provenance identity.
 * Run once during agent setup.
 */
export function generateProvenanceKeyPair(): KeyPair;

/**
 * Sign a challenge nonce from a receiving system.
 * Returns a base64-encoded signature over `${provenanceId}:${nonce}`.
 *
 * @param privateKeyBase64  Your PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER)
 * @param provenanceId      Your agent's Provenance ID
 * @param nonce             The nonce sent by the receiving system
 */
export function signChallenge(privateKeyBase64: string, provenanceId: string, nonce: string): string;

/**
 * Sign your PROVENANCE.yml identity claim.
 *
 * Produces the `identity.signature` value for PROVENANCE.yml.
 * Signs `${provenanceId}:${publicKeyBase64}` — binding the keypair to your specific agent ID.
 * Run once during setup, after generateProvenanceKeyPair().
 *
 * @param privateKeyBase64  Your PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER)
 * @param provenanceId      Your agent's Provenance ID
 * @param publicKeyBase64   The public key you generated (base64 SPKI DER)
 * @returns                 Base64 signature — put in PROVENANCE.yml identity.signature
 */
export function signForProvenance(privateKeyBase64: string, provenanceId: string, publicKeyBase64: string): string;

/**
 * Sign a revocation request — clears your agent's public key and identity_verified status.
 * Use when your private key is compromised or you're rotating keys.
 * Send the result as signed_challenge to POST /api/agents/revoke.
 */
export function signRevocation(privateKeyBase64: string, provenanceId: string): string;

/**
 * Sign a whole declaration — spec 0.2.
 *
 * Covers every field, so deleting a constraint or adding a capability breaks the
 * signature. `signForProvenance` (spec 0.1) covers only the identity and key.
 *
 * Signs the canonical form of the PARSED declaration, so reformatting the file
 * does not invalidate the signature.
 *
 * @param privateKeyBase64  Your PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER)
 * @param declaration       Parsed declaration; identity.signature is ignored
 * @returns Base64 signature — put it in identity.signature
 */
export function signDeclaration(privateKeyBase64: string, declaration: object): string;

/**
 * Prove live control of a key against a nonce — domain-separated form.
 *
 * Use this for any endpoint a stranger can call. The legacy `signChallenge`
 * signs the same payload shape as a revocation, so exposing that publicly lets
 * a caller obtain a valid revocation signature for your own key.
 */
export function signAgentChallenge(privateKeyBase64: string, provenanceId: string, nonce: string): string;

/** Revoke a provenance id — domain-separated form. Takes no caller-supplied input. */
export function signAgentRevocation(privateKeyBase64: string, provenanceId: string): string;
