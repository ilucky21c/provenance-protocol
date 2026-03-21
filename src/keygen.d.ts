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
