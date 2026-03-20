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
