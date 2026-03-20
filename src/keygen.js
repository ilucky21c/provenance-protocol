/**
 * provenance-protocol — Key generation and signing utilities
 *
 * Agent operators use this to:
 *   1. Generate an Ed25519 keypair once (setup)
 *   2. Put the public key in PROVENANCE.yml under identity.public_key
 *   3. Keep the private key in their environment (never committed, never shared)
 *   4. Sign challenges from receiving systems at runtime
 *
 * Usage (one-time setup):
 *   import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';
 *   const { publicKey, privateKey } = generateProvenanceKeyPair();
 *   // Add publicKey to your PROVENANCE.yml:
 *   //   identity:
 *   //     public_key: "<publicKey>"
 *   // Store privateKey as an environment variable: PROVENANCE_PRIVATE_KEY=<privateKey>
 *
 * Usage (runtime — signing challenges):
 *   import { signChallenge } from 'provenance-protocol/keygen';
 *   const signature = signChallenge(process.env.PROVENANCE_PRIVATE_KEY, provenanceId, nonce);
 *   // Return signature to the receiving system
 *
 * Note: This module uses Node.js built-in crypto. It is Node-only (not browser).
 * The verification side (in index.js) uses Web Crypto and works everywhere.
 */

import { generateKeyPairSync, sign, createPrivateKey } from 'crypto';

/**
 * Generate a new Ed25519 keypair for use with Provenance identity.
 *
 * Run this once during agent setup. Add the public key to PROVENANCE.yml.
 * Store the private key securely as an environment variable.
 *
 * @returns {{ publicKey: string, privateKey: string }}
 *   publicKey  — base64-encoded SPKI DER. Goes in PROVENANCE.yml identity.public_key
 *   privateKey — base64-encoded PKCS8 DER. Store as PROVENANCE_PRIVATE_KEY env var
 *
 * Example:
 *   const { publicKey, privateKey } = generateProvenanceKeyPair();
 *   console.log('Add to PROVENANCE.yml:');
 *   console.log('identity:');
 *   console.log(`  public_key: "${publicKey}"`);
 *   console.log('\nStore as environment variable:');
 *   console.log(`PROVENANCE_PRIVATE_KEY=${privateKey}`);
 */
export function generateProvenanceKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  return {
    publicKey: Buffer.from(publicKey).toString('base64'),
    privateKey: Buffer.from(privateKey).toString('base64'),
  };
}

/**
 * Sign a challenge from a receiving system.
 *
 * Call this when a receiving system sends you a nonce to prove your identity.
 * The signed message is always `${provenanceId}:${nonce}` — this binds the
 * signature to your specific identity and prevents replay attacks.
 *
 * @param {string} privateKeyBase64  Your PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER)
 * @param {string} provenanceId     Your provenance ID, e.g. "provenance:github:alice/agent"
 * @param {string} nonce            The nonce sent by the receiving system
 * @returns {string}                Base64-encoded signature to return to the receiver
 *
 * Example:
 *   app.post('/prove-identity', (req, res) => {
 *     const { provenanceId, nonce } = req.body;
 *     const signature = signChallenge(
 *       process.env.PROVENANCE_PRIVATE_KEY,
 *       provenanceId,
 *       nonce
 *     );
 *     res.json({ signature });
 *   });
 */
export function signChallenge(privateKeyBase64, provenanceId, nonce) {
  const keyBuffer = Buffer.from(privateKeyBase64, 'base64');
  const privateKey = createPrivateKey({ key: keyBuffer, format: 'der', type: 'pkcs8' });
  const message = Buffer.from(`${provenanceId}:${nonce}`, 'utf8');
  return sign(null, message, privateKey).toString('base64');
}
