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

/**
 * Sign your PROVENANCE.yml identity claim.
 *
 * Call this once after generating your keypair to produce the `identity.signature`
 * value that goes into PROVENANCE.yml. The signature proves you control the private
 * key that matches the public key in the file.
 *
 * The signed message is `${provenanceId}:${publicKeyBase64}` — this binds the key
 * pair to your specific Provenance ID, preventing key reuse across identities.
 *
 * @param {string} privateKeyBase64  Your PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER)
 * @param {string} provenanceId     Your agent's Provenance ID, e.g. "provenance:github:alice/agent"
 * @param {string} publicKeyBase64  The public key you're registering (base64 SPKI DER)
 * @returns {string}                Base64-encoded signature — put this in identity.signature
 *
 * Example (one-time setup):
 *   import { generateProvenanceKeyPair, signForProvenance } from 'provenance-protocol/keygen';
 *   const { publicKey, privateKey } = generateProvenanceKeyPair();
 *   const id = 'provenance:github:your-org/your-agent';
 *   const signature = signForProvenance(privateKey, id, publicKey);
 *   console.log('Add to PROVENANCE.yml:');
 *   console.log('identity:');
 *   console.log(`  public_key: "${publicKey}"`);
 *   console.log(`  signature: "${signature}"`);
 */
/**
 * Sign a revocation request.
 *
 * Call this when you want to revoke your agent's cryptographic identity —
 * e.g. if your private key was compromised or you're rotating keys.
 *
 * @param {string} privateKeyBase64  Your current PROVENANCE_PRIVATE_KEY
 * @param {string} provenanceId     Your agent's Provenance ID
 * @returns {string}                Base64 signature — send as signed_challenge to POST /api/agents/revoke
 *
 * Example:
 *   import { signRevocation } from 'provenance-protocol/keygen';
 *   const signed_challenge = signRevocation(process.env.PROVENANCE_PRIVATE_KEY, provenanceId);
 *   await fetch('https://getprovenance.dev/api/agents/revoke', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ provenance_id: provenanceId, signed_challenge }),
 *   });
 */
export function signRevocation(privateKeyBase64, provenanceId) {
  return signChallenge(privateKeyBase64, provenanceId, 'REVOKE');
}

export function signForProvenance(privateKeyBase64, provenanceId, publicKeyBase64) {
  const keyBuffer = Buffer.from(privateKeyBase64, 'base64');
  const privateKey = createPrivateKey({ key: keyBuffer, format: 'der', type: 'pkcs8' });
  const message = Buffer.from(`${provenanceId}:${publicKeyBase64}`, 'utf8');
  return sign(null, message, privateKey).toString('base64');
}
