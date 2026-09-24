/**
 * provenance-protocol — the Provenance Protocol, offline
 *
 * Everything here works with no network service, no account and no API key:
 * verify a declaration, decide whether to accept an agent on the strength of
 * it, find where an agent's declaration lives, and verify attestations that
 * third parties have issued about it.
 *
 *   import { checkDeclaration } from 'provenance-protocol';
 *
 *   const { allowed, reason } = await checkDeclaration(declaration, {
 *     retrievedFrom: url,
 *     requireConstraints: ['no:financial:transact'],
 *   });
 *
 * Signing is Node-only and lives in 'provenance-protocol/keygen'. A client for
 * an index service — an application of the standard, not part of it — lives in
 * 'provenance-protocol/index-client' and must be pointed at an index you choose.
 */

export * from './verify.js';
export {
  declarationSigningPayload,
  attestationSigningPayload,
  canonicalJson,
  CanonicalError,
} from './canonical.js';
