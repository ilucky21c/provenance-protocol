/**
 * provenance-protocol — the Provenance Protocol, offline (TypeScript definitions)
 *
 * No network service, no account, no API key. Signing is in
 * 'provenance-protocol/keygen'; an index client is in
 * 'provenance-protocol/index-client'.
 */

export * from './verify.js';

/** The exact string a spec-0.2 declaration signature covers. */
export function declarationSigningPayload(declaration: object): string;

/** The exact string an attestation signature covers. */
export function attestationSigningPayload(attestation: object): string;

/** Canonical JSON: keys sorted at every depth, no insignificant whitespace. */
export function canonicalJson(value: unknown): string;

export class CanonicalError extends Error {}
