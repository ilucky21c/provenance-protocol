/**
 * provenance-protocol — the Provenance Protocol, offline (TypeScript definitions)
 *
 * No network service, no account, no API key. Signing is in
 * 'provenance-protocol/keygen'; an index client is in
 * 'provenance-protocol/index-client'.
 */

export * from './verify.js';

export interface DeclarationChange {
  /** Dotted path, e.g. 'constraints' or 'data.retention'. */
  field: string;
  change: 'added' | 'removed' | 'modified';
  value?: unknown;
  from?: unknown;
  to?: unknown;
  /** For someone relying on the agent. */
  direction: 'weakened' | 'strengthened' | 'neutral';
  /** A weakening that `changes.pending` listed in advance. */
  announced: boolean;
}

/** Every difference between two parsed declarations, classified. Offline, deterministic. */
export function compareDeclarations(before: object, after: object): DeclarationChange[];

/** Approximate length of an ISO 8601 duration in days ('none' is 0), or null. */
export function durationDays(value: string): number | null;

/** The exact string a notice signature covers. */
export function noticeSigningPayload(notice: object): string;

/** The exact string a spec-0.2 declaration signature covers. */
export function declarationSigningPayload(declaration: object): string;

/** The exact string an attestation signature covers. */
export function attestationSigningPayload(attestation: object): string;

/** Canonical JSON: keys sorted at every depth, no insignificant whitespace. */
export function canonicalJson(value: unknown): string;

export class CanonicalError extends Error {}
