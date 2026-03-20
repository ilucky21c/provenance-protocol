/**
 * provenance-protocol TypeScript definitions
 */

export interface TrustProfile {
  found: boolean;
  provenance_id: string;
  platform?: string;
  name?: string;
  declared?: boolean;
  confidence?: number;
  age_days?: number | null;
  capabilities?: string[];
  constraints?: string[];
  incidents?: number;
  model?: {
    provider: string;
    model_id: string;
  } | null;
  status?: string;
  first_seen?: string | null;
  url?: string;
  /** Base64-encoded Ed25519 SPKI public key, if the agent registered one. */
  public_key?: string | null;
}

export interface GateResult {
  allowed: boolean;
  reason: string | null;
  trust: TrustProfile | null;
  fallback?: boolean;
}

export interface SignedProof {
  /** The nonce you sent to the agent. */
  nonce: string;
  /** The base64 signature the agent returned. */
  signature: string;
}

export interface VerifyResult {
  verified: boolean;
  reason: string | null;
}

export interface GateOptions {
  requireDeclared?: boolean;
  requireConstraints?: string[];
  requireCapabilities?: string[];
  requireClean?: boolean;
  requireMinAge?: number;
  requireMinConfidence?: number;
  /**
   * Cryptographically verify the agent controls its declared private key.
   * The agent must have signed `${provenanceId}:${nonce}` with its private key.
   */
  requireSignedProof?: SignedProof;
  onApiError?: 'throw' | 'allow' | 'deny';
}

export interface SearchParams {
  q?: string;
  platform?: string;
  capabilities?: string[];
  constraints?: string[];
  declared?: boolean;
  minConfidence?: number;
  limit?: number;
  offset?: number;
}

export interface SearchResult {
  agents: TrustProfile[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProvenanceOptions {
  apiUrl?: string;
  cacheTTL?: number;
  onApiError?: 'throw' | 'allow' | 'deny';
}

export class Provenance {
  constructor(options?: ProvenanceOptions);

  /**
   * Check an agent's trust profile.
   * Results are cached for the configured TTL (default 5 minutes).
   */
  check(provenanceId: string): Promise<TrustProfile>;

  /**
   * Returns true if the agent has publicly committed to a constraint.
   */
  hasConstraint(provenanceId: string, constraint: string): Promise<boolean>;

  /**
   * Returns true if the agent has declared a capability.
   */
  hasCapability(provenanceId: string, capability: string): Promise<boolean>;

  /**
   * Returns true if the agent has no open incidents.
   */
  isClean(provenanceId: string): Promise<boolean>;

  /**
   * Returns true if the agent has existed for at least minDays.
   */
  isOldEnough(provenanceId: string, minDays: number): Promise<boolean>;

  /**
   * Run all your trust requirements in one call.
   * Supports fail-safe behavior via onApiError option.
   * Pass requireSignedProof to also verify cryptographic identity.
   */
  gate(provenanceId: string, options?: GateOptions): Promise<GateResult>;

  /**
   * Verify that a running agent cryptographically owns the identity it claims.
   *
   * Protocol: send the agent a nonce, ask it to sign `${provenanceId}:${nonce}`,
   * then call this to verify the returned signature against the public key in the index.
   *
   * @param provenanceId  The agent's Provenance ID
   * @param nonce         The nonce you sent to the agent
   * @param signature     The base64 signature the agent returned
   */
  verifySignature(provenanceId: string, nonce: string, signature: string): Promise<VerifyResult>;

  /**
   * Search for agents by capabilities, constraints, platform etc.
   */
  search(params?: SearchParams): Promise<SearchResult>;

  /**
   * Check multiple agents in a single request (max 50).
   * More efficient than calling check() multiple times.
   */
  checkBatch(provenanceIds: string[]): Promise<Record<string, TrustProfile>>;

  /**
   * Gate multiple agents in a single request.
   */
  gateBatch(provenanceIds: string[], options?: GateOptions): Promise<Record<string, GateResult>>;
}

/**
 * Default instance pointing at provenance.dev
 */
export const provenance: Provenance;
