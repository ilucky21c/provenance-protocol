# Test vectors

Normative test data for the Provenance Protocol. An implementation that
reproduces these results interoperates with every other implementation that
does, without reference to any service.

## signatures-0.1.json

Ed25519 signature vectors for the three signed messages in the protocol:

| Message | Used for |
|---|---|
| `<provenance_id>:<public_key>` | `identity.signature` in `PROVENANCE.yml` |
| `<provenance_id>:<nonce>` | live proof that a running agent holds the key |
| `<provenance_id>:REVOKE` | owner-signed revocation |

Each vector carries the exact message, the public key, the signature, and
whether it must verify. Ed25519 is deterministic (RFC 8032), so signing the
given message with the given private key must reproduce the given signature
byte for byte.

The four negative vectors are the cases that matter in practice: a signature
from the wrong key, an altered `provenance_id`, a substituted public key
(the re-hosting attack), and a malformed signature.

The private keys in these files are test data. Never use them for anything.

## declarations-0.2.json

Whole-declaration signatures (spec 0.2): the signed payload is
`provenance-declaration-v1:` followed by the canonical JSON of the parsed
declaration without `identity.signature`.

## attestations-0.1.json

Attestations (format 0.1). Verify each vector with the issuer public key in the
file, at the vector's `now`, and compare the **status** — `valid`, `expired`,
`not_yet_valid`, `invalid` or `unchecked` — not just pass/fail. The vectors
that matter most are `attestation-forged-and-expired` (a forgery must read as
`invalid`, never as `expired`) and `attestation-window-extended` (pushing
`valid_until` out after signing must break the signature).

Also included: the `declaration_digest` of a 0.2 declaration, and a withdrawal
signature with its payload.

## Running them

Any Ed25519 implementation works. With Node:

```js
import { readFileSync } from 'node:fs';

const { vectors } = JSON.parse(readFileSync('signatures-0.1.json', 'utf8'));

for (const v of vectors) {
  const key = await crypto.subtle.importKey(
    'spki', Buffer.from(v.public_key, 'base64'), { name: 'Ed25519' }, false, ['verify']
  );
  let got;
  try {
    got = await crypto.subtle.verify(
      'Ed25519', key, Buffer.from(v.signature, 'base64'), new TextEncoder().encode(v.message)
    ) ? 'valid' : 'invalid';
  } catch { got = 'invalid'; }
  console.log(got === v.expect ? `PASS ${v.id}` : `FAIL ${v.id}`);
}
```

See [SPEC.md](../SPEC.md#signing-and-verification) for what a valid signature
does and does not prove.
