# Provenance Protocol Specification
**Versions 0.1 and 0.2**

---

## What is PROVENANCE.yml?

`PROVENANCE.yml` is a single file that lives in the root of any AI agent's
repository. It tells the world — in a structured, machine-readable,
human-readable way — what this agent is, what it can do, what it will
never do, and who is responsible for it.

Think of it as the agent's public identity card.
Voluntary. Simple. Five minutes to add. Zero friction.

The filename is unambiguous by design. No existing project will already
have a file called `PROVENANCE.yml` for any other purpose. When you see
this file in a repository you know exactly what it is and why it exists.

---

## Why does this exist?

The agent internet is growing faster than the infrastructure to understand it.
Thousands of agents exist publicly — on GitHub, HuggingFace, npm, PyPI,
ClawMarket — but there is no standard way to answer basic questions:

- What does this agent actually do?
- What can it access? What will it never touch?
- Who built it and how do I reach them if something goes wrong?
- What model powers it, and has that changed recently?
- Has this agent's behavior been consistent over time?

`PROVENANCE.yml` makes these questions answerable — automatically, at scale,
without anyone needing to manually curate anything.

It is the `robots.txt` of the agent internet. A simple convention that
benefits everyone: developers get discoverability, receiving systems get
trust signals, the ecosystem gets a shared foundation.

---

## The File

Place a file named exactly `PROVENANCE.yml` in the root of your repository.

### Minimal valid PROVENANCE.yml

```yaml
provenance: "0.1"
name: "Research Assistant"
description: "Searches the web and summarizes academic papers on a given topic."
```

Three lines. That is the minimum. Everything else is optional but valuable.

---

### Complete PROVENANCE.yml

```yaml
# PROVENANCE.yml
# Provenance Protocol v0.1
# https://getprovenance.dev/spec

provenance: "0.1"

# ── Identity ──────────────────────────────────────────────────────────────────

name: "Research Assistant"
version: "1.4.2"
description: >
  Searches the web, retrieves academic papers, and produces structured
  summaries with citations. Designed for researchers and analysts.

# ── Intelligence ──────────────────────────────────────────────────────────────
# When model changes, Provenance detects behavioral drift automatically

model:
  provider: "anthropic"
  model_id: "claude-sonnet-4-5"

# ── Capabilities — what this agent CAN do ─────────────────────────────────────

capabilities:
  - read:web
  - read:pdf
  - read:arxiv
  - write:summaries

# ── Constraints — what this agent will NEVER do ───────────────────────────────
# These are public commitments. Recorded permanently. Violations are detectable.

constraints:
  - no:write:external
  - no:financial:transact
  - no:pii
  - no:delegate:agents

# ── Runtime ───────────────────────────────────────────────────────────────────

runtime:
  type: "task"              # task | persistent | scheduled
  trigger: "api"            # api | webhook | schedule | event

# ── Contact ───────────────────────────────────────────────────────────────────

contact:
  name: "Alice Chen"
  url: "https://alice.dev"
  email: "agent-issues@alice.dev"

# ── Skills ────────────────────────────────────────────────────────────────────
# External skills this agent uses — Provenance tracks these as dependencies

skills:
  - id: "web-search-001"
    source: "skillsmp"
    url: "https://skillsmp.com/skills/web-search-001"

# ── Provenance ────────────────────────────────────────────────────────────────
# Links this file to your entry in the Provenance index

provenance_id: "provenance:github:alice/research-assistant"

# ── Identity — optional, makes this file tamper-evident ───────────────────────
# Signature covers "<provenance_id>:<public_key>". See Signing and Verification.

identity:
  public_key: "MCowBQYDK2VwAyEA..."
  signature: "3n8Kd0vQ..."
  algorithm: "ed25519"
```

---

## Field Reference

### Required

| Field | Type | Description |
|---|---|---|
| `provenance` | string | Spec version. Currently `"0.1"` |
| `name` | string | Human-readable name for this agent |
| `description` | string | What this agent does, in plain language |

### Recommended

| Field | Type | Description |
|---|---|---|
| `version` | string | Semantic version of the agent |
| `model.provider` | string | `anthropic` `openai` `google` `mistral` `meta` `local` `other` |
| `model.model_id` | string | Specific model e.g. `claude-sonnet-4-5` |
| `capabilities` | list | What this agent can do |
| `constraints` | list | What this agent will never do — public commitment |
| `contact.name` | string | Who is responsible for this agent |
| `contact.url` | string | Where to learn more |
| `runtime.type` | string | `task` `persistent` `scheduled` |

### Optional

| Field | Type | Description |
|---|---|---|
| `contact.email` | string | Contact for issues or abuse reports |
| `skills` | list | SkillsMP or other skills this agent depends on |
| `delegates` | list | Sub-agents this orchestrator spawns |
| `provenance_id` | string | Links to your Provenance index entry |
| `runtime.trigger` | string | `api` `webhook` `schedule` `event` |
| `identity.public_key` | string | Base64 SPKI DER Ed25519 public key |
| `identity.signature` | string | Base64 Ed25519 signature over `<provenance_id>:<public_key>`. Optional — see Signing and Verification |
| `identity.algorithm` | string | Always `ed25519` in v0.1 |

---

## Capability Vocabulary

Standard capability strings. Provenance indexes and filters by them.
Custom capabilities allowed — prefix with your domain: `acme:custom-capability`

### Read
```
read:web          fetch public web content
read:files        read local files
read:database     query databases
read:email        read email (requires auth)
read:calendar     read calendar (requires auth)
read:code         read code repositories
read:pdf          parse PDF documents
read:images       process images
read:audio        process audio
```

### Write
```
write:files       write local files
write:database    write to databases
write:email       send email
write:code        modify code
write:summaries   generate written content
write:external    any external system write
```

### Execute
```
execute:code      run code in a sandbox
execute:terminal  run terminal commands
execute:browser   control a browser
```

### Financial
```
financial:read       read financial data
financial:transact   initiate financial transactions
```

### Delegation
```
delegate:agents   can spawn or hire sub-agents
delegate:humans   can request human approval
```

### Constraints (no: prefix)

Any capability prefixed with `no:` is a public constraint.
A commitment that this agent will never exercise that capability.

```yaml
constraints:
  - no:financial:transact    # will never initiate transactions
  - no:write:external        # will never write to external systems
  - no:delegate:agents       # will never spawn sub-agents
  - no:pii                   # will never collect personal data
```

**Constraints are the most powerful field in PROVENANCE.yml.**
A receiving system that requires `no:financial:transact` can filter for it.
An agent that publicly commits to a constraint and violates it gets a
permanent incident on its Provenance record. The commitment is real.

---

## Provenance IDs

Every agent in the Provenance index has a stable identifier derived from
where it lives publicly. No registration required — the ID is computed
deterministically from the public URL.

```
provenance:github:owner/repo
provenance:npm:@scope/package-name
provenance:pypi:package-name
provenance:huggingface:owner/space-name
provenance:clawmarket:listing-id
```

Add `provenance_id` to your PROVENANCE.yml to link your file to your
index entry and claim your agent profile.

---

## How Provenance uses PROVENANCE.yml

When Provenance discovers or crawls an agent repository it:

1. Reads `PROVENANCE.yml` if present
2. Hashes the file content — future changes are detectable
3. Records the discovery in the tamper-evident public log
4. Indexes capabilities and constraints for search
5. Monitors for changes — what changed, when, from what to what
6. Computes the Provenance ID from the repository URL
7. Surfaces the agent in search results for capability queries

Without PROVENANCE.yml, Provenance still indexes the agent from code
signals — framework imports, package keywords, repository topics — but
with lower confidence. Adding PROVENANCE.yml upgrades the profile from
inferred to declared.

---

## Signing and Verification

A `PROVENANCE.yml` file is readable by anyone, which also means it is
editable by anyone who re-hosts it. The optional `identity` block makes a
declaration **tamper-evident**: it proves the file was produced by whoever
holds a particular private key, and that nobody has altered it since.

Verification requires no network access and no account. Any implementation
can perform it offline.

### The identity block

```yaml
provenance_id: "provenance:github:alice/research-assistant"

identity:
  public_key: "MCowBQYDK2VwAyEA..."   # base64 of SPKI DER Ed25519 public key
  signature: "3n8Kd0vQ..."            # base64 of raw 64-byte Ed25519 signature
  algorithm: "ed25519"                # always ed25519 in v0.1
```

`public_key` is required when `identity` is present. `algorithm` is optional
and defaults to `ed25519`; no other value is valid.

`signature` is optional, and its presence changes what the block means:

- **`public_key` alone** advertises the key this agent will use to prove
  control live, through the challenge-response below. The declaration itself
  is not tamper-evident. This is the path for an agent with no public
  repository, where there is no stable location to sign against.
- **`public_key` with `signature`** additionally makes the declaration
  tamper-evident. This requires `provenance_id`, since the identity is part
  of what gets signed.

Prefer the signed form wherever the agent has a public location. A verifier
that finds a key with no signature has learned which key to challenge, and
nothing about whether the file has been altered.

### What gets signed — and this differs by version

The `provenance` field selects the rule. A verifier MUST use the rule for the
version the declaration declares, and MUST refuse to guess for a version it does
not know.

#### 0.2 — the whole declaration (use this)

The signed message is the UTF-8 encoding of:

```
provenance-declaration-v1:<canonical JSON of the declaration>
```

The canonical JSON is produced from the **parsed** declaration, with
`identity.signature` removed — it cannot cover itself — and with object keys
sorted by Unicode code point recursively and no insignificant whitespace.

Because canonicalisation applies to the parsed value rather than the file's
bytes, comments, indentation, quoting style and key order do not affect the
signature. A declaration can be reformatted without re-signing. Only JSON
representable values may be signed; a parser that yields dates or other
non-plain objects must be made to yield strings instead.

Every field is covered, so deleting a constraint or adding a capability breaks
the signature. `provenance_id` is not required to verify a 0.2 signature, though
the location check still needs it.

#### 0.1 — the identity only (legacy)

The signed message is the UTF-8 encoding of:

```
<provenance_id>:<public_key>
```

This binds the key to the identity, so a key lifted from one declaration cannot
be replayed under a different `provenance_id`, and it requires `provenance_id`
to be present.

**It does not cover any other field.** A 0.1 declaration's capabilities and
constraints are not protected by its signature: someone with write access to the
location can delete a declared constraint and the signature still verifies.
Location and write access are the only controls there.

0.1 declarations remain readable and verifiable — nothing published stops
working — but new declarations SHOULD use 0.2, and a verifier SHOULD report
which coverage it checked so a reader is not misled about what was proven.

### How to verify

1. Read `provenance_id` and the `identity` block.
2. Reconstruct the message as `<provenance_id>:<public_key>`.
3. Import `public_key` as an Ed25519 SPKI DER key.
4. Verify `signature` over the message bytes.

Ed25519 is deterministic (RFC 8032), so a correct implementation produces
byte-identical signatures for the same key and message. The test vectors in
`test-vectors/signatures-0.1.json` let you confirm this without contacting
anyone.

### What verification proves — and what it does not

A valid signature proves the declaration was produced by the holder of that
private key, and:

- under **0.2**, that no field of the declaration has changed since;
- under **0.1**, only that `provenance_id` and `public_key` have not changed —
  everything else is unprotected.

A valid signature does **not** prove:

- that the key belongs to any particular person or organisation, or
- that the declared capabilities or constraints are accurate, or
- that the declaration is still current.

Binding a key to a real-world identity is a separate step. Two mechanisms
are available, and they compose:

**Location.** A declaration fetched from the repository named by its own
`provenance_id` was placed there by someone with write access to it. A
declaration whose `provenance_id` does not match where it was found should
be treated as unverified regardless of its signature — this is the
re-hosting case the substituted-key test vector covers.

**Continuity.** Once a key has been seen for a `provenance_id`, a later
declaration signed by a different key is a key rotation and must be treated
as a material change, not a silent update.

This is the same division of labour as a machine-readable passport: the
document proves its own integrity offline, while identity binding and
current standing are looked up.

### Every signed payload is domain-separated

An agent's key signs several different things. Each payload MUST carry the
prefix for its purpose, so that a signature obtained for one purpose can never
be presented as another:

| Purpose | Signed payload |
|---|---|
| Declaration (0.2) | `provenance-declaration-v1:<canonical JSON>` |
| Live proof of key control | `provenance-challenge-v1:<provenance_id>:<nonce>` |
| Revocation | `provenance-revocation-v1:<provenance_id>` |

This is not a precaution against something hypothetical. In 0.1 a challenge was
signed as `<provenance_id>:<nonce>` and a revocation as
`<provenance_id>:REVOKE` — **the same payload with a chosen nonce.** Any
publicly reachable endpoint that signs a caller-supplied nonce in the 0.1 form
therefore hands out valid revocation signatures for its own key, and a stranger
can revoke the agent. Supplying the public key as the nonce likewise reproduces
the 0.1 declaration signature.

An endpoint that signs a caller-supplied value MUST use the separated challenge
form, and MUST NOT sign the 0.1 payload. Verifiers SHOULD require the separated
form from any agent that exposes a public challenge endpoint.

The 0.1 payloads remain defined so existing deployments keep working, but they
are unsafe to expose and are superseded.

### Live proof of key control

A signature on a file proves the file's origin. It does not prove that the
agent running right now controls that key. For that, a receiving system issues
a nonce and the agent returns a signature over
`provenance-challenge-v1:<provenance_id>:<nonce>`.

Nonces must be single-use and unpredictable. The receiving system verifies the
signature against the public key it already holds for that `provenance_id`.

### Revocation

A key holder revokes a `provenance_id` by signing
`provenance-revocation-v1:<provenance_id>`. The payload contains no
caller-supplied input, so it cannot be produced by a challenge endpoint however
that endpoint is called.

Revocation is the one operation that cannot be verified offline — a verifier
has no way to know a revocation has been issued without asking. Implementations
that cache public keys should re-check revocation status on the same cadence
they would re-check any other freshness signal.

---

## Conformance

An implementation of this specification is conformant if it:

1. Accepts every file that validates against the schema for its declared
   version — `schema/provenance-0.1.json` or `schema/provenance-0.2.json`.
2. Treats `provenance`, `name` and `description` as required and everything
   else as optional.
3. Ignores unrecognised top-level fields rather than rejecting the file.
   Future spec versions add fields; a `0.1` reader must not break on them.
4. Treats `identity.signature` as optional, and an unsigned `identity`
   block as advertising a key rather than attesting the file.
5. Applies the signing rule for the version the declaration declares, refuses
   to guess for an unknown version, and reports which coverage it checked —
   a reader must not be left thinking a 0.1 signature protected the
   declared constraints.
6. Reproduces every signature in `test-vectors/signatures-0.1.json` and every
   declaration in `test-vectors/declarations-0.2.json` marked `valid`, and
   refuses every one marked `invalid`.
7. Treats a declaration whose `provenance_id` does not match its retrieval
   location as unverified.

Points 6 and 7 are what make independent implementations agree. An
implementation that passes the test vectors interoperates with every other
one that does, with no reference to any particular service.

A reference implementation of offline verification ships in this repository as
`provenance-protocol/verify`. It is one implementation, not the definition —
the vectors are the definition.

---

## Implementing this specification

This specification, its JSON Schema and its test vectors are published under
the MIT Licence. You may implement them in any language, for any purpose,
commercial or otherwise, without permission, notification or fee.

Nothing in this specification requires contacting any particular service. A
conformant implementation can read, validate and cryptographically verify a
declaration entirely offline. Services built on this protocol — indexes,
monitors, attesters — are applications of the standard, not part of it.

---

## Versioning

The `provenance` field records which spec version you are using, and it is what
a reader uses to decide how to interpret the file.

We commit to backwards compatibility: a `0.1` file will always be readable and
verifiable, whatever later versions say. Fields are never removed.

Usually a new version only adds fields. Version 0.2 is the exception so far — it
changed what an existing field *covers*, because `identity.signature` in 0.1
protected only the identity and left the declared capabilities and constraints
unprotected, which was weaker than readers assumed. Rather than redefine 0.1
under declarations already published, 0.2 defines the stronger rule and the
`provenance` field keeps the two apart. A verifier implements both and applies
the one the declaration asks for.

Where a version changes the meaning of an existing field, it will always do so
by declaring a new version, never by reinterpreting an old one.

---

## FAQ

**Do I have to register anywhere?**
No. Provenance discovers agents automatically. Adding PROVENANCE.yml
improves your profile but requires no account, no API key, no permission.

**What if I already have a file in my repo I want to keep private?**
PROVENANCE.yml is only read from public repositories. Private repos
are not crawled.

**What if my constraints are inaccurate?**
Constraints are public commitments. Be honest. A constraint you declare
but violate becomes a permanent incident on your record.

**Can I use custom capability strings?**
Yes. Prefix with your domain: `acme:internal-tool`. Standard vocabulary
recommended for interoperability.

**What happens when I change my model?**
Provenance detects it from the repository commit and from behavioral
fingerprinting. The change is recorded — not penalized. Transparency
is the point.

**What if my agent is on HuggingFace, not GitHub?**
Same process. Add PROVENANCE.yml to your Space or model repository root.
Provenance crawls HuggingFace the same way it crawls GitHub.

---

*Provenance Protocol v0.1 — MIT License*
*https://getprovenance.dev*
*https://github.com/ilucky21c/provenance-protocol*
