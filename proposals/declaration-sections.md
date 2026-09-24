# Proposal: what a declaration can say, and how a cooperating vendor delivers it

Status: **adopted** — Parts A, B and C are specified in SPEC.md and implemented in provenance-protocol 0.7.0; the delivery pieces in provenance-middleware and provenance-action. EU AI Act classification deferred as stated.
Date: 24 September 2026

## Why

A declaration today answers *what can this agent do, what will it never do,
which model runs it, who to contact*. A risk or procurement team asks more than
that, and asks it first: where does our data go, who else touches it, what needs
a human's approval, who is legally answerable, what does it depend on. This
proposal adds those, and the delivery channel for a vendor who plugs in fully.

## Principles

1. **Passport only.** Everything in Part A is the vendor describing its own
   agent. Stamps (attestations) are unchanged.
2. **Optional, additive, within spec 0.2.** New sections are optional
   top-level fields. The signing rule is unchanged, so every 0.2 verifier
   released so far keeps verifying these declarations — conformance rule 3
   already requires unknown top-level fields to be ignored. Declaring them as a
   new version would make every deployed verifier refuse the file. The 0.2
   schema gains the new sections as optional properties; nothing that validates
   today stops validating.
3. **Few fields, fixed words.** Every field here becomes frozen once published.
   Prefer a short controlled vocabulary to free text, and reuse existing
   standards (ISO country codes, ISO 8601 durations, the capability vocabulary)
   instead of inventing formats.
4. **Self-declared, and labelled as such.** These are the vendor's signed
   statements. Their value is that they are signed, versioned, and watched: a
   change is visible, dated and attributable. Where an outside check exists,
   Part C says so.
5. **Answer once, reuse everywhere.** Each section maps to a question vendors
   already answer on security questionnaires and for the EU AI Act, so filling
   it in is copying, not new work.

---

## Part A — New declaration sections (the passport)

### `operator` — who is answerable

```yaml
operator:
  legal_name: "Acme Robotics Ltd"
  jurisdiction: "GB"                 # ISO 3166-1 alpha-2
  registration: "GB-COH:12345678"    # optional; scheme:number
  security_contact: "https://acme.example/.well-known/security.txt"
```

`contact` stays for people; `operator` is the legal party. Buyers need the
entity to contract with and the jurisdiction whose law applies.

### `data` — what happens to data the agent is given

```yaml
data:
  categories: [customer_content, personal]   # controlled vocabulary
  retention: "P30D"                          # ISO 8601 duration; "none" = not kept
  training_use: none                         # none | opt_in | opt_out | yes
  regions: [EU]                              # where processed and stored
```

Vocabulary for `categories`: `customer_content`, `personal`,
`special_category` (health, biometrics, etc.), `financial`, `credentials`.

This is the first question on every procurement form. Today only `no:pii`
touches it.

### `subprocessors` — who else touches the data

```yaml
subprocessors:
  - name: "Anthropic"
    role: model_provider          # model_provider | hosting | tool | storage | other
    regions: [US]
    data_categories: [customer_content]
    provenance_id: null           # when the subprocessor has one
```

The model provider becomes one entry here. `model` stays as it is.

### `oversight` — what needs a human

```yaml
oversight:
  approval_required: [financial:transact, write:email]   # capabilities
  pausable_by_customer: true
```

Distinguishes an agent that *can* pay from one that pays *without asking*. Uses
the existing capability vocabulary.

### `limits` — hard ceilings

```yaml
limits:
  - applies_to: financial:transact
    max: 500
    unit: USD                    # ISO 4217, or "actions"
    per: "P1D"                   # ISO 8601 duration; omit for per-action
```

### `dependencies` — what it relies on

```yaml
dependencies:
  - provenance_id: "provenance:domain:search-tool.example"
    kind: mcp_server             # mcp_server | agent | api | package
    purpose: "web search"
  - url: "https://api.example-payments.com"
    kind: api
    purpose: "card payments"
```

Supersedes `skills` and `delegates`, which remain valid (fields are never
removed). **This is what makes chain monitoring possible:** a dependency with a
provenance id has its own declaration, which can be watched, so a promise
dropped three links down reaches the buyer at the top.

### `certifications` — pointers, not claims

```yaml
certifications:
  - standard: "ISO/IEC 42001"
    attestation_url: "https://certifier.example/att/abc123.json"   # preferred
    report_url: null
```

A certification the vendor merely names is weak. One backed by a stamp the
certifier signed is strong, and verifiable offline. The declaration only
points; the proof is the certifier's attestation.

### `changes` — notice before weakening

```yaml
changes:
  notice_period: "P30D"
  pending:
    - field: constraints
      change: removed
      value: no:write:external
      effective: "2026-11-01"
      reason: "adding CRM sync"
```

A vendor commits to announce material changes in advance and lists them while
pending. Buyers get warning instead of surprise; a change that lands without
having been pending for the notice period is itself a visible breach of the
vendor's own promise. Nobody else offers this.

### `interop` — links to other ecosystems

```yaml
interop:
  a2a_agent_card: "https://agent.example/.well-known/agent-card.json"
  mcp_registry: "com.example/research-server"
```

The other direction — an A2A card or MCP entry pointing at the declaration —
is a short convention for those formats, drafted separately.

### Considered and deferred

- **EU AI Act risk class.** Useful, but a vendor's self-classification is a
  legal statement with consequences, and the categories are still being
  interpreted. Defer until the guidance settles; revisit then.
- **Uptime / SLA figures.** Contractual, and not a property of the agent.
- **Free-text security descriptions.** Unverifiable and unmaintainable;
  certifications cover this better.

---

## Part B — Delivery when the vendor plugs in (open packages, not Nymbrink)

All of this goes into the open packages. The vendor chooses which watchers to
notify — any attester, several, or none. Hard-wiring one would be lock-in and
many vendors would refuse it.

| Signal | Delivered by | Status |
|---|---|---|
| Signed declaration at its own address | provenance-middleware | built |
| Live proof of key control | provenance-middleware | built |
| Running version | provenance-middleware | built |
| **Change notice** — signed "my declaration changed, here is the new digest", sent at startup when it differs | provenance-middleware | new |
| **Release note** — signed "release 4.2, commit abc, declaration digest X" from CI | provenance-action | new |
| **Key rotation, signed by the old key** — so a new key reads as continuity, not as an impostor | provenance-protocol (new payload) + middleware | new |
| **Self-reported incident** — the vendor discloses its own incident, signed | provenance-protocol (new payload) | new |

Protocol additions for these are new domain-separated payloads
(`provenance-notice-v1`, `provenance-rotation-v1`, `provenance-incident-v1`)
and a short spec section on how a watcher receives them (an HTTPS endpoint the
vendor configures; the notice is signed, so the transport needs no trust).

**What the vendor never sends:** private keys, traffic, user data, prompts or
outputs. Behaviour evidence comes from buyers (signed job receipts, reports),
never by instrumenting the vendor.

---

## Part C — What a watcher can check, with and without cooperation

| Signal | Source | Can it be cross-checked? |
|---|---|---|
| Promises, capabilities, data, oversight, limits | Declaration | Change is provable; truth is self-declared |
| Subprocessor regions / hosting | Declaration | Partly — DNS and hosting of the endpoints |
| Dependencies | Declaration | Yes — each has its own declaration to watch |
| Certifications | Certifier's stamp | Yes — offline, against the certifier's key |
| Pending changes honoured | Declaration history | Yes — did it land only after the notice period? |
| Domain, certificate, DNS ownership | Public | Yes, no cooperation needed |
| Package publish rights (new maintainer) | npm / PyPI | Yes — a classic supply-chain warning |
| Repository ownership transfer | GitHub | Yes |
| A2A card / MCP entry changes | Public | Yes |
| Terms, privacy, subprocessor pages | Public | Change only |
| Known flaws in declared dependencies | Advisory databases | Yes |
| Behaviour | Buyers' signed receipts and reports | Attributable, not judged |

---

## Decisions for the owner

1. Approve the sections in Part A (or strike any).
2. Approve additive-within-0.2 rather than a new version number.
3. Approve Part B's four new signals, all in the open packages.
