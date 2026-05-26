# Apple Secure Enclave Custody Implementation Docs Guidance

> Status: Active authoring guidance. This document guides the creation of two
> future Apple Secure Enclave Custody implementation documents and does not
> describe shipped behavior.
> Date: 2026-05-25.
> Purpose: Define the responsibilities, scope, and writing standards for the
> Secure Enclave Custody Implementation Reference and Implementation Roadmap.
> Audience: Document authors, Swift/Rust implementers, security reviewers,
> architecture reviewers, product owners, test owners, reviewers, and AI coding
> tools.
> Related: [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md),
> [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md),
> [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md),
> [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md),
> [Architecture](ARCHITECTURE.md), [Security](SECURITY.md),
> [Persisted State Inventory](PERSISTED_STATE_INVENTORY.md), and
> [Testing](TESTING.md).

## Role

This document guides the creation of two implementation-preparation documents:

- `APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_REFERENCE.md`
- `APPLE_SECURE_ENCLAVE_CUSTODY_IMPLEMENTATION_ROADMAP.md`

Those two documents should be written from the four active source documents
listed below and this guidance document. They should not replace those source
documents:

| Source | Owns |
| --- | --- |
| [Product Design](APPLE_SECURE_ENCLAVE_CUSTODY_PRODUCT_DESIGN.md) | Product semantics, user commitments, MVP scope, compatibility language, and user-facing consequences. |
| [Architecture Plan](APPLE_SECURE_ENCLAVE_CUSTODY_ARCHITECTURE_PLAN.md) | Model separation, layer ownership, metadata/handle split, resolver/router architecture, and Rust/Swift ownership direction. |
| [Security Requirements](APPLE_SECURE_ENCLAVE_CUSTODY_SECURITY_REQUIREMENTS.md) | Security red lines, access policy, private-operation requirements, validation categories, evidence gates, and release gates. |
| [Feasibility Summary](APPLE_SECURE_ENCLAVE_CUSTODY_FEASIBILITY_SUMMARY.md) | Feasibility evidence, caveats, POC boundaries, and remaining production-readiness gaps. |

The implementation documents should add practical guidance that the source
documents do not fully provide. They should not become second copies of Product
Design, Architecture Plan, Security Requirements, or Testing.

## Target Documents

The Implementation Reference should help later per-PR implementation plans. It
should describe middle-level implementation contracts: what layer owns which
responsibility, what state must be representable, what route must be used, how
failures should be classified, which source document owns a requirement, and
what kinds of tests should prove the contract.

The Implementation Roadmap should provide staged PR planning. It should describe
the approximate order of work, phase entry conditions, exit conditions,
validation expectations, and rollback rules. It should not be treated as the
complete implementation plan for any phase. Each phase still needs its own
implementation plan before code work begins.

Together, the two documents should be more implementation-facing than the four
active source documents, but less final than code-level implementation plans.

## Detail Level

The documents should use a middle-contract level of detail.

They should not decide exact APIs, final persisted schemas, Keychain naming,
UniFFI representation, signing result representation, localized UI copy, test
fixture file names, or hardware runner implementation details.

They also should not avoid useful reference detail. Avoiding premature
implementation choices does not mean avoiding every concrete value. Concrete
values may be included as reference material for later implementation planning
when they help clarify what a later plan needs to decide or verify.

Reference detail should remain selective. It should not become a way to list
every possible value, repeat requirements already covered by active source
documents, or settle low-level choices that belong to later implementation
plans. Include concrete reference values when they reduce a real risk of later
misunderstanding, not merely because a detailed value is available.

Good middle-contract content includes:

- clear layer ownership, such as what Rust/Sequoia owns and what
  Swift/Security owns;
- required separation between OpenPGP configuration, private-key custody, and
  operation capability;
- state that must be representable, without choosing final field names;
- stable error categories that UI, workflow services, tests, and security
  review can share;
- operation-routing rules, such as when software custody may use an existing
  route and when Secure Enclave custody must use a different route;
- concrete negative test scenarios when a generic test description would be too
  vague;
- phase entry conditions, exit conditions, validation expectations, and rollback
  rules;
- concrete reference values or guardrails when a vague phrase would hide an
  important decision, such as naming `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  as a reference value when discussing Keychain item accessibility, rather than
  only saying "item accessibility."

Poor middle-contract content includes:

- repeated copies of source-document authority that should be linked instead;
- broad statements such as "keep boundaries clear" without naming the boundary;
- vague checklists that hide required defaults or failure behavior;
- detailed function signatures, storage keys, generated binding shapes, or UI
  copy that belong to a later implementation plan;
- long fixed templates that make later authors preserve structure even when the
  content would be clearer another way.

The test for a useful paragraph is: a later implementation-plan author should
be able to use it to decide what to design, what not to design, and what to
verify. The paragraph should not force the final code interface unless the
active source documents already require that choice.

## Reference Framework

The Implementation Reference may use this framework as a starting point. It is
not a required outline. Authors may combine, split, rename, or reorder sections
when that produces a clearer implementation reference.

Suggested coverage:

- role, status, and source authorities;
- current software-custody baseline and target Secure Enclave custody model;
- configuration, custody, and operation capability separation;
- protected metadata, public binding, handle state, availability, and recovery
  concerns;
- Secure Enclave handle-store responsibilities and the relationship between
  metadata and Security-layer handles;
- resolver and router responsibilities;
- Rust/Swift handoff responsibilities for signing, key agreement, session-key
  acquisition, payload processing, and streaming;
- business operation semantics for generation, import/export, signing,
  decryption, streaming workflows, revocation, expiry, certification, and
  unsupported operations;
- stable error taxonomy;
- implementation test contracts and evidence expectations, with links to the
  owning validation documents;
- documentation update triggers.

The reference should prefer links to source documents for product semantics,
security policy, broad validation gates, and repository-wide rules. It should
keep implementation-specific constraints when removing them would make later
PR planning ambiguous.

## Roadmap Framework

The Implementation Roadmap may use this framework as a starting point. It is
not a required outline. Authors may adjust phase names, split phases, combine
small phases, or change ordering when the implementation dependency graph
requires it.

Suggested coverage:

- a roadmap decision explaining that Secure Enclave custody remains hidden or
  test-only until the active product, architecture, security, implementation,
  hardware, interop, and release gates allow product exposure;
- short global PR guidance that links to source documents instead of repeating
  repository-wide rules;
- staged PR phases for documentation/baseline work, model and metadata work,
  Rust external-operation proving, Security handle storage, hidden generation,
  signing-class workflow integration, decrypt and streaming integration,
  product UI/error surfaces, hardware and interop evidence, and release
  readiness;
- per-phase goal, recommended PR grouping, entry conditions, exit conditions,
  validation expectations, and rollback rules;
- program-level stop conditions that send work back to product, architecture,
  and security review;
- roadmap update triggers.

The roadmap should be actionable enough to guide later phase planning, but it
should not replace the implementation plan for any phase. It should name the
kind of work and the gate for that work, not the final code API.

## Style Rules

Use source links instead of repeating authority. If a requirement already lives
in Product Design, Architecture Plan, Security Requirements, Feasibility
Summary, Testing, Security, or Persisted State Inventory, link to that source
unless the implementation document needs a short local restatement to explain
how the requirement is consumed.

Do not dilute important requirements into generic words. If the important point
is a concrete default, failure mode, phase gate, or test scenario, state it
plainly. A useful implementation reference should not make reviewers guess what
"availability," "accessibility," "route," "policy," or "state" means.

If a specific value is useful mainly as reference for later implementation
planning, label it as reference material and keep it at the level needed to
reduce planning ambiguity.

Do not lock down low-level implementation choices too early. If a future PR
must choose exact type names, schemas, function signatures, generated binding
interfaces, storage names, or UI copy, say that the future PR owns that choice.

Avoid decorative structure. A framework is helpful only when it makes the
implementation boundary clearer. Do not preserve a section only because a
suggested framework listed it, and do not add exhaustive lists when a source
document already owns the detail.

When tension exists between being specific and avoiding premature design,
prefer this rule:

- include details that preserve a safety or interoperability constraint;
- defer details that merely choose one possible code representation.

## Acceptance Criteria

The two implementation documents are ready when:

- they clearly state that they describe proposed future work, not shipped
  behavior;
- they name the active source documents and respect their ownership;
- they provide practical guidance beyond the four active source documents;
- they avoid becoming duplicate Product, Architecture, Security, or Testing
  documents;
- they include enough implementation detail to guide later PR plans and
  reviews;
- they avoid deciding exact code interfaces, persisted field names, Keychain
  naming, generated binding details, UI copy, or fixture names;
- their roadmap phases are useful planning units, not release promises;
- every future phase still expects its own implementation plan before code work
  begins.
