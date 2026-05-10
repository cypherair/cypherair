# Contacts Documentation Bridge

> **Status:** Archived temporary bridge.
> **Archived on:** 2026-05-10.
> **Archival reason:** Contacts-specific durable content has been consolidated into long-term docs and the Contacts-specific document set has been archived.
> **Successor documents:** [PRD](../PRD.md) · [TDD](../TDD.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TESTING](../TESTING.md) · [PERSISTED_STATE_INVENTORY](../PERSISTED_STATE_INVENTORY.md)
> **Current code and active canonical docs outrank this archived file whenever they disagree.**
>
> Original bridge metadata follows.

> **Status:** Completed temporary bridge; not a canonical current-state authority.
> **Purpose:** Record the completed consolidation of the archived Contacts source files into long-term CypherAir documentation.
> **Audience:** Engineering, product, QA, security review, and AI coding tools.
> **Source of truth:** Current code plus canonical current-state docs win over this bridge and over archived Contacts planning history.
> **Last reviewed:** 2026-05-10.
> **Update triggers:** Any decision to consolidate, archive, or materially rewrite the Contacts-specific document set.

## 1. Source Documents

Use these archived Contacts source files only as historical source material, not as long-term current-state authorities:

- [CONTACTS_PRD](CONTACTS_PRD.md)
- [CONTACTS_TDD](CONTACTS_TDD.md)
- [CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN](CONTACTS_PROTECTED_DOMAIN_IMPLEMENTATION_PLAN.md)
- [CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY](CONTACTS_PROTECTED_DOMAIN_SURFACE_INVENTORY.md)

Before moving any claim, verify it against current code and the active long-term docs. When source documents preserve implementation sequencing, treat that sequencing as historical context unless a current code path or current-state document still depends on it.

## 2. Consolidation Map

- Move durable product behavior into [PRD](../PRD.md): person-centered Contacts, multiple keys per contact, manual verification versus OpenPGP certification, search, tags, recipient lists, no active Contacts package exchange, and mandatory encryption for any future complete Contacts backup or device migration.
- Move durable domain model and service-boundary rules into [TDD](../TDD.md) and [ARCHITECTURE](../ARCHITECTURE.md): `ContactsDomainSnapshot`, `ContactIdentity`, `ContactKeyRecord`, `ContactTag`, `RecipientList`, `ContactCertificationArtifactReference`, `ContactService` as the UI/app facade, `ContactsDomainStore` as the protected-domain persistence owner, runtime-only search/filter/selection state, and relock cleanup.
- Move durable security and persisted-state rules into [SECURITY](../SECURITY.md) and [PERSISTED_STATE_INVENTORY](../PERSISTED_STATE_INVENTORY.md): no legacy fallback after protected-domain cutover, legacy cleanup/quarantine-only behavior, certification-signature export as an explicit artifact boundary, no package or social-graph export, and no plaintext derivative caches outside the protected `contacts` payload.
- Move durable regression requirements into [TESTING](../TESTING.md) and [CODE_REVIEW](../CODE_REVIEW.md): protected-domain migration/readability, preferred/additional/historical key behavior, merge preservation, search and tag normalization, recipient-list resolution, certification artifact persistence/revalidation, locked/opening/recovery/framework-unavailable states, relock cleanup, legacy fallback prohibition, and package-exchange absence.

## 3. Do Not Move

- Do not move historical PR-by-PR execution narrative, old gate tables, or line-by-line surface checklist history into long-term current-state docs.
- Do not move withdrawn package-design details such as `.cypherair-contacts`, Apple Archive containers, package manifests, package import previews, package commits, or multi-contact export flows. Long-term docs should retain only the current boundary: no active Contacts package exchange; complete Contacts backup or device migration requires a future mandatory encrypted design.
- Do not move source wording that still describes shipped Contacts behavior as future, remaining, or gated by historical sequencing. Rewrite those claims as current-state behavior only after checking code.

## 4. Completion Criteria

The archived Contacts source files were moved after their durable current-state content was consolidated into the long-term docs, active links were redirected to those long-term docs, and a markdown-link audit plus targeted stale-claim sweep passed for active and archived documentation.
