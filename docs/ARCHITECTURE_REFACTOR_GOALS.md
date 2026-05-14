# Architecture Refactor Goals

This document records the agreed high-level goals for the CypherAir architecture refactor.
It describes the intended architectural direction only. It is not a current-state audit,
detailed design, implementation reference, or execution plan.

## Target Architecture

The intended dependency shape is:

```text
UI / Presentation Extensions
  -> ScreenModel
      -> Service
          -> App-owned Models
          -> FFI Adapter / Mapper
              -> PgpEngine / UniFFI
          -> Security
```

## Clarify Architecture Boundaries

Define the responsibilities and dependency direction of the main application layers:

- UI
- Presentation Extensions
- ScreenModel
- Service
- App-owned Models
- FFI Adapter / Mapper
- Security

The goal is to establish shared architecture language for future refactoring and code
review.

## Narrow the Responsibility of Models

The Models layer should primarily contain app-owned data models, domain values, error
vocabulary, and persisted payload schemas.

Models should not directly own:

- UniFFI / FFI type mapping
- UI presentation logic
- Security / ProtectedData store details
- unlock / relock state machines
- migration coordination details

`CypherAirError` may remain in the Models layer as an app-owned error model. However,
mappings such as `PgpError -> CypherAirError` should move toward the FFI Adapter /
Mapper boundary so Models do not directly depend on UniFFI types.

## Establish an FFI Adapter / Mapper Boundary

UniFFI and `PgpEngine` generated types should be contained behind an adapter / mapper
boundary.

Services should expose app-owned models and app-owned errors to ScreenModels and UI.
FFI types should not leak upward into Models, ScreenModels, or UI-facing APIs as a
long-term architecture.

## Clarify UI and ScreenModel Responsibilities

UI should not directly orchestrate Service workflows.

In this context, direct orchestration means multi-step business workflows, async state
transitions, error normalization, cross-service coordination, and business decisions.

UI should interact with ScreenModels through exposed state and actions. ScreenModels own
user-driven workflow state, invoke Services, and prepare UI-consumable state.

## Limit Presentation Extensions to Presentation

Presentation Extensions are display helpers only.

They may provide colors, icons, titles, subtitles, formatted text, accessibility labels,
button labels, and similar UI-facing representations.

They should not participate in business workflows, call Services, access Security, or
perform FFI mapping.

## Remove Legacy Contact Runtime Projection

The Contacts runtime should move toward the newer contacts domain model.

Normal app runtime should not continue to use the legacy `Contact` projection as the
primary contact model.

The refactor should reduce and eventually remove runtime dependencies on the legacy
`Contact` projection, moving main flows toward `ContactIdentity`, `ContactKeyRecord`,
summaries, recipient models, and other current contacts-domain types.

Legacy flat contacts support should remain only as an old-install migration input unless
and until the migration support window is explicitly retired.

## Isolate Migration and Compatibility Code

Legacy and migration-related code should be isolated behind explicit migration or
compatibility boundaries.

Migration code should not remain mixed into the current runtime service path except where
required as a clear compatibility adapter.

This goal includes contact migration isolation where it directly supports removal of
legacy runtime projection. It does not imply a broad file-splitting effort.

## Non-Goals for This Round

The following are not goals of this refactor round:

- Comprehensive splitting of all files over 800 lines
- Package modularization
- Large-scale directory restructuring
- Comprehensive Sendable conformance cleanup

Sendable consistency should remain a follow-up architecture hygiene item, especially as
ScreenModel, FFI Adapter, and future module boundaries become clearer.
